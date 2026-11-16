// Author: Krishna Inukonda (benchmarking).
//
// Two-board ESP-NOW benchmark. Flash the SAME build to both boards. They find
// each other by broadcast; the board with the lower MAC becomes the initiator
// and runs the tests, the other (responder) only echoes and counts.
//
// Records printed (parsed by tools/bench_parse.py):
//   initiator: HEAP/MINHEAP/STACK, HANDSHAKE,setup,us (peer setup -> first echoed probe), RTT
//   responder: HEAP/MINHEAP/STACK, TPUT (msgs/s on receiver), PDR (received vs sent)
//
// BENCH_SECURITY is set from CMake (see main/CMakeLists.txt).

#include <stdio.h>
#include <string.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "esp_event.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "nvs_flash.h"

#include "bench_crypto.h"
#include "bench_measure.h"

#if BENCH_SECURITY == 2
// PROTO: when Yvvy's handshake/AEAD functions exist, remove this and fill in the
// three PROTO points below (handshake in test_setup, seal before send, open on receive).
#error "BENCH_SECURITY=2 (custom protocol) needs the PROTO hooks filled in"
#endif

#define ENCRYPT          (BENCH_SECURITY == 1)
#define WIFI_CHANNEL     10          // same channel as main/main.c
#define SETUP_RUNS       50
#define RTT_RUNS         1000
#define TPUT_WINDOW_US   (5 * 1000 * 1000)
#define REPLY_TIMEOUT_MS 100
#define BENCH_MAGIC      0xB3        // ignore ESP-NOW frames from other projects on the channel

#if BENCH_RTT_N > 0 && RTT_RUNS > BENCH_RTT_N
#error "RTT_RUNS must not exceed BENCH_RTT_N"
#endif

// Total frame sizes tested (header included). 250 is the ESP-NOW v1 maximum.
static const uint16_t FRAME_SIZES[] = { 32, 250 };
#define N_SIZES (sizeof FRAME_SIZES / sizeof FRAME_SIZES[0])

#if ENCRYPT
// Test-only CCMP keys, identical on both boards. Not secrets.
static const uint8_t PMK[ESP_NOW_KEY_LEN] = { 'b','e','n','c','h','_','p','m','k','_','1','6','b','y','t','e' };
static const uint8_t LMK[ESP_NOW_KEY_LEN] = { 'b','e','n','c','h','_','l','m','k','_','1','6','b','y','t','e' };
#endif

static const uint8_t BROADCAST[ESP_NOW_ETH_ALEN] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

enum { MSG_HELLO, MSG_PROBE, MSG_PROBE_ACK, MSG_PING, MSG_PONG, MSG_DATA, MSG_END, MSG_END_ACK };

typedef struct __attribute__((packed)) {
    uint8_t  magic;
    uint8_t  type;
    uint16_t len;    // total frame length
    uint32_t seq;    // sequence number (END: number of DATA frames sent)
} bench_hdr_t;

typedef struct { uint8_t type; uint16_t len; uint32_t seq; } rx_evt_t;

static uint8_t s_self[ESP_NOW_ETH_ALEN];
static uint8_t s_peer[ESP_NOW_ETH_ALEN];
static volatile bool s_have_peer;

static SemaphoreHandle_t s_sent;    // send_cb fired for the last frame
static SemaphoreHandle_t s_reply;   // the reply the initiator waits for arrived
static volatile uint8_t  s_wait_type;
static volatile uint32_t s_wait_seq;
static QueueHandle_t s_rx_q;        // responder: frames that need an answer

static volatile uint16_t s_tp_len;  // responder: frame size of the current DATA run, 0 = idle
static volatile uint32_t s_tp_rx;

static void send_cb(const esp_now_send_info_t *info, esp_now_send_status_t status)
{
    (void) info;
    (void) status;
    xSemaphoreGive(s_sent);
}

// Runs in the Wi-Fi task: only bookkeeping here, answers go through s_rx_q.
static void recv_cb(const esp_now_recv_info_t *info, const uint8_t *data, int len)
{
    bench_hdr_t h;
    if (len < (int) sizeof h) return;
    memcpy(&h, data, sizeof h);
    if (h.magic != BENCH_MAGIC) return;

    if (!s_have_peer) {
        memcpy(s_peer, info->src_addr, ESP_NOW_ETH_ALEN);
        s_have_peer = true;
    }

    switch (h.type) {
    case MSG_HELLO:
        return;
    case MSG_PONG:
        bench_rtt_recv(h.seq);
        // fall through
    case MSG_PROBE_ACK:
    case MSG_END_ACK:
        if (h.type == s_wait_type && h.seq == s_wait_seq) xSemaphoreGive(s_reply);
        return;
    case MSG_DATA:
        // PROTO: decrypt/verify here; count only frames that authenticate.
        if (h.len != s_tp_len) {
            s_tp_len = h.len;
            s_tp_rx = 0;
            bench_tp_start();
        }
        s_tp_rx++;
        bench_tp_count();
        return;
    default: {
        rx_evt_t e = { h.type, h.len, h.seq };
        xQueueSend(s_rx_q, &e, 0);
        return;
    }
    }
}

// Sends one frame and waits for its send callback (one frame in flight at a time).
static esp_err_t send_frame(const uint8_t *dst, uint8_t type, uint16_t len, uint32_t seq)
{
    static uint8_t buf[ESP_NOW_MAX_DATA_LEN];
    bench_hdr_t h = { BENCH_MAGIC, type, len, seq };
    memcpy(buf, &h, sizeof h);
    // PROTO: seal (encrypt + tag) the payload here for BENCH_SECURITY == 2.

    xSemaphoreTake(s_sent, 0);
    esp_err_t err = esp_now_send(dst, buf, len);
    if (err == ESP_OK) xSemaphoreTake(s_sent, pdMS_TO_TICKS(REPLY_TIMEOUT_MS));
    return err;
}

// Initiator: send a frame and wait for the matching reply.
static bool request(uint8_t type, uint8_t reply, uint16_t len, uint32_t seq)
{
    s_wait_type = reply;
    s_wait_seq = seq;
    xSemaphoreTake(s_reply, 0);
    if (send_frame(s_peer, type, len, seq) != ESP_OK) return false;
    return xSemaphoreTake(s_reply, pdMS_TO_TICKS(REPLY_TIMEOUT_MS)) == pdTRUE;
}

static void add_peer(const uint8_t *mac, bool encrypt)
{
    esp_now_peer_info_t p;
    memset(&p, 0, sizeof p);
    p.channel = WIFI_CHANNEL;
    p.ifidx = WIFI_IF_STA;
    p.encrypt = encrypt;
#if ENCRYPT
    if (encrypt) memcpy(p.lmk, LMK, ESP_NOW_KEY_LEN);
#endif
    memcpy(p.peer_addr, mac, ESP_NOW_ETH_ALEN);
    ESP_ERROR_CHECK(esp_now_add_peer(&p));
}

// Setup time: add the peer (and, for the custom protocol, run the handshake),
// then until the first probe is echoed back by the responder.
static void test_setup(void)
{
    for (uint32_t i = 0; i < SETUP_RUNS; i++) {
        ESP_ERROR_CHECK(esp_now_del_peer(s_peer));
        bench_handshake_start();
        add_peer(s_peer, ENCRYPT);
        // PROTO: run the custom handshake here.
        if (request(MSG_PROBE, MSG_PROBE_ACK, sizeof(bench_hdr_t), i)) bench_handshake_end("setup");
        else printf("SETUP_FAIL,setup,%u\n", (unsigned) i);
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

static void test_rtt(uint16_t len)
{
    char label[16];
    snprintf(label, sizeof label, "rtt_%u", len);
    bench_rtt_reset();
    for (uint32_t i = 0; i < RTT_RUNS; i++) {
        bench_rtt_send(i);
        request(MSG_PING, MSG_PONG, len, i);
    }
    vTaskDelay(pdMS_TO_TICKS(200));  // let late echoes land before reporting
    bench_rtt_report(label, RTT_RUNS);
}

static void test_tput(uint16_t len)
{
    uint32_t sent = 0;
    int64_t end = esp_timer_get_time() + TPUT_WINDOW_US;
    while (esp_timer_get_time() < end) {
        if (send_frame(s_peer, MSG_DATA, len, sent) == ESP_OK) sent++;
        else vTaskDelay(1);  // driver queue full: back off one tick
    }
    for (int i = 0; i < 5 && !request(MSG_END, MSG_END_ACK, sizeof(bench_hdr_t), sent); i++) {}
    // receiver measures msgs/s; the frame size is carried by the DATA run it already saw
}

static void initiator_task(void *arg)
{
    (void) arg;
    vTaskDelay(pdMS_TO_TICKS(1000));  // let the responder finish discovery
    test_setup();
    bench_min_heap("after_setup");
    for (size_t i = 0; i < N_SIZES; i++) test_rtt(FRAME_SIZES[i]);
    for (size_t i = 0; i < N_SIZES; i++) {
        test_tput(FRAME_SIZES[i]);
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    bench_heap("after_tests");
    bench_min_heap("after_tests");
    bench_stack("bench_task");
    printf("BENCH_DONE\n");
    vTaskDelete(NULL);
}

static void responder_task(void *arg)
{
    (void) arg;
    rx_evt_t e;
    for (;;) {
        if (xQueueReceive(s_rx_q, &e, portMAX_DELAY) != pdTRUE) continue;
        switch (e.type) {
        case MSG_PROBE:
            send_frame(s_peer, MSG_PROBE_ACK, sizeof(bench_hdr_t), e.seq);
            break;
        case MSG_PING:
            send_frame(s_peer, MSG_PONG, e.len, e.seq);
            break;
        case MSG_END:
            if (s_tp_len) {  // first END of this run (the initiator may retry)
                char label[16];
                snprintf(label, sizeof label, "tput_%u", s_tp_len);
                bench_tp_end(label);
                printf("PDR,%s,%u,%u\n", label, (unsigned) s_tp_rx, (unsigned) e.seq);
                s_tp_len = 0;
                bench_min_heap("responder");
                bench_stack("responder_task");
            }
            send_frame(s_peer, MSG_END_ACK, sizeof(bench_hdr_t), e.seq);
            break;
        }
    }
}

void app_main(void)
{
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    vTaskDelay(pdMS_TO_TICKS(3000));  // give the serial monitor time to attach
#if BENCH_CRYPTO
    printf("BENCH_START,crypto\n");
    bench_crypto_run();
    return;
#endif
    printf("BENCH_START,security=%d\n", BENCH_SECURITY);

    bench_heap("pre_wifi_init");
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_channel(WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE));
    bench_heap("post_wifi_init");

    s_sent = xSemaphoreCreateBinary();
    s_reply = xSemaphoreCreateBinary();
    s_rx_q = xQueueCreate(16, sizeof(rx_evt_t));
    configASSERT(s_sent && s_reply && s_rx_q);
    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_send_cb(send_cb));
    ESP_ERROR_CHECK(esp_now_register_recv_cb(recv_cb));
#if ENCRYPT
    ESP_ERROR_CHECK(esp_now_set_pmk(PMK));
#endif
    add_peer(BROADCAST, false);  // broadcast frames cannot be encrypted
    bench_heap("post_espnow_init");

    // Discovery: broadcast until we hear the other board, then keep going for a
    // second so it surely hears us too.
    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_STA, s_self));
    while (!s_have_peer) {
        send_frame(BROADCAST, MSG_HELLO, sizeof(bench_hdr_t), 0);
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    add_peer(s_peer, ENCRYPT);
    for (int i = 0; i < 10; i++) {
        send_frame(BROADCAST, MSG_HELLO, sizeof(bench_hdr_t), 0);
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    bool initiator = memcmp(s_self, s_peer, ESP_NOW_ETH_ALEN) < 0;
    printf("ROLE,%s,self=" MACSTR ",peer=" MACSTR "\n",
           initiator ? "initiator" : "responder", MAC2STR(s_self), MAC2STR(s_peer));
    bench_heap("peer_added");

    xTaskCreate(initiator ? initiator_task : responder_task, "bench", 4096, NULL, 5, NULL);
}
