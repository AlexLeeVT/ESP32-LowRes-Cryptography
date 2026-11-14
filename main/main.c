#include "main.h"

// C includes
#include <stdio.h>

// FreeRTOS libs
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// ESP32 Hardware Libraries
#include "esp_log.h"
#include "driver/gpio.h"

// ESP32 WIFI Libs
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "nvs_flash.h"
#include "esp_mac.h"
#include "esp_now.h"

// Primitive and Crypt Libraries
// #include <ascon/api.h>
// #include <ascon/ascon.h>
// #include <ascon/constants.h>
// #include <ascon/crypto_aead.h>

/**
 * Define the types of radio as either:
 * - RADIO_CLIENT
 * - RADIO_SERVER
 */
#define RADIO_CLIENT

static uint8_t s_broadcast_mac[ESP_NOW_ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#define ESPNOW_MAXDELAY 512

static const char *TAG = "ESPNOW";
static const uint8_t WIFI_CHANNEL = 10; // WiFi channel to communicate over

static QueueHandle_t s_espnow_queue = NULL; // event prod-con queue

static bool s_has_peer = false;
static session_state_t s_session_state = DISCOVERY;

/*
Initialize the wifi radio. Communicates over 2.4 GhZ using IEEE 802.11
*/
void init_wifi()
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_channel(WIFI_CHANNEL, WIFI_SECOND_CHAN_NONE));
}

/*
Get the device MAC address
*/
static void get_mac_address()
{
    char mac[ESP_NOW_ETH_ALEN];
    esp_wifi_get_mac(WIFI_IF_STA, (uint8_t *)mac);
    ESP_LOGI("MAC address", "MAC address: %02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/*
Callback function when a packet is sent
*/
static void send_cb(const esp_now_send_info_t *tx_info, esp_now_send_status_t status)
{
    // create the event
    espnow_event_t evt;
    evt.id = ESPNOW_SEND_CB_EVT;

    // log relevant packet data
    espnow_event_send_cb_t *send = &evt.info.send_cb;
    memcpy(send->mac_addr, tx_info->des_addr, ESP_NOW_ETH_ALEN);
    send->status = status;

    // enqueue the event
    if (xQueueSend(s_espnow_queue, &evt, ESPNOW_MAXDELAY) != pdTRUE)
    {
        ESP_LOGW("SEND_CB", "queue send fail");
    }
}

/*
Callback function when a packet is received.
Do not do heavy computation in this function!
*/
static void recv_cb(const esp_now_recv_info_t *recv_info, const uint8_t *data, int len)
{
    // create the event
    espnow_event_t evt;
    evt.id = ESPNOW_RECV_CB_EVT;
    espnow_event_recv_cb_t *recv = &evt.info.recv_cb;

    // get the source and destination mac addresses
    uint8_t *mac_addr = recv_info->src_addr;
    uint8_t *dest_addr = recv_info->des_addr;

    // receive the data
    recv->data_len = len; // length and espnow_data_t data length should be the same
    recv->data = malloc(len);
    if (recv->data == NULL)
    {
        ESP_LOGE("RECV_CB", "malloc receive data failed");
        return;
    }
    memcpy(recv->data, data, len);
    memcpy(recv->mac_addr, mac_addr, ESP_NOW_ETH_ALEN);

    // enqueue the event
    if (xQueueSend(s_espnow_queue, &evt, ESPNOW_MAXDELAY) != pdTRUE)
    {
        ESP_LOGW("RECV_CB", "queue send fail");
        free(recv->data);
    }
}

/*
initialize the espnow library
Return:
 - ESP_ERROR or ESP_OK
*/
static esp_err_t init_espnow()
{
    // initialize event producer-consumer queue
    s_espnow_queue = xQueueCreate(ESPNOW_QUEUE_SIZE, sizeof(espnow_event_t));
    if (s_espnow_queue == NULL)
    {
        ESP_LOGE(TAG, "malloc event queue fail");
        return ESP_FAIL;
    }

    // initialize the callback functions
    ESP_ERROR_CHECK(esp_now_init());
    ESP_ERROR_CHECK(esp_now_register_send_cb(send_cb));
    ESP_ERROR_CHECK(esp_now_register_recv_cb(recv_cb));

    // setup broadcast mode
    esp_now_peer_info_t peer;
    peer.channel = WIFI_CHANNEL;
    peer.ifidx = WIFI_IF_STA;
    peer.encrypt = false;
    memcpy(peer.peer_addr, s_broadcast_mac, ESP_NOW_ETH_ALEN);
    ESP_ERROR_CHECK(esp_now_add_peer(&peer));

    return ESP_OK;
}

/*
shutdown espnow if we run into any issues.
*/
static void espnow_deinit(espnow_data_t *send_param)
{
    espnow_event_t evt;

    while (xQueueReceive(s_espnow_queue, &evt, 0) == pdTRUE)
    {
        if (evt.id == ESPNOW_RECV_CB_EVT)
        {
            free(evt.info.recv_cb.data);
        }
    }
    vQueueDelete(s_espnow_queue);
    s_espnow_queue = NULL;
    esp_now_deinit();
}

/*
This task consumes available work and processes the data accordingly
*/
#ifdef RADIO_SERVER
// static void radio_task(void *pvParamter) {

// }
#endif

/*
This task consumes available work and processes the data accordingly
*/
#ifdef RADIO_CLIENT
// static void process_send_event() {
//     /**
//      * switch(s_session_sate)
//      *      case HELLO
//      *          Broadcast Hello Message
//      *
//      *      case AUTHENTICATE
//      *          generate signature
//      *          Unicast Auth Message
//      *
//      *      case SESSION_OK
//      *          encrypt message
//      *          send unicast
//      */
// }

// static void process_recv_event() {
//     /**
//      * switch(s_session_sate)
//      *      case HELLO
//      *          if ( msg_recv is HELLO message )
//      *              get oth_key
//      *              get oth mac addr
//      *              set to unicast
//      *              change callback functions
//      *
//      *
//      *
//      *              s_session_state = AUTHENTICATE
//      *
//      *      case AUTHENTICATE
//      *          get signature
//      *          biuld signature
//      *
//      *      case SESSION_OK
//      *          verify signature
//      *          HKDF
//      */
// }

static void radio_task(void *pvParameter)
{
    (void)pvParameter;

    ESP_LOGI("RADIO_TASK", "Start Radio Task");
    espnow_event_t evt;

    // setup initial data packet

    espnow_data_t data = {
        .count = 0,
        .msg = "DISCOVERY"};
    memcpy(data.send_peer, s_broadcast_mac, ESP_NOW_ETH_ALEN);

    // send at least one packet on start
    ESP_ERROR_CHECK(esp_now_send(s_broadcast_mac, (const uint8_t *)&data, sizeof(espnow_data_t)));

    // task loop
    while (1)
    {
        // this queue is only populated AFTER a callback function is executed.
        if (xQueueReceive(s_espnow_queue, &evt, portMAX_DELAY) == pdTRUE)
        {
            switch (evt.id)
            {
            case ESPNOW_SEND_CB_EVT:
                ESP_LOGI("RADIO_TASK", "message sent!");
                // do some data manipulation
                data.count += 1;

                // ship the data over
                ESP_ERROR_CHECK(esp_now_send(data.send_peer, (const uint8_t *)&data, sizeof(espnow_data_t)));
                vTaskDelay(pdMS_TO_TICKS(200));
                break;

            case ESPNOW_RECV_CB_EVT:
                // get data from event
                espnow_event_recv_cb_t *recv = &evt.info.recv_cb;
                if (recv->data_len != sizeof(espnow_data_t))
                {
                    ESP_LOGW("RADIO_TASK", "invalid packet length: %d", recv->data_len);
                    free(recv->data);
                    break;
                }
                espnow_data_t recv_data;
                uint8_t *src_mac = recv->mac_addr;

                memcpy(&recv_data, recv->data, sizeof(espnow_data_t));

                // do something with the data
                ESP_LOGI("RADIO_TASK",
                         "message received: \n\tcount: %d\n\tmsg: %s\n\tSender MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                         recv_data.count,
                         recv_data.msg,
                         src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);

                // we discovered another device, add as a peer and swap target to them
                if (!IS_BROADCAST_ADDR(src_mac) && !s_has_peer)
                {
                    ESP_LOGI("RADIO TASK",
                             "Adding Peer: Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x",
                             src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
                    memcpy(data.send_peer, src_mac, ESP_NOW_ETH_ALEN);

                    esp_now_peer_info_t peer;
                    peer.channel = WIFI_CHANNEL;
                    peer.ifidx = WIFI_IF_STA;

                    // set to true to use built in CCMP espnow
                    peer.encrypt = false;
                    memcpy(peer.peer_addr, src_mac, ESP_NOW_ETH_ALEN);
                    ESP_ERROR_CHECK(esp_now_add_peer(&peer));

                    // change the message to show difference in state
                    memcpy(data.msg, "PEER FOUND", MESSAGE_LENGTH);
                    s_has_peer = true;
                }

                free(recv->data);
                break;
            default:
                ESP_LOGW("RADIO_TASK", "invalid event id, exiting.");
            }
        }
    }

    /*
    switch (evt.id):
        case SEND:
            // log we have sent a messaeg
            // log unicast or brodacst
            // log where we sent it to
        case RECV:
            switch (connection_state):
                // hello message
                case DISCOVERY:
                case AUTH:
                    if (auth == OK) {
                        connection_state = SESSION_OK
                    }
                case SESSION_OK:
                    // send messsage data using secrety key & session_ids
                    */
    // }
}
#endif

/*
entry point for application
*/
void app_main(void)
{
    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND)
    {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    init_wifi();
    ESP_ERROR_CHECK(init_espnow());

    get_mac_address();

    xTaskCreate(radio_task, "radio_task", 2048, NULL, 4, NULL);
}