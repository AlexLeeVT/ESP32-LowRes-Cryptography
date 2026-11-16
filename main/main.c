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

static uint8_t BROADCAST_MAC[ESP_NOW_ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#define ESPNOW_MAXDELAY 512

static const char *TAG = "ESPNOW";
static const uint8_t WIFI_CHANNEL = 10; // WiFi channel to communicate over

static QueueHandle_t s_espnow_queue = NULL; // event prod-con queue

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
Callback function after a packet is sent and the radio is ready again
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
    esp_now_peer_info_t send_peer;
    send_peer.channel = WIFI_CHANNEL;
    send_peer.ifidx = WIFI_IF_STA;
    send_peer.encrypt = false;
    memcpy(send_peer.peer_addr, BROADCAST_MAC, ESP_NOW_ETH_ALEN);
    ESP_ERROR_CHECK(esp_now_add_peer(&send_peer));

    return ESP_OK;
}

/*
shutdown espnow if we run into any issues.
*/
// static void espnow_deinit(espnow_data_t *p_send_param)
// {
//     espnow_event_t evt;

//     while (xQueueReceive(s_espnow_queue, &evt, 0) == pdTRUE)
//     {
//         if (evt.id == ESPNOW_RECV_CB_EVT)
//         {
//             free(evt.info.recv_cb.data);
//         }
//     }
//     vQueueDelete(s_espnow_queue);
//     s_espnow_queue = NULL;
//     esp_now_deinit();
// }

/*
This task consumes available work and processes the data accordingly
*/
#ifdef RADIO_SERVER
#endif /* RADIO_SERVER */

/*
This task consumes available work and processes the data accordingly
*/
static void process_send_event(espnow_communication_params_t *params, espnow_event_send_cb_t *send)
{
    espnow_crypto_state_t *state = &params->espnow_crypto_state;
    espnow_data_peer_info_t *send_peer = &params->send_peer;
    espnow_data_public_keys_t *pubkeys = &params->keys.public;

    espnow_data_hello_t hello_buf = {
        .type = params->session_info.type,
        .version = params->session_info.version,
        .length = sizeof(espnow_data_hello_t),
    };
    memcpy(hello_buf.ed25519_pub, pubkeys->ed25519_pub, ED25519_PUBKEY_LEN);
    memcpy(hello_buf.x25519_pub, pubkeys->x25519_pub, X25519_EPH_PUBKEY_LEN);

    esp_err_t e;


    switch (*state) 
    {
        // continually send discovery checks while in broadcast mode
        // case DISCOVER:
        //     break;

        // case AUTH:
        //     break;

        // case SESSION_OK:
        //     break;

        default:
#ifdef  RADIO_CLIENT
            e = esp_now_send(send_peer->addr, (uint8_t *)&hello_buf, sizeof(espnow_data_hello_t));
            ESP_ERROR_CHECK(e);
#elif   RADIO_SERVER
#endif

            if(send->status != ESP_NOW_SEND_SUCCESS) ESP_LOGI("PROCESS_SEND_EVENT()", "message not received by recipient.");
            // let radio rest
            vTaskDelay(pdMS_TO_TICKS(100));
    }
    //   case HELLO
    //       Broadcast Hello Message

    //   case AUTHENTICATE
    //       generate signature
    //       Unicast Auth Message

    //   case SESSION_OK
    //       encrypt message
    //       send unicast
}

/**
 * Process the receive data and
 */
static void process_recv_event(espnow_communication_params_t *params, espnow_event_recv_cb_t *recv)
{
    espnow_crypto_state_t *state = &params->espnow_crypto_state;
    espnow_data_peer_info_t *peer = &params->send_peer;
    espnow_data_public_keys_t *peer_keys = &peer->keys;

    switch(*state)
    {
        // we received a hello message back from the server, move on to the next state
        case DISCOVER:
            // generate relevant cryptographic authentication
            
            // get data
            espnow_data_hello_t recv_data;
            if(recv->data_len != sizeof(espnow_data_hello_t)) {
                ESP_LOGI("process_recv_event()::DISCOVER", "Incorrect data received");
                free(recv->data);
                return;
            }

            ESP_LOGI("process_recv_event()::DISCOVER", "Received acknowledgement from server");
            memcpy(&recv_data, recv->data, sizeof(espnow_data_hello_t));
            
            // get receiver MAC address
            memcpy(peer->addr, recv->mac_addr, ESP_NOW_ETH_ALEN);

            // copy public keys over into persistent data structure
            memcpy(peer_keys->ed25519_pub, recv_data.ed25519_pub, ED25519_PUBKEY_LEN);
            memcpy(peer_keys->x25519_pub, recv_data.x25519_pub, X25519_EPH_PUBKEY_LEN);
            
            // put device in unicast mode and add peer
            esp_now_peer_info_t send_peer;
            send_peer.channel = WIFI_CHANNEL;
            send_peer.ifidx = WIFI_IF_STA;
            send_peer.encrypt = false; // set to true to use built in CCMP for espnow
            memcpy(send_peer.peer_addr, peer->addr, ESP_NOW_ETH_ALEN);
            ESP_ERROR_CHECK(esp_now_add_peer(&send_peer));
            
            peer->radio_mode = ESPNOW_DATA_UNICAST;

            *state = AUTH;
            break;

        case AUTH:
            ESP_LOGI("PROCESS_RECV_EVENT()::AUTH", "Hello from auth");
            break;

        default:
    }

    // switch (s_session_state)
    //   case HELLO
    //       if ( msg_recv is HELLO message )
    //           get oth_key
    //           get oth mac addr
    //           set to unicast
    //           change callback functions

    //           s_session_state = AUTHENTICATE

    //   case AUTHENTICATE
    //       get signature
    //       biuld signature

    //   case SESSION_OK
    //       verify signature
    //       HKDF
}

static void prime_radio(espnow_communication_params_t *params) {
    espnow_data_peer_info_t *send_peer = &params->send_peer;
    espnow_data_public_keys_t *pubkeys = &params->keys.public;

    espnow_data_hello_t hello_buf = {
        .type = params->session_info.type,
        .version = params->session_info.version,
        .length = sizeof(espnow_data_hello_t),
    };
    memcpy(hello_buf.ed25519_pub, pubkeys->ed25519_pub, ED25519_PUBKEY_LEN);
    memcpy(hello_buf.x25519_pub, pubkeys->x25519_pub, X25519_EPH_PUBKEY_LEN);

    ESP_ERROR_CHECK( esp_now_send(send_peer->addr, (uint8_t *)&hello_buf, sizeof(espnow_data_hello_t)) );
}

// Initializes all cryptographic parameters and related session info
static void init_cryptographic_secrets(espnow_communication_params_t *params) {
    memcpy(params->send_peer.addr, BROADCAST_MAC, ESP_NOW_ETH_ALEN);
    memset(params->keys.public.ed25519_pub, 1, ED25519_PUBKEY_LEN);
    memset(params->keys.public.x25519_pub, 2, ED25519_PUBKEY_LEN);
}


static void radio_task(void *pvParameter)
{
    (void)pvParameter;

    espnow_event_t evt;
    espnow_communication_params_t params;

    init_cryptographic_secrets(&params);

#ifdef RADIO_CLIENT
    ESP_LOGI("radio_task()", "Start radio task, radio ready!");
    vTaskDelay(pdMS_TO_TICKS(5000));
    prime_radio(&params);
#endif

    while (1)
    {
        // this queue is only populated AFTER a callback function is executed.
        if (xQueueReceive(s_espnow_queue, &evt, portMAX_DELAY) == pdTRUE)
        {
            switch (evt.id)
            {
            case ESPNOW_SEND_CB_EVT:
                ESP_LOGI("RADIO_TASK()", "message sent!");
                espnow_event_send_cb_t *send = &evt.info.send_cb;
                process_send_event(&params, send);
                break;

            case ESPNOW_RECV_CB_EVT:
                // get data from event
                espnow_event_recv_cb_t *recv = &evt.info.recv_cb;
                process_recv_event(&params, recv);
                free(recv->data);
                break;
            default:
                ESP_LOGW("RADIO_TASK", "invalid event id, exiting.");
            }
        }
    }
}

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