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
#include "esp_random.h"
// #include <ascon/ascon.h>
// #include <ascon/constants.h>
// #include <ascon/crypto_aead.h>

/**
 * Define the types of radio as either:
 * - RADIO_CLIENT
 * - RADIO_SERVER
 */

static uint8_t BROADCAST_MAC[ESP_NOW_ETH_ALEN] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

#define ESPNOW_MAXDELAY 512

static const char *TAG = "ESPNOW";
static const uint8_t WIFI_CHANNEL = 7; // WiFi channel to communicate over

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
Consumes callback event by managing how data is parsed.
Input:
- params: cached parameters such as keys and peer details
- send: callback event details
*/
static void process_send_event(espnow_communication_params_t *params, espnow_event_send_cb_t *send)
{
    espnow_crypto_state_t *state = &params->espnow_crypto_state;
    uint8_t *peer_addr = params->espnow_peer_addr;

    switch (*state) 
    {
        // broadcast the hello message
        case DISCOVER:
#ifdef  RADIO_CLIENT
            ESP_ERROR_CHECK(esp_now_send(peer_addr, (uint8_t *)params->hello_packet, CRYPT_HELLO_LEN));
            if(send->status != ESP_NOW_SEND_SUCCESS) ESP_LOGI("PROCESS_SEND_EVENT()::DISCOVER", "message not received by recipient.");
#elif   RADIO_SERVER
#endif
            // let radio rest
            // vTaskDelay(pdMS_TO_TICKS(100));
            break;

        case AUTH:
            // if we don't reach the other person, try again
            ESP_LOGI("process_send_event()::AUTH", "Sending Auth Packet");
            static int auth_timeout = 0;

            if(auth_timeout > 15) { // timeout and retry
                ESP_LOGI("process_send_event()::AUTH", "Failed to send Auth packet, returning to discover phase");

                auth_timeout = 0;
                // remove peer from peer list
                esp_now_del_peer(params->espnow_peer_addr);
                memcpy(params->espnow_peer_addr, BROADCAST_MAC, ESP_NOW_ETH_ALEN);

                // return to discovery state
                *state = DISCOVER;
                prime_radio(params);
            }

            if (send->status != ESP_NOW_SEND_SUCCESS) { // 
                auth_timeout = auth_timeout + 1;
                esp_now_send(peer_addr, (uint8_t *)params->auth_packet, CRYPT_AUTH_LEN);
                vTaskDelay(pdMS_TO_TICKS(200));

                ESP_LOGI("process_send_event()::AUTH", ".");
            }


            break;

        case SESSION_OK:
            // encrypt the message
            // send the ciphertext
            break;

        default:
    }

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
    uint8_t *peer_mac = params->espnow_peer_addr;

    // get data
    uint8_t *recv_data;
    memcpy(&recv_data, recv->data, recv->data_len);

    switch(*state)
    {
        // we received a hello message back from the server, move on to the next state
        case DISCOVER:
            // get data
            memcpy(peer_mac, recv->mac_addr, ESP_NOW_ETH_ALEN);

            // parse data for peer
            if(crypt_parse_hello(recv_data, CRYPT_HELLO_LEN, &params->session.peer) != 0) {
                free(recv->data);
                return;
            }
            
            // add device to peer list
            esp_now_peer_info_t send_peer;
            send_peer.channel = WIFI_CHANNEL;
            send_peer.ifidx = WIFI_IF_STA;
            send_peer.encrypt = false; // set to true to use built in CCMP for espnow
            memcpy(send_peer.peer_addr, peer_mac, ESP_NOW_ETH_ALEN);
            ESP_ERROR_CHECK(esp_now_add_peer(&send_peer));

            // crate auth shared keys and generate encrypted nonce
            crypt_make_auth(params->auth_packet, &params->session, device_private_key);

            // switch state
            *state = AUTH;
            ESP_LOGI("PROCESS_RECV_EVENT()::DISCOVER", "Change state to AUTH");
            break;

        case AUTH: // We got the auth packet! Lets see if it is good.
            // if the nonce can be decrypted and it matches the nonce we sent, then we know the other person has the shared key.
            if (accept_auth(recv_data, recv->data_len, &params->session) != 0) {
                ESP_LOGI("process_recv_event()::AUTH", "Verification failed, rejecting peer");

                // remove peer from peer list
                esp_now_del_peer(params->espnow_peer_addr);
                memcpy(params->espnow_peer_addr, BROADCAST_MAC, ESP_NOW_ETH_ALEN);

                free(recv->data);

                // return to discovery state
                *state = DISCOVER;
                prime_radio(params);
            }
                // move on to SESSION_OK and store the shared key
            // otherwise, go deny the connection, remove the peer, go back to broadcast mode, and set the mode to HELLO.
            ESP_LOGI("process_recv_event()::AUTH", "Verification succeeded, SESSION_OK!");

            *state = SESSION_OK;
            // send a single SESSION_OK packet
            break;

        case SESSION_OK:
            // decrypt the message with the shared key.

            break;

        default:
    }

    free(recv->data);
}

static void prime_radio(espnow_communication_params_t *params) { 
    ESP_ERROR_CHECK( esp_now_send(params->espnow_peer_addr, params->hello_packet, CRYPT_HELLO_LEN) );
}

// Initializes all cryptographic parameters and related session info
static void init_cryptographic_parameters(espnow_communication_params_t *params) {
    memcpy(params->espnow_peer_addr, BROADCAST_MAC, ESP_NOW_ETH_ALEN);
    uint8_t *hello_packet = params->hello_packet;

    // create and store the hello packet once
    crypt_make_hello_packet(hello_packet, device_private_key, &params->session.local, esp_random);
}

static void radio_task(void *pvParameter)
{
    (void)pvParameter;

    espnow_event_t evt;
    espnow_communication_params_t params;

    init_cryptographic_parameters(&params);

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
                espnow_event_send_cb_t *send = &evt.info.send_cb;
                process_send_event(&params, send);
                break;

            case ESPNOW_RECV_CB_EVT:
                // get data from event
                espnow_event_recv_cb_t *recv = &evt.info.recv_cb;
                process_recv_event(&params, recv);
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