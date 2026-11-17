#include "main.h"

// C includes
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// FreeRTOS libs
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

// ESP32 Hardware Libraries
#include "esp_log.h"

// ESP32 WIFI Libs
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_mac.h"
#include "esp_now.h"

// Primitive and Crypt Libraries
#include "esp_random.h"

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

static void prime_radio(espnow_communication_params_t *params) { 
    ESP_ERROR_CHECK( esp_now_send(params->espnow_peer_addr, params->hello_packet, CRYPT_HELLO_LEN) );
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
    static int auth_timeout = 0;
    espnow_crypto_state_t *state = &params->espnow_crypto_state;
    uint8_t *peer_addr = params->espnow_peer_addr;

    switch (*state) 
    {
        case AWAIT:
            // do nothing
            break;
        // broadcast the hello message
        case DISCOVER:
            auth_timeout = 0;
            ESP_ERROR_CHECK(esp_now_send(peer_addr, params->hello_packet, CRYPT_HELLO_LEN));
            if(send->status != ESP_NOW_SEND_SUCCESS) ESP_LOGI("PROCESS_SEND_EVENT()::DISCOVER", "message not received by recipient.");
            ESP_LOGI("process_send_event()::DISCOVER", "hello msg sent!");
            // let radio rest
            vTaskDelay(pdMS_TO_TICKS(100));
            break;

        case AUTH:
            // if we don't reach the other person, try again
            ESP_LOGI("process_send_event()::AUTH", "Sending Auth Packet");

            if(auth_timeout > 15) { // timeout and retry
                ESP_LOGI("process_send_event()::AUTH", "Failed to send Auth packet, returning to discover phase");

                auth_timeout = 0;
                // remove peer from peer list
                esp_now_del_peer(params->espnow_peer_addr);
                memcpy(params->espnow_peer_addr, BROADCAST_MAC, ESP_NOW_ETH_ALEN);

                // return to discovery state
                *state = DISCOVER;
                prime_radio(params);
                
                return;
            }

            if (send->status != ESP_NOW_SEND_SUCCESS) { // 
                auth_timeout = auth_timeout + 1;
                esp_now_send(peer_addr, params->auth_packet, CRYPT_AUTH_LEN);
                vTaskDelay(pdMS_TO_TICKS(200));

                ESP_LOGI("process_send_event()::AUTH", ".");
            }


            break;

        case SESSION_OK:
            ESP_LOGI("process_send_event()::SESSION_OK", "Hello from session ok send");
            // encrypt the message
            // send the ciphertext
            
            break;

        default:
    }

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
    if (recv == NULL || recv->data == NULL ||
        recv->data_len <= 0 || recv->data_len > ESP_NOW_MAX_DATA_LEN) { 
            return; 
    }

    uint8_t *recv_data = malloc(recv->data_len);
    memcpy(recv_data, recv->data, recv->data_len);

    switch(*state)
    {
        case AWAIT:
#if defined( RADIO_SERVER )
            // parse data for peer
            ESP_LOGI("PROCESS_RECV_EVENT()::AWAIT", "Parsing Hello packet");
            if(crypt_parse_hello(recv_data, recv->data_len, &params->session.peer) != 0) {
                ESP_LOGI("PROCESS_RECV_EVENT()::AWAIT", "Failed parsing Hello packet");
                // free(recv->data);
                break;
            }
            
            // add device to peer list
            memcpy(peer_mac, recv->mac_addr, ESP_NOW_ETH_ALEN);
            esp_now_peer_info_t send_peer;
            send_peer.channel = WIFI_CHANNEL;
            send_peer.ifidx = WIFI_IF_STA;
            send_peer.encrypt = false; // set to true to use built in CCMP for espnow
            memcpy(send_peer.peer_addr, peer_mac, ESP_NOW_ETH_ALEN);
            ESP_ERROR_CHECK(esp_now_add_peer(&send_peer));

            ESP_LOGI("process_recv_event()::AWAIT", "change state to DISCOVER");
            *state = DISCOVER;
            prime_radio(params);
            break;
        // we received a hello message back from the server, move on to the next state
#endif
        case DISCOVER:
#if defined (RADIO_CLIENT)
            // parse data for peer
            ESP_LOGI("PROCESS_RECV_EVENT()::DISCOVER", "Parsing Hello packet");
            if(crypt_parse_hello(recv_data, recv->data_len, &params->session.peer) != 0) {
                ESP_LOGI("PROCESS_RECV_EVENT()::DISCOVER", "Failed parsing Hello packet");
                // free(recv->data);
                break;
            }
            
            // add device to peer list
            memcpy(peer_mac, recv->mac_addr, ESP_NOW_ETH_ALEN);
            esp_now_peer_info_t send_peer;
            send_peer.channel = WIFI_CHANNEL;
            send_peer.ifidx = WIFI_IF_STA;
            send_peer.encrypt = false; // set to true to use built in CCMP for espnow
            memcpy(send_peer.peer_addr, peer_mac, ESP_NOW_ETH_ALEN);
            ESP_ERROR_CHECK(esp_now_add_peer(&send_peer));
#endif
            // crate auth shared keys and generate encrypted nonce
            if(crypt_make_auth(params->auth_packet, &params->session, device_private_key)) {
                ESP_LOGI("process_recv_event()::DISCOVER", "Error making auth message!");
            }
            ESP_LOGI("PROCESS_RECV_EVENT()::DISCOVER", "Added peer %02x:%02x:%02x:%02x:%02x:%02x", 
                peer_mac[0], peer_mac[1], peer_mac[2], peer_mac[3], peer_mac[4], peer_mac[5]
            );
            esp_now_send(peer_mac, params->auth_packet, CRYPT_AUTH_LEN);

            // switch state
            *state = AUTH;
            ESP_LOGI("PROCESS_RECV_EVENT()::DISCOVER", "Change state to AUTH");
            break;

        case AUTH: // We got the auth packet! Lets see if it is good.
            int result = accept_auth(recv_data, recv->data_len, &params->session);

            // clear the buffer until we get to the auth data 
            if(recv_data[1] != CRYPT_TYPE_AUTH) {
                ESP_LOGI("process_recv_event()::AUTH", "Not an AUTH packet! skipping");
                break;
            }

            // verify the authentication
            if (result != 0) {
                ESP_LOGI("process_recv_event::AUTH", "AUTH result=%d type=%u len=%d", result,
                    recv->data_len >= 2 ? recv_data[1] : 0, recv->data_len);

                // remove peer from peer list
                esp_now_del_peer(params->espnow_peer_addr);
                memcpy(params->espnow_peer_addr, BROADCAST_MAC, ESP_NOW_ETH_ALEN);

                // free(recv->data);

                // return to discovery state
                *state = DISCOVER;
                prime_radio(params);
                break;
            }
            ESP_LOGI("process_recv_event()::AUTH", "Verification succeeded, SESSION_OK!");

            *state = SESSION_OK;
            // send a single SESSION_OK packet

#if defined(RADIO_CLIENT)
            crypt_data_encrypt(
                &params->session,
                params->session.outgoing_counter_initialized
                    ? params->session.last_outgoing_counter + 1
                    : 1,
                (const uint8_t *) "Hello from Client",
                PLAINTEXT_LEN,
                params->encrypted_packet,
                sizeof(params->encrypted_packet),
                &params->encrypted_len
            );

            esp_now_send(params->espnow_peer_addr, params->encrypted_packet, params->encrypted_len);
#endif


            break;

        case SESSION_OK:
            // decrypt the message with the shared key.
            ESP_LOGI("process_recv_event()::SESSION_OK", "Decrypt debug message");

            uint64_t incoming_counter =
                params->session.incoming_counter_initialized
                    ? params->session.last_incoming_counter + 1
                    : 1;

            uint8_t decrypted_message[PLAINTEXT_LEN];
            int ret = crypt_data_decrypt(
                &params->session,
                recv_data,
                recv->data_len,
                incoming_counter,
                decrypted_message,
                sizeof(decrypted_message),
                &params->decrypted_len
            );

            ESP_LOGI("process_recv_event::SESSION_OK", "Data: %s", decrypted_message);

            if (ret == 0)
            {

            // ping pong the data
            crypt_data_encrypt(
                &params->session,
                params->session.outgoing_counter_initialized
                    ? params->session.last_outgoing_counter + 1
                    : 1,
#if defined (RADIO_CLIENT)
                (const uint8_t *) "Hello from Client",
#elif defined (RADIO_SERVER)
                (const uint8_t *) "Hello from Server",
#endif
                PLAINTEXT_LEN,
                params->encrypted_packet,
                sizeof(params->encrypted_packet),
                &params->encrypted_len
            );

            esp_now_send(params->espnow_peer_addr, params->encrypted_packet, params->encrypted_len);
            }

            break;

        default:
    }

    free(recv_data);
    free(recv->data);
}

static int esp_random_wrapper(uint8_t *out, size_t length)
{
    esp_fill_random(out, length);
    return 0;
}

// Initializes all cryptographic parameters and related session info
static void init_cryptographic_parameters(espnow_communication_params_t *params) {
    memcpy(params->espnow_peer_addr, BROADCAST_MAC, ESP_NOW_ETH_ALEN);
#if defined(RADIO_CLIENT)
    params->espnow_crypto_state = DISCOVER;
#elif defined(RADIO_SERVER)
    params->espnow_crypto_state = AWAIT;
#endif
    params->ready = 0;

    // create and store the hello packet once
    crypt_make_hello_packet(params->hello_packet, device_private_key, &params->session.local, esp_random_wrapper);
}

static void radio_task(void *pvParameter)
{
    (void)pvParameter;

    ESP_LOGI("radio_task()", "Starting the radio task.");

    espnow_event_t evt;
    espnow_communication_params_t params;

    init_cryptographic_parameters(&params);

#if defined(RADIO_CLIENT)
    ESP_LOGI("radio_task()::CLIENT", "Radio ready!");
    vTaskDelay(pdMS_TO_TICKS(3000));
    prime_radio(&params);
#elif defined(RADIO_SERVER)
    ESP_LOGI("radio_task()::SERVER", "Radio ready!");
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

    xTaskCreate(radio_task, "radio_task", 8192, NULL, 4, NULL);
}