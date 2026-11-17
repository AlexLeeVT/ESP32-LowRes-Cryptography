#ifndef MAIN_H
#define MAIN_H

// standrard includes
#include <stdio.h>

// esp includes
#include "esp_now.h"

// cryptography includes
#include "crypto_main.h"

#define RADIO_CLIENT
// #define RADIO_SERVER

// hardware macros
#define HIGH 1
#define LOW 0

// hardware definition macros
#define LED_PIN 21

// espnow macros
#define ESPNOW_QUEUE_SIZE 6
#define IS_BROADCAST_ADDR(addr) (memcmp(addr, BROADCAST_MAC, ESP_NOW_ETH_ALEN) == 0)
#define PLAINTEXT_LEN 32
#define ENCRYPTED_PACKET_SIZE CRYPT_DATA_FIXED_LEN + PLAINTEXT_LEN + CRYPT_TAG_LEN

/**
 * ------------------------------------DISCLAIMER--------------------------------------------- 
 * WARNING!!!
 * 
 * THIS IS A PROOF OF CONCEPT CODE AND TYPICALLY SECRET KEYS ARE NOT NOT SHARED!
 * NEVER SHARE YOUR ACTUAL PRIVATE KEY AS IT COULD COMPROMISE YOUR PROJECT AND ANY RESOURCES ATTACHED
 * SHARING YOUR PRIVATE KEY COULD LEAD TO MAJOR SECURITY FLAWS 
 * 
 * Good practice is to load it from an environment variable or a local file and **never** uploaded anywhere.
 * ------------------------------------DISCLAIMER--------------------------------------------- 
 */
#if defined( RADIO_CLIENT )
static const uint8_t device_private_key[64] = {
    0x0c, 0x09, 0xe0, 0x7d, 0x0d, 0x59, 0x0e, 0x87, 
    0xdf, 0xba, 0x34, 0x40, 0x7e, 0x99, 0xd3, 0x9f, 
    0x55, 0xcd, 0x41, 0x87, 0x9b, 0xf6, 0x6e, 0xd6, 
    0xa0, 0xb0, 0x3b, 0x9f, 0x00, 0xd0, 0xeb, 0x51, 
    0xe6, 0xb9, 0xf4, 0xcc, 0x78, 0x6d, 0x76, 0x8b, 
    0xf9, 0x54, 0xb0, 0x1f, 0x19, 0xa5, 0x3e, 0xeb, 
    0x89, 0x14, 0x8d, 0x57, 0xae, 0xc4, 0x7b, 0x0d, 
    0x85, 0x3f, 0xbb, 0x70, 0x23, 0xb5, 0x61, 0x23
};
static const uint8_t device_public_key[32] = {
    0xe6, 0xb9, 0xf4, 0xcc, 0x78, 0x6d, 0x76, 0x8b, 
    0xf9, 0x54, 0xb0, 0x1f, 0x19, 0xa5, 0x3e, 0xeb, 
    0x89, 0x14, 0x8d, 0x57, 0xae, 0xc4, 0x7b, 0x0d, 
    0x85, 0x3f, 0xbb, 0x70, 0x23, 0xb5, 0x61, 0x23
};
#elif defined( RADIO_SERVER )
static const uint8_t device_private_key[64] = {
    0xd7, 0xc7, 0x12, 0x19, 0xe6, 0x77, 0x6a, 0xdd, 
    0xdc, 0x05, 0x12, 0x88, 0x8d, 0xe9, 0x25, 0x45, 
    0x4c, 0xfa, 0x6c, 0xea, 0xc8, 0xcb, 0xc5, 0xa1, 
    0xec, 0x6e, 0x1a, 0xfa, 0xf5, 0xf8, 0x62, 0x14, 
    0x59, 0xde, 0xb4, 0xa7, 0x3f, 0xfc, 0x81, 0x94, 
    0x61, 0xbe, 0x97, 0x1f, 0x3c, 0x7e, 0x60, 0xd9, 
    0x2c, 0x59, 0xf1, 0x0e, 0xe5, 0x4b, 0xbf, 0x0b, 
    0x36, 0xb2, 0x8f, 0x15, 0x1f, 0xf7, 0xbf, 0x67
};
static const uint8_t device_public_key[32] = {
    0x59, 0xde, 0xb4, 0xa7, 0x3f, 0xfc, 0x81, 0x94, 
    0x61, 0xbe, 0x97, 0x1f, 0x3c, 0x7e, 0x60, 0xd9, 
    0x2c, 0x59, 0xf1, 0x0e, 0xe5, 0x4b, 0xbf, 0x0b, 
    0x36, 0xb2, 0x8f, 0x15, 0x1f, 0xf7, 0xbf, 0x67
};
#endif

/* ESPNOW Handling Structs */
typedef enum
{
    ESPNOW_SEND_CB_EVT,
    ESPNOW_RECV_CB_EVT,
} espnow_event_id_t;

typedef struct
{
    uint8_t mac_addr[ESP_NOW_ETH_ALEN];
    esp_now_send_status_t status;
} espnow_event_send_cb_t;

typedef struct
{
    uint8_t mac_addr[ESP_NOW_ETH_ALEN];
    uint8_t *data;
    int data_len;
} espnow_event_recv_cb_t;

typedef union
{
    espnow_event_send_cb_t send_cb;
    espnow_event_recv_cb_t recv_cb;
} espnow_event_info_t;


/* When ESPNOW sending or receiving callback function is called, post event to ESPNOW task. */
typedef struct
{
    espnow_event_id_t id;
    espnow_event_info_t info;
} espnow_event_t;

typedef enum
{
    ESPNOW_DATA_BROADCAST,
    ESPNOW_DATA_UNICAST,
    ESPNOW_DATA_MAX,
} espnow_radio_mode_t;

/*------------------------------------------- CRYPTOGRAPIC DATA AND PRIMITAVES ----------------------------------------------------*/

typedef enum
{
    AWAIT,
    DISCOVER,
    AUTH,
    SESSION_OK
} espnow_crypto_state_t;

/*
caches information about the current session between loops. 
*/
typedef struct {
    uint8_t espnow_peer_addr[ESP_NOW_ETH_ALEN]; // who do we send to
    espnow_crypto_state_t espnow_crypto_state;  // tracks what state the cryptographic protocl is in
    crypt_session_t session;

    uint8_t hello_packet[CRYPT_HELLO_LEN];
    uint8_t auth_packet[CRYPT_AUTH_LEN];
    uint8_t encrypted_packet[ENCRYPTED_PACKET_SIZE];
    size_t encrypted_len, decrypted_len;
    bool ready;
} espnow_communication_params_t;

#endif /* MAIN_H */