#ifndef MAIN_H
#define MAIN_H

#include <stdio.h>
#include "esp_now.h"
#include "compact25519/compact25519.h"

// hardware macros
#define HIGH 1
#define LOW 0

// hardware definition macros
#define LED_PIN 21

#define ESPNOW_QUEUE_SIZE 6

#define IS_BROADCAST_ADDR(addr) (memcmp(addr, BROADCAST_MAC, ESP_NOW_ETH_ALEN) == 0)

// cryptography constants (in bytes)
#define ED25519_PRIVKEY_LEN 32
#define ED25519_PUBKEY_LEN 32
#define NONCE_LEN 16
#define X25519_EPH_PUBKEY_LEN 32
#define ED25519_SIG_LEN 64
#define SESSION_ID_LEN 8
#define COUNTER_LEN 8
#define CIPHERTEXT_LEN 32
#define AEAD_AUTH_TAG_LEN 16

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
    DISCOVER,
    AUTH,
    SESSION_OK
} espnow_crypto_state_t;

/* CRYPTOGRAPHIC DATA STRUCTS WHILE SENDING OR RECEIVING */
typedef struct
{
    uint8_t version;
    uint8_t type;
    uint16_t length;

    uint8_t ed25519_pub[ED25519_PUBKEY_LEN];
    uint8_t nonce[NONCE_LEN];
    uint8_t x25519_pub[X25519_EPH_PUBKEY_LEN];
} espnow_data_hello_t;

typedef struct
{
    uint8_t version;
    uint8_t type;
    uint16_t length;

    uint8_t ed25519_pub[ED25519_PUBKEY_LEN];
    uint8_t ed25519_sig[ED25519_SIG_LEN];
} espnow_data_auth_t;

typedef struct
{
    uint8_t version;
    uint8_t type;
    uint16_t length;

    uint8_t session_id[SESSION_ID_LEN];
    uint8_t counter[COUNTER_LEN];

    char cipher[CIPHERTEXT_LEN];
    uint8_t auth_tag[AEAD_AUTH_TAG_LEN];
} espnow_data_msg_t;

/* PERSISTENT DATA BETWEEN LOOPS */
/*
Store any secrets in this struct
*/
typedef struct {
    // uint8_t shared_secret
    uint8_t priv_key[ED25519_PRIVKEY_LEN];
} espnow_data_private_keys_t;

/*
Store any public identity keys here 
*/
typedef struct {
    uint8_t ed25519_pub[ED25519_PUBKEY_LEN];
    uint8_t x25519_pub[X25519_EPH_PUBKEY_LEN];
} espnow_data_public_keys_t;

/* when receving/sending data, ensures the session id and counter are on the same frame */
typedef struct {
    uint8_t version;
    uint8_t type;

    uint8_t session_id[SESSION_ID_LEN];
    uint8_t frame_counter[COUNTER_LEN];
} espnow_data_session_info_t;

typedef struct {
    uint8_t addr[ESP_NOW_ETH_ALEN];             // who to send to
    espnow_radio_mode_t radio_mode;             // tracks if we are broadcasting or unicasting

    espnow_data_public_keys_t keys;             // unicast send_peer keys 
    uint8_t nonce[NONCE_LEN];
} espnow_data_peer_info_t;

typedef union {
    espnow_data_public_keys_t public;
    espnow_data_private_keys_t private;
} espnow_data_cryptography_keys_t;

/*
caches information about the current session between loops
*/
typedef struct {
    espnow_data_cryptography_keys_t keys;       // all related crypto keys
    espnow_data_peer_info_t send_peer;          // send_peer related info including keys
    
    espnow_crypto_state_t espnow_crypto_state;  // tracks what state the cryptographic protocl is in
    espnow_data_session_info_t session_info;    // tracks session info
} espnow_communication_params_t;

#endif /* MAIN_H */