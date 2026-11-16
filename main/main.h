#ifndef MAIN_H
#define MAIN_H

// standrard includes
#include <stdio.h>

// esp includes
#include "esp_now.h"

// cryptography includes
#include "compact25519/compact25519.h"
#include "ascon/api.h"

// hardware macros
#define HIGH 1
#define LOW 0

// hardware definition macros
#define LED_PIN 21

// espnow macros
#define ESPNOW_QUEUE_SIZE 6
#define IS_BROADCAST_ADDR(addr) (memcmp(addr, BROADCAST_MAC, ESP_NOW_ETH_ALEN) == 0)

// cryptography macros
#define NONCE_SIZE 16
#define SESSION_ID_SIZE 8
#define CIPHERTEXT_SIZE 32

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

    uint8_t ed25519[ED25519_PUBLIC_KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t x25519[X25519_KEY_SIZE];
} espnow_data_hello_t;

typedef struct
{
    uint8_t version;
    uint8_t type;
    uint16_t length;

    uint8_t ed25519[ED25519_PUBLIC_KEY_SIZE];
    uint8_t ed25519_sig[ED25519_SIGNATURE_SIZE];
} espnow_data_auth_t;

typedef struct
{
    uint8_t version;
    uint8_t type;
    uint16_t length;

    uint64_t session_id;
    uint64_t counter;

    char cipher[CIPHERTEXT_SIZE];
    uint8_t auth_tag[AEAD_AUTH_TAG_LEN];
} espnow_data_msg_t;

/* PERSISTENT DATA BETWEEN LOOPS */
/*
Store any secrets in this struct
*/
typedef struct {
    // uint8_t shared_secret
    uint8_t ed25519[ED25519_PRIVATE_KEY_SIZE];
    uint8_t x25519[X25519_KEY_SIZE];
} espnow_data_private_keys_t;

/*
Store any public identity keys here 
*/
typedef struct {
    uint8_t ed25519[ED25519_PUBLIC_KEY_SIZE];
    uint8_t x25519[X25519_KEY_SIZE];
} espnow_data_public_keys_t;

/* when receving/sending data, ensures the session id and counter are on the same frame */
typedef struct {
    uint8_t version;
    uint8_t type;

    uint8_t session_id[SESSION_ID_SIZE];
    uint64_t frame_counter;
} espnow_data_session_info_t;

typedef struct {
    uint8_t addr[ESP_NOW_ETH_ALEN];             // who to send to
    espnow_radio_mode_t radio_mode;             // tracks if we are broadcasting or unicasting

    espnow_data_public_keys_t keys;             // unicast send_peer keys 
    uint64_t counter;
} espnow_data_peer_info_t;

typedef uint8_t espnow_data_shared_key_t[X25519_SHARED_SIZE];
typedef union {
    espnow_data_public_keys_t public;
    espnow_data_private_keys_t private;
    espnow_data_shared_key_t shared;
} espnow_data_cryptography_keys_t;

/*
caches information about the current session between loops. 

- keys: generated public and private keys
- nonce: Hardware RNG nonce generated at start
- send_peer: peer info including keys and mac addr
- espnow_crypto_state: what state of the lightweight cryptographic protocol we are in
    - DISCOVER, AUTH, SESSION_OK
- 
*/
typedef struct {
    espnow_data_cryptography_keys_t keys;       // all related crypto keys
    uint8_t nonce[NONCE_SIZE];                  // generated nonce
    espnow_data_peer_info_t send_peer;          // send_peer related info including keys
    
    espnow_crypto_state_t espnow_crypto_state;  // tracks what state the cryptographic protocl is in
    espnow_data_session_info_t session_info;    // tracks session info
} espnow_communication_params_t;

#endif /* MAIN_H */