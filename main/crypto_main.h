#ifndef CRYPTO_MAIN_H
#define CRYPTO_MAIN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "compact25519/compact25519.h"

#define CRYPT_VERSION 1u
#define CRYPT_PROTOCOL_ID "CS5584-ESP32-v1"
#define CRYPT_PROTOCOL_ID_LEN (sizeof(CRYPT_PROTOCOL_ID) - 1u)

#define CRYPT_TYPE_HELLO 1u
#define CRYPT_TYPE_AUTH  2u
#define CRYPT_TYPE_DATA  3u

#define CRYPT_HEADER_LEN 4u
#define CRYPT_HELLO_LEN  84u
#define CRYPT_AUTH_LEN   100u
#define CRYPT_DATA_FIXED_LEN 20u
#define CRYPT_TAG_LEN 16u
#define CRYPT_KEY_LEN 16u
#define CRYPT_NONCE_LEN 16u
#define CRYPT_SESSION_ID_LEN 8u

typedef int (*crypt_random_fn)(uint8_t *out, size_t length);

typedef struct {
    uint8_t public_key[ED25519_PUBLIC_KEY_SIZE];
    uint8_t nonce[CRYPT_NONCE_LEN];
    uint8_t ephemeral_public[X25519_KEY_SIZE];
    uint8_t ephemeral_private[X25519_KEY_SIZE];
} crypt_hello_t;

typedef struct {
    crypt_hello_t local;
    crypt_hello_t peer;
    uint8_t session_id[CRYPT_SESSION_ID_LEN];
    uint8_t outgoing_aead_key[CRYPT_KEY_LEN];
    uint8_t incoming_aead_key[CRYPT_KEY_LEN];
    bool local_is_a;
    bool established;
    bool outgoing_counter_initialized;
    bool incoming_counter_initialized;
    uint64_t last_outgoing_counter;
    uint64_t last_incoming_counter;
} crypt_session_t;

#ifdef __cplusplus
extern "C" {
#endif

int crypt_make_hello_packet(
    uint8_t packet[CRYPT_HELLO_LEN],
    const uint8_t private_key[ED25519_PRIVATE_KEY_SIZE],
    crypt_hello_t *hello,
    crypt_random_fn random_bytes);

int crypt_parse_hello(
    const uint8_t *packet,
    size_t packet_len,
    crypt_hello_t *hello);

int crypt_make_auth(
    uint8_t packet[CRYPT_AUTH_LEN],
    const crypt_session_t *session,
    const uint8_t private_key[ED25519_PRIVATE_KEY_SIZE]);

int verify_auth(
    const uint8_t *packet,
    size_t packet_len,
    crypt_session_t *session);

int accept_auth(
    const uint8_t *packet,
    size_t packet_len,
    crypt_session_t *session);

int crypt_data_encrypt(
    crypt_session_t *session,
    uint64_t counter,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *packet,
    size_t packet_capacity,
    size_t *packet_len);

int crypt_data_decrypt(
    crypt_session_t *session,
    const uint8_t *packet,
    size_t packet_len,
    uint64_t expected_counter,
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_len);

#ifdef __cplusplus
}
#endif

#endif /* CRYPTO_MAIN_H */
