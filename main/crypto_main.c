#include "crypto_main.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "ascon/api.h"
#include "ascon/crypto_aead.h"

#include "mbedtls/hkdf.h"
#include "mbedtls/md.h"

/*
 * Wire format
 *
 * All multi-byte integers are unsigned big-endian values.  Length is the
 * complete packet length, including VERSION, TYPE, and LENGTH.
 *
 * The caller must provide a crypt_random_fn backed by a CSPRNG.  On ESP-IDF,
 * esp_random() is suitable when the hardware RNG is seeded.
 */
static void put16(uint8_t *p, uint16_t x);
static void put64(uint8_t *p, uint64_t x);
static uint16_t get16(const uint8_t *p);
static uint64_t get64(const uint8_t *p);
static int verify_packet_header(const uint8_t *packet, size_t packet_len,
                                uint8_t type, size_t expected_min);
static size_t construct_transcript(const crypt_hello_t *local,
                                   const crypt_hello_t *peer, uint8_t *out);

static int sha256_hash(const uint8_t *data, size_t data_len,
                       uint8_t output[32]);
static int hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                       const uint8_t *salt, size_t salt_len,
                       const uint8_t *info, size_t info_len,
                       uint8_t *out, size_t out_len);

static void put16(uint8_t *p, uint16_t x) {
    p[0] = (uint8_t)(x >> 8); 
    p[1] = (uint8_t)x;        
}

static void put64(uint8_t *p, uint64_t x) {
    for (int i = 7; i >= 0; --i) {
        p[i] = (uint8_t)x; 
        x >>= 8;           
    }
}

static uint16_t get16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]); 
}

static uint64_t get64(const uint8_t *p) {
    uint64_t x = 0;
    for (int i = 0; i < 8; ++i) {
        x = (x << 8) | p[i]; 
    }
    return x;
}

static int verify_packet_header(const uint8_t *packet, size_t packet_len, uint8_t type, size_t expected_min) {
    return packet 
    && packet_len >= expected_min 
    && packet[0] == CRYPT_VERSION 
    && packet[1] == type 
    && get16(packet + 2) == packet_len;
}

/*
 * Construct a transcript of the handshake messages.
 * The transcript is used to derive the session keys.
 */
static size_t construct_transcript(const crypt_hello_t *local, const crypt_hello_t *peer, uint8_t *out) {
    if (!local || !peer || !out) return 0;

    // determine a and b lexicographically so both local and peer get the same order
    const crypt_hello_t *a = memcmp(local->public_key, peer->public_key, ED25519_PUBLIC_KEY_SIZE) < 0 ? local : peer;
    const crypt_hello_t *b = a == local ? peer : local;

    size_t offset = 0;

    // Set protocol ID to start the packet
    memcpy(out + offset, CRYPT_PROTOCOL_ID, CRYPT_PROTOCOL_ID_LEN);
    offset += CRYPT_PROTOCOL_ID_LEN;

    // ID_A
    memcpy(out + offset, a->public_key, ED25519_PUBLIC_KEY_SIZE);
    offset += ED25519_PUBLIC_KEY_SIZE;

    // N_A
    memcpy(out + offset, a->nonce, CRYPT_NONCE_LEN);
    offset += CRYPT_NONCE_LEN;

    // X_A
    memcpy(out + offset, a->ephemeral_public, X25519_KEY_SIZE);
    offset += X25519_KEY_SIZE;

    // ID_B
    memcpy(out + offset, b->public_key, ED25519_PUBLIC_KEY_SIZE);
    offset += ED25519_PUBLIC_KEY_SIZE;

    // N_B
    memcpy(out + offset, b->nonce, CRYPT_NONCE_LEN);
    offset += CRYPT_NONCE_LEN;

    // X_B
    memcpy(out + offset, b->ephemeral_public, X25519_KEY_SIZE);
    offset += X25519_KEY_SIZE;

    return offset; 
}


/*
 * Create the HELLO packet and generate the fresh ephemeral key pair
 * HELLO packet is of form: Version | Type | Length | Ed25519 Public Key | Nonce | Ephemeral X25519 Public Key
*/
int crypt_make_hello_packet(uint8_t packet[CRYPT_HELLO_LEN], const uint8_t private_key[64], crypt_hello_t *hello, crypt_random_fn random_bytes) {

    uint8_t seed[32];

    if (!packet || !private_key || !hello || !random_bytes) {
        return -1;
    }

    if (random_bytes(hello->nonce, CRYPT_NONCE_LEN) != 0) {
        memset(seed, 0, sizeof seed);
        return -1;
    }

    if (random_bytes(seed, sizeof seed) != 0) {
        memset(seed, 0, sizeof seed);
        return -1;
    }

    compact_ed25519_calc_public_key(hello->public_key, private_key);
    compact_x25519_keygen(hello->ephemeral_private, hello->ephemeral_public, seed);
    
    uint8_t offset = 0;

    packet[offset] = CRYPT_VERSION;
    offset++;
    packet[offset] = CRYPT_TYPE_HELLO;
    offset++;

    put16(packet + offset, CRYPT_HELLO_LEN);
    offset += 2;

    memcpy(packet + offset, hello->public_key, ED25519_PUBLIC_KEY_SIZE);
    offset += ED25519_PUBLIC_KEY_SIZE;

    memcpy(packet + offset, hello->nonce, CRYPT_NONCE_LEN);
    offset += CRYPT_NONCE_LEN;

    memcpy(packet + offset, hello->ephemeral_public, X25519_KEY_SIZE);
    offset += X25519_KEY_SIZE;

    memset(seed, 0, sizeof seed);
    return 0;
    
}


int crypt_parse_hello(const uint8_t *packet, size_t packet_len, crypt_hello_t *hello) {
    // Validate the HELLO packet
    if (!hello || packet_len != CRYPT_HELLO_LEN || !verify_packet_header(packet, packet_len, CRYPT_TYPE_HELLO, CRYPT_HELLO_LEN)) {
        return -1;
    }

    memcpy(hello->public_key, packet + CRYPT_HEADER_LEN, ED25519_PUBLIC_KEY_SIZE);
    memcpy(hello->nonce, packet + CRYPT_HEADER_LEN + ED25519_PUBLIC_KEY_SIZE, CRYPT_NONCE_LEN);
    memcpy(hello->ephemeral_public, packet + CRYPT_HEADER_LEN + ED25519_PUBLIC_KEY_SIZE + CRYPT_NONCE_LEN, X25519_KEY_SIZE);
    memset(hello->ephemeral_private, 0, X25519_KEY_SIZE);
    return 0;

}

/*
 * Sign the canonical transcript and create an AUTH packet.
 * AUTH packet is of form: Version | Type | Length | Ed25519 Public Key | Ed25519 Signature over transcript
*/
int crypt_make_auth(uint8_t packet[CRYPT_AUTH_LEN], const crypt_session_t *session, const uint8_t private_key[64]) {
    uint8_t transcript[CRYPT_PROTOCOL_ID_LEN + 2 * (ED25519_PUBLIC_KEY_SIZE + CRYPT_NONCE_LEN + X25519_KEY_SIZE)];
    size_t transcript_len;
    uint8_t signature[64];

    if (!packet || !session || !private_key) {
        return -1;
    }

    transcript_len = construct_transcript(&session->local, &session->peer, transcript);

    if (transcript_len == 0) {
        return -1;
    }

    compact_ed25519_sign(signature, private_key, transcript, transcript_len);
    packet[0] = CRYPT_VERSION;
    packet[1] = CRYPT_TYPE_AUTH;
    put16(packet + 2, CRYPT_AUTH_LEN);
    memcpy(packet + CRYPT_HEADER_LEN, session->local.public_key, ED25519_PUBLIC_KEY_SIZE);
    memcpy(packet + CRYPT_HEADER_LEN + ED25519_PUBLIC_KEY_SIZE, signature, 64);
    memset(signature, 0, sizeof signature); /* Clear the temporary signature buffer. */
    return 0;

}

int verify_auth(const uint8_t *packet, size_t packet_len, crypt_session_t *session) {

    uint8_t transcript[CRYPT_PROTOCOL_ID_LEN + 2 * (ED25519_PUBLIC_KEY_SIZE + CRYPT_NONCE_LEN + X25519_KEY_SIZE)];
    size_t transcript_len;

    if (!session || packet_len != CRYPT_AUTH_LEN ||
        !verify_packet_header(packet, packet_len,
                              CRYPT_TYPE_AUTH, CRYPT_AUTH_LEN)) {
        return -1;
    }

    const uint8_t *peer_id = session->peer.public_key;

    if (memcmp(packet + 4, peer_id, ED25519_PUBLIC_KEY_SIZE) != 0) {
        return -2; /* AUTH must identify the HELLO peer. */
    }

    transcript_len = construct_transcript(&session->local, &session->peer, transcript);
    if (transcript_len == 0) {
        return -3; /* Check that transcript is not empty*/
    }

    if (!compact_ed25519_verify_length(packet + 36, 64, peer_id, transcript, transcript_len)) {
        return -4; /* Check signature and length*/
    }

    return 0;
}

int accept_auth(const uint8_t *packet, size_t packet_len, crypt_session_t *session) {

    uint8_t transcript[CRYPT_PROTOCOL_ID_LEN + 2 * (ED25519_PUBLIC_KEY_SIZE + CRYPT_NONCE_LEN + X25519_KEY_SIZE)];
    size_t transcript_len;
    int verification_result;
    uint8_t shared_secret[32];
    uint8_t salt[32];
    uint8_t material[32];


    verification_result = verify_auth(packet, packet_len, session);
    if (verification_result != 0) {
        return verification_result;
    }

    transcript_len = construct_transcript(&session->local, &session->peer, transcript);
    if (transcript_len == 0) {
        return -3;
    }

    compact_x25519_shared(shared_secret, session->local.ephemeral_private, session->peer.ephemeral_public);

    /* Reject the all-zero result required for invalid X25519 peer inputs. */
    uint8_t nonzero = 0;
    for (size_t i = 0; i < sizeof shared_secret; ++i) {
        nonzero |= shared_secret[i];
    }
    if (!nonzero) {
        memset(shared_secret, 0, sizeof shared_secret);
        return -4;
    }

    if (sha256_hash(transcript, transcript_len, salt) != 0) {
        memset(shared_secret, 0, sizeof shared_secret);
        memset(salt, 0, sizeof salt);
        memset(material, 0, sizeof material);
        return -6;
    }

    // Use HKDF to derive the session keys from the shared secret and salt
    if (hkdf_sha256(
            shared_secret,
            32,
            salt,
            32,
            (const uint8_t*)"CS5584 session",
            14,
            material,
            32) != 0) {
        memset(shared_secret, 0, sizeof shared_secret);
        memset(salt, 0, sizeof salt);
        memset(material, 0, sizeof material);
        return -6;
    }

    bool first_is_local = memcmp(session->local.public_key, session->peer.public_key, ED25519_PUBLIC_KEY_SIZE) < 0;
    session->local_is_a = first_is_local;

    // session ID-ed by the salt, and the outgoing/incoming keys are derived from the HKDF material
    memcpy(session->session_id, salt, 8);
    memcpy(session->outgoing_aead_key, first_is_local ? material : material + 16, CRYPT_KEY_LEN);
    memcpy(session->incoming_aead_key, first_is_local ? material + 16 : material, CRYPT_KEY_LEN);

    session->outgoing_counter_initialized = false;
    session->incoming_counter_initialized = false;
    session->last_outgoing_counter = 0;
    session->last_incoming_counter = 0;

    session->established = true;
    memset(shared_secret, 0, sizeof shared_secret);
    memset(material, 0, sizeof material);
    memset(salt, 0, sizeof salt);
    return 0;
}

static int sha256_hash(
    const uint8_t* data,
    size_t data_len,
    uint8_t output[32]) {
    if ((!data && data_len != 0) || !output) {
        return -1;
    }

    const mbedtls_md_info_t* md =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (md == NULL) {
        return -2;
    }

    return mbedtls_md(
               md,
               data,
               data_len,
               output) == 0
               ? 0
               : -2;
}

/**
 * @brief Derives a key of length out_len from the input key material (ikm) using HKDF with SHA-256.
 * 
 * @param ikm input key material
 * @param ikm_len length of input key material
 * @param salt salt value
 * @param salt_len length of salt
 * @param info context information
 * @param info_len length of context information
 * @param out output buffer
 * @param out_len length of output buffer
 * @return int status of the operation, 0 for success, -1 for failure
 */
static int hkdf_sha256(
    const uint8_t* ikm,
    size_t ikm_len,
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* info,
    size_t info_len,
    uint8_t* out,
    size_t out_len) {
    if ((!ikm && ikm_len != 0) ||
        (!salt && salt_len != 0) ||
        (!info && info_len != 0) ||
        (!out && out_len != 0)) {
        return -1;
    }

    if (out_len > 255u * 32u) {
        return -1;
    }

    const mbedtls_md_info_t* md =
        mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

    if (md == NULL) {
        return -2;
    }

    int ret = mbedtls_hkdf(
        md,
        salt,
        salt_len,
        ikm,
        ikm_len,
        info,
        info_len,
        out,
        out_len);

    return ret == 0 ? 0 : -2;
}


/**
 * @brief Encrypts the given plaintext using the provided session and counter.
 * 
 * @param session The cryptographic session to use for encryption.
 * @param counter The counter to use for encryption.
 * @param plaintext The plaintext to encrypt.
 * @param plaintext_len The length of the plaintext in bytes.
 * @param packet The output buffer where the encrypted packet will be stored.
 * @param packet_capacity The capacity of the output buffer in bytes.
 * @param packet_len The length of the encrypted packet in bytes.
 * @return int 0 on success, negative for failure.
 */
int crypt_data_encrypt(crypt_session_t *session, uint64_t counter, const uint8_t *plaintext, size_t plaintext_len, uint8_t *packet, size_t packet_capacity, size_t *packet_len) {
    unsigned long long ciphertext_len = 0;
    uint8_t nonce[CRYPT_NONCE_LEN];
    size_t total;

    if (plaintext_len > UINT16_MAX - CRYPT_DATA_FIXED_LEN - CRYPT_TAG_LEN) {
        return -1;
    }

    total = CRYPT_DATA_FIXED_LEN + plaintext_len + CRYPT_TAG_LEN;
    if (!session || !session->established || (!plaintext && plaintext_len) ||
        !packet || !packet_len) {
        return -1; // Invalid parameters
    }

    *packet_len = 0;

    if (packet_capacity < total) {
        return -2; // Insufficient packet capacity
    }

    if (session->outgoing_counter_initialized &&
        counter <= session->last_outgoing_counter) {
        return -3; // Counter must be strictly increasing
    }

    packet[0] = CRYPT_VERSION;
    packet[1] = CRYPT_TYPE_DATA;
    put16(packet + 2, (uint16_t)total);

    memcpy(packet + 4, session->session_id, 8); // Copy session ID to packet
    put64(packet + 12, counter); // Copy counter to packet
    memcpy(nonce, packet + 4, CRYPT_NONCE_LEN);

    // Encrypt the plaintext
    if (crypto_aead_encrypt(packet + CRYPT_DATA_FIXED_LEN, &ciphertext_len,
                            plaintext, plaintext_len, packet,
                            CRYPT_DATA_FIXED_LEN, NULL, nonce,
                            session->outgoing_aead_key) != 0 ||
        ciphertext_len != plaintext_len + CRYPT_TAG_LEN) {
        return -4; // Encryption failed
    }
    
    session->last_outgoing_counter = counter;
    session->outgoing_counter_initialized = true;
    *packet_len = total; // Set the output packet length
    return 0; // Success
}

/**
 * @brief Decrypts the given packet using the provided session and expected counter.
 * 
 * @param session The cryptographic session to use for decryption.
 * @param packet The packet to decrypt.
 * @param packet_len The length of the packet in bytes.
 * @param expected_counter The expected counter value.
 * @param plaintext The output buffer where the decrypted plaintext will be stored.
 * @param plaintext_capacity The capacity of the output buffer in bytes.
 * @param plaintext_len The length of the decrypted plaintext in bytes.
 * @return int 0 on success, negative for failure.
 */
int crypt_data_decrypt(crypt_session_t *session, const uint8_t *packet,
                       size_t packet_len, uint64_t expected_counter,
                       uint8_t *plaintext, size_t plaintext_capacity,
                       size_t *plaintext_len) {
    uint8_t nonce[CRYPT_NONCE_LEN];
    unsigned long long decrypted_len = 0;
    uint64_t counter;

    if (!session || !session->established || !packet ||
        !plaintext_len || !plaintext) {
        return -1;
    }

    *plaintext_len = 0;
    if (!verify_packet_header(packet, packet_len, CRYPT_TYPE_DATA,
                              CRYPT_DATA_FIXED_LEN + CRYPT_TAG_LEN)) {
        return -2; // Invalid packet header
    }

    size_t ciphertext_len = packet_len - CRYPT_DATA_FIXED_LEN;
    size_t expected_plaintext_len = ciphertext_len - CRYPT_TAG_LEN;

    if (memcmp(packet + 4, session->session_id, 8) != 0) {
        return -3; // Session ID mismatch
    }

    counter = get64(packet + 12);
    if (counter != expected_counter ||
        (session->incoming_counter_initialized &&
         counter <= session->last_incoming_counter)) {
        return -4; // Counter must be strictly increasing
    }

    if (plaintext_capacity < expected_plaintext_len) {
        return -6; // Insufficient plaintext buffer capacity
    }

    memcpy(nonce, packet + 4, CRYPT_NONCE_LEN);
    if (crypto_aead_decrypt(plaintext, &decrypted_len, NULL,
                            packet + CRYPT_DATA_FIXED_LEN, ciphertext_len,
                            packet, CRYPT_DATA_FIXED_LEN, nonce,
                            session->incoming_aead_key) != 0 ||
        decrypted_len != ciphertext_len - CRYPT_TAG_LEN) {
        return -7; // Decryption failed
    }

    *plaintext_len = (size_t)decrypted_len;
    session->last_incoming_counter = counter;
    session->incoming_counter_initialized = true;
    return 0; // Success
}
