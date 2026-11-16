#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "crypto_main.h"
#include "main/ascon/crypto_aead.h"
#include "main/ascon/api.h"

/*
 * Wire format
 *
 * All multi-byte integers are unsigned big-endian values.  Length is the
 * complete packet length, including VERSION, TYPE, and LENGTH.
 *
 * The caller must provide a crypt_random_fn backed by a CSPRNG.  On ESP-IDF,
 * esp_random() is suitable when the hardware RNG is seeded.
 */

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
    memcpy(out + offset, a->ephemeral_public, ED25519_PUBLIC_KEY_SIZE);
    offset += ED25519_PUBLIC_KEY_SIZE;

    // ID_B
    memcpy(out + offset, b->public_key, ED25519_PUBLIC_KEY_SIZE);
    offset += ED25519_PUBLIC_KEY_SIZE;

    // N_B
    memcpy(out + offset, b->nonce, CRYPT_NONCE_LEN);
    offset += CRYPT_NONCE_LEN;

    // X_B
    memcpy(out + offset, b->ephemeral_public, ED25519_PUBLIC_KEY_SIZE);
    offset += ED25519_PUBLIC_KEY_SIZE;

    return offset; 
}


/*
 * Create the HELLO packet and generate the fresh ephemeral key pair
 * HELLO packet is of form: Version | Type | Length | Ed25519 Public Key | Nonce | Ephemeral X25519 Public Key
*/
int crypt_make_hello_packet(uint8_t packet[CRYPT_HELLO_LEN], const uint8_t private_key[64], crypt_hello_t *hello, crypt_random_fn random_bytes) {

    uint8_t seed[32];

    if (!packet || !private_key || !hello || !random_bytes
    || random_bytes(hello->nonce, CRYPT_NONCE_LEN) != 0 || random_bytes(seed, 32)) return -1;

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

    memset(seed, 0, sizeof seed);
    return 0;
    
}


int crypt_parse_hello(const uint8_t *packet, size_t packet_len, crypt_hello_t *hello) {
    // Validate the HELLO packet
    if (!hello || packet_len != CRYPT_HELLO_LEN || !verify_packet_header(packet, packet_len, CRYPT_TYPE_HELLO, CRYPT_HELLO_LEN)) {
        return -1;
    }

    memcpy(hello->public_key, packet + 4, 32);
    memcpy(hello->nonce, packet + 36, 16);
    memcpy(hello->ephemeral_public, packet + 52, 32);
    memset(hello->ephemeral_private, 0, 32);
    return 0;

}

/*
 * Sign the canonical transcript and create an AUTH packet.
 * AUTH packet is of form: Version | Type | Length | Ed25519 Public Key | Ed25519 Signature over transcript
*/
int crypt_make_auth(uint8_t packet[CRYPT_AUTH_LEN], const crypt_session_t *session, const uint8_t private_key[64]) {
    uint8_t transcript[CRYPT_HEADER_LEN + 2 * (ED25519_PUBLIC_KEY_SIZE + CRYPT_NONCE_LEN + X25519_KEY_SIZE)];
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
    memcpy(packet + 4, session->local.public_key, ED25519_PUBLIC_KEY_SIZE);
    memcpy(packet + 36, signature, 64);
    memset(signature, 0, sizeof signature); /* Clear the temporary signature buffer. */
    return 0;

}

int verify_auth(const uint8_t *packet, size_t packet_len, crypt_session_t *session) {

    uint8_t transcript[CRYPT_HEADER_LEN + 2 * (ED25519_PUBLIC_KEY_SIZE + CRYPT_NONCE_LEN + X25519_KEY_SIZE)];
    size_t transcript_len;
    uint8_t shared_secret[32];

    if (!verify_packet_header(packet, packet_len, CRYPT_TYPE_AUTH, CRYPT_AUTH_LEN) || !session) {
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

    compact_x25519_shared(shared_secret, session->local.ephemeral_private, session->peer.ephemeral_public);

    /* Reject the all-zero result required for invalid X25519 peer inputs. */
    uint8_t nonzero = 0;
    for (size_t i = 0; i < sizeof shared_secret; ++i) {
        nonzero |= shared_secret[i];
    }
    memset(shared_secret, 0, sizeof shared_secret);
    if (!nonzero) {
        return -5;
    }

    return 0;
}

int accept_auth(const uint8_t *packet, size_t packet_len, crypt_session_t *session) {

    uint8_t transcript[CRYPT_HEADER_LEN + 2 * (ED25519_PUBLIC_KEY_SIZE + CRYPT_NONCE_LEN + X25519_KEY_SIZE)];
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
    
    sha256_t hash; 
    sha256_init(&hash);
    sha256_update(&hash, transcript, transcript_len);
    sha256_final(&hash, salt);

    // Use HKDF to derive the session keys from the shared secret and salt
    if (hkdf_sha256(shared_secret, 32, salt, 32, (const uint8_t *)"CS5584 session", 14, material, 32) != 0) {
        return -6;
    }

    bool first_is_local = memcmp(session->local.public_key, session->peer.public_key, ED25519_PUBLIC_KEY_SIZE) < 0;
    session->local_is_a = first_is_local;

    // session ID-ed by the salt, and the outgoing/incoming keys are derived from the HKDF material
    memcpy(session->session_id, salt, 8);
    memcpy(session->outgoing_aead_key, first_is_local ? material : material + 16, CRYPT_KEY_LEN);
    memcpy(session->incoming_aead_key, first_is_local ? material + 16 : material, CRYPT_KEY_LEN);

    session->established = true;
    memset(shared_secret, 0, sizeof shared_secret);
    memset(material, 0, sizeof material);
    return 0;
}

typedef struct {
    uint32_t hash_state[8];
    uint64_t bits;
    uint8_t block[64];
    size_t used;
} sha256_t;

static void sha256_compress(sha256_t *state, const uint8_t block[64]) {
    static const uint32_t k[64] = {
        0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu,
        0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u, 0xd807aa98u, 0x12835b01u,
        0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u,
        0xc19bf174u, 0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
        0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau, 0x983e5152u,
        0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u,
        0x06ca6351u, 0x14292967u, 0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu,
        0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
        0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u,
        0xd6990624u, 0xf40e3585u, 0x106aa070u, 0x19a4c116u, 0x1e376c08u,
        0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu,
        0x682e6ff3u, 0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
        0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
    };

    uint32_t message_schedule[64];

    // make big endian
    for (unsigned i = 0; i < 16; ++i) {
        message_schedule[i] = ((uint32_t)block[4 * i] << 24) |
        ((uint32_t)block[4 * i + 1] << 16) |
        ((uint32_t)block[4 * i + 2] << 8) |
        ((uint32_t)block[4 * i + 3]);
    }

    // Expand the first 16 words into the remaining 48 words of the message schedule array
    for (unsigned i = 16; i < 64; ++i) {
        uint32_t a = rotr(message_schedule[i - 15], 7) ^ rotr(message_schedule[i - 15], 18) ^ (message_schedule[i - 15] >> 3);
        uint32_t c = rotr(message_schedule[i - 2], 17) ^ rotr(message_schedule[i - 2], 19) ^ (message_schedule[i - 2] >> 10);
        message_schedule[i] = message_schedule[i - 16] + a + message_schedule[i - 7] + c;
    }

    uint32_t a = state->hash_state[0],
            b = state->hash_state[1],
            c = state->hash_state[2],
            d = state->hash_state[3],
            e = state->hash_state[4],
            f = state->hash_state[5],
            g = state->hash_state[6],
            h = state->hash_state[7];

    for (unsigned i = 0; i < 64; ++i) {
        uint32_t S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + k[i] + message_schedule[i];
        uint32_t S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t t2 = S0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

}

static void sha256_init(sha256_t *s) {
    static const uint32_t iv[8] = {
        0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
        0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u
    };
    if (!s) return;
    memset(s->block, 0, sizeof s->block);
    s->bits = 0;
    s->used = 0;
}

static void sha256_update(sha256_t *s, const void *data, size_t len) {
    if (!s || (!data && len != 0)) {
        return; 
    }

    const uint8_t *p = (const uint8_t *)data;
    s->bits += (uint64_t)len * 8u; //padding stores length in bits
    while (len) {
        size_t remaining = 64u - s->used; //remaining capacity in the 64-byte block
        if (remaining > len) {
            remaining = len; // Do not consume more input than available
        }
        memcpy(s->block + s->used, p, remaining);
        s->used += remaining;
        p += remaining;
        len -= remaining;
        if (s->used == 64u) { // Exactly one full block is ready
            sha256_compress(s, s->block);
            s->used = 0;
        }
    }
}

/* Append padding, process final block, and emit 32 digest bytes*/
static void sha256_final(sha256_t *s, uint8_t out[32]) {
    size_t n = s->used;
    /* Append the padding: a single '1' bit followed by zeros */
    s->block[n] = 0x80;
    if (++n > 56u) { /* No room for the 8-byte length in this block */
        memset(s->block + n, 0, 64u - n);
        sha256_compress(s, s->block);
        n = 0;
    }

    memset(s->block + n, 0, 56u - n); /* Leave bytes 56..63 for the bit length */
    for (int i = 0; i < 8; ++i) {
        s->block[56 + i] = (uint8_t)(s->bits >> (56 - 8 * i)); /* Big-endian 64-bit length */
    }
    sha256_compress(s, s->block);
    for (unsigned i = 0; i < 8; ++i) {
        for (unsigned j = 0; j < 4; ++j) {
            out[4 * i + j] = (uint8_t)(s->hash_state[i] >> (24 - 8 * j));
        }
    }

}

/*
 * Compute HMAC-SHA-256(key, data) = H((K xor opad) || H((K xor ipad) || data))
 * Paramters:
 * key: pointer to the key used for HMAC
 * key_len: length of the key in bytes
 * data: pointer to the data to be hashed
 * data_len: length of the data in bytes
 * out: pointer to the output buffer where the HMAC result will be stored (32 bytes)
 */
static void hmac_sha256(const uint8_t *key, size_t key_len, const void *data, size_t data_len, uint8_t out[32]) {
    if ((!key && key_len != 0) || (!data && data_len != 0) || !out) {
        return; 
    }
    uint8_t k[64] = {0};
    uint8_t ipad[64], opad[64], inner[32];

    // If the key is longer than 64 bytes, hash it first
    if (key_len > 64u) { 
        sha256_t h;
        sha256_init(&h);
        sha256_update(&h, key, key_len);
        sha256_final(&h, k);
    } else {
        memcpy(k, key, key_len);
    }

    // Build the two 64-byte HMAC pads
    for (unsigned i = 0; i < 64; ++i) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    sha256_t h;
    // Compute inner hash: H((K xor ipad) || data)
    sha256_init(&h);
    sha256_update(&h, ipad, 64);
    sha256_update(&h, data, data_len);
    sha256_final(&h, inner);

    // Compute outer hash: H((K xor opad) || inner_hash)
    sha256_init(&h);
    sha256_update(&h, opad, 64);
    sha256_update(&h, inner, 32);
    sha256_final(&h, out);

}



static uint32_t rotr(uint32_t x, unsigned n) {
    /* A rotate preserves all 32 bits: right-shifted bits wrap left. */
    return (x >> n) | (x << (32u - n));
}