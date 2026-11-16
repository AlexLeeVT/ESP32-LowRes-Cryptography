// Author: Krishna Inukonda (benchmarking).
//
// Records (parsed by tools/bench_parse.py):
//   CPU_MHZ,mhz
//   CRYPTO,label,cycles      one operation, repeated RUNS_FAST or RUNS_SLOW times
//   STACK,label,bytes        crypto task stack still free after each group
//   MINHEAP,label,bytes
#include "bench_crypto.h"

#include <stdio.h>
#include <string.h>

#include "esp_cpu.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "psa/crypto.h"
#include "sdkconfig.h"

#include "bench_measure.h"
#include "compact25519.h"
#include "crypto_aead.h"

#define RUNS_FAST   50     // Ascon, HKDF: microseconds each
#define RUNS_SLOW   20     // X25519, Ed25519: hundreds of ms each, very consistent
#define AD_LEN      8      // stands in for a packet header authenticated as AD
#define TASK_STACK  16384

// Payload sizes; 224 + 16-byte tag + header still fits one 250-byte ESP-NOW v1 frame.
static const size_t SIZES[] = { 16, 64, 128, 224 };
#define N_SIZES (sizeof SIZES / sizeof SIZES[0])

// Times one statement n times and prints one CRYPTO line per run. The 1-tick
// delay between runs (outside the timed part) lets the idle task feed the
// task watchdog; without it the watchdog fires and inflates the runs it hits.
#define TIME(label, n, stmt)                                           \
    for (int _r = 0; _r < (n); _r++) {                                 \
        uint32_t _t0 = esp_cpu_get_cycle_count();                      \
        stmt;                                                          \
        uint32_t _dt = esp_cpu_get_cycle_count() - _t0;                \
        printf("CRYPTO,%s,%u\n", (label), (unsigned) _dt);             \
        vTaskDelay(1);                                                 \
    }

static uint8_t s_pt[224], s_ct[224 + 16], s_back[224], s_ad[AD_LEN];

static void bench_ascon(void)
{
    uint8_t key[16], nonce[16];
    unsigned long long clen = 0, mlen;
    char label[32];
    esp_fill_random(key, sizeof key);
    esp_fill_random(nonce, sizeof nonce);
    for (size_t i = 0; i < N_SIZES; i++) {
        size_t n = SIZES[i];
        snprintf(label, sizeof label, "ascon128_enc_%u", (unsigned) n);
        TIME(label, RUNS_FAST, crypto_aead_encrypt(s_ct, &clen, s_pt, n, s_ad, AD_LEN, NULL, nonce, key));
        snprintf(label, sizeof label, "ascon128_dec_%u", (unsigned) n);
        TIME(label, RUNS_FAST, crypto_aead_decrypt(s_back, &mlen, NULL, s_ct, clen, s_ad, AD_LEN, nonce, key));
    }
}

static void bench_x25519(void)
{
    uint8_t seed[32], priv[32], pub[32], peer_priv[32], peer_pub[32], shared[32];
    esp_fill_random(seed, sizeof seed);
    compact_x25519_keygen(peer_priv, peer_pub, seed);
    TIME("x25519_keygen", RUNS_SLOW, (esp_fill_random(seed, sizeof seed), compact_x25519_keygen(priv, pub, seed)));
    TIME("x25519_shared", RUNS_SLOW, compact_x25519_shared(shared, priv, peer_pub));
}

static void bench_ed25519(void)
{
    // 96 bytes = what AUTH would sign: both X25519 ephemerals + both 16-byte nonces
    uint8_t seed[32], priv[64], pub[32], sig[64], transcript[96];
    esp_fill_random(transcript, sizeof transcript);
    TIME("ed25519_keygen", RUNS_SLOW, (esp_fill_random(seed, sizeof seed), compact_ed25519_keygen(priv, pub, seed)));
    TIME("ed25519_sign_96", RUNS_SLOW, compact_ed25519_sign(sig, priv, transcript, sizeof transcript));
    TIME("ed25519_verify_96", RUNS_SLOW, compact_ed25519_verify(sig, pub, transcript, sizeof transcript));
}

static void bench_hkdf(void)
{
    uint8_t secret[32], salt[32], out[32];
    static const uint8_t info[] = "espnow session keys";
    esp_fill_random(secret, sizeof secret);
    esp_fill_random(salt, sizeof salt);

    psa_key_derivation_operation_t op = PSA_KEY_DERIVATION_OPERATION_INIT;
    if (psa_key_derivation_setup(&op, PSA_ALG_HKDF(PSA_ALG_SHA_256)) != PSA_SUCCESS) {
        printf("HKDF_UNAVAILABLE\n");
        return;
    }
    psa_key_derivation_abort(&op);

    TIME("hkdf_sha256_32", RUNS_FAST, ({
        psa_key_derivation_operation_t o = PSA_KEY_DERIVATION_OPERATION_INIT;
        psa_key_derivation_setup(&o, PSA_ALG_HKDF(PSA_ALG_SHA_256));
        psa_key_derivation_input_bytes(&o, PSA_KEY_DERIVATION_INPUT_SALT, salt, sizeof salt);
        psa_key_derivation_input_bytes(&o, PSA_KEY_DERIVATION_INPUT_SECRET, secret, sizeof secret);
        psa_key_derivation_input_bytes(&o, PSA_KEY_DERIVATION_INPUT_INFO, info, sizeof info - 1);
        psa_key_derivation_output_bytes(&o, out, sizeof out);
        psa_key_derivation_abort(&o);
    }));
}

static void crypto_task(void *arg)
{
    (void) arg;
    printf("CPU_MHZ,%d\n", CONFIG_ESP_DEFAULT_CPU_FREQ_MHZ);
    bench_heap("crypto_start");

    esp_fill_random(s_pt, sizeof s_pt);
    esp_fill_random(s_ad, sizeof s_ad);
    if (psa_crypto_init() != PSA_SUCCESS) printf("PSA_INIT_FAIL\n");  // HKDF needs PSA

    bench_ascon();
    bench_stack("crypto_after_ascon");
    bench_x25519();
    bench_stack("crypto_after_x25519");
    bench_ed25519();
    bench_stack("crypto_after_ed25519");
    bench_hkdf();
    bench_stack("crypto_after_hkdf");

    bench_min_heap("crypto_end");
    printf("BENCH_DONE\n");
    vTaskDelete(NULL);
}

void bench_crypto_run(void)
{
    // Pinned so the cycle counter is read on one core; Wi-Fi is off in this mode.
    xTaskCreatePinnedToCore(crypto_task, "crypto", TASK_STACK, NULL, 5, NULL, 0);
}
