// Author: Krishna Inukonda (benchmarking).
#ifndef BENCH_CRYPTO_H
#define BENCH_CRYPTO_H

// Single-board benchmark of the custom protocol's building blocks: cycle counts
// for Ascon-AEAD128 (per packet), X25519, Ed25519 and HKDF-SHA256 (handshake).
// Needs no Wi-Fi and no second board. Runs when built with -DBENCH_CRYPTO=1.
void bench_crypto_run(void);

#endif
