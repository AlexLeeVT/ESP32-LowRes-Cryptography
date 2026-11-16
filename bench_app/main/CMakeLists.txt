# Author: Krishna Inukonda (benchmarking).
# Reuses the shared instrumentation in ../../main so every build prints the same records.
idf_component_register(SRCS "bench_app.c" "bench_crypto.c"
                            "../../main/bench_measure.c"
                            "../../main/compact25519/compact25519.c"
                            "../../main/ascon/aead.c"
                       PRIV_INCLUDE_DIRS "../../main" "../../main/compact25519" "../../main/ascon"
                       PRIV_REQUIRES esp_wifi esp_netif esp_event esp_timer nvs_flash mbedtls)

# Pick at build time, e.g.  idf.py -C bench_app -B bench_app/build/b2 -DBENCH_SECURITY=1 build
#   BENCH_SECURITY 0 = baseline 1 (no encryption), 1 = baseline 2 (CCMP), 2 = custom protocol
#   BENCH_CRYPTO   1 = single-board crypto benchmark instead of the radio tests
#   BENCH_RTT_N    0 for runs whose absolute RAM numbers you report (drops ~4.3 KB of RTT buffers)
if(NOT DEFINED BENCH_SECURITY)
    set(BENCH_SECURITY 0)
endif()
if(NOT DEFINED BENCH_CRYPTO)
    set(BENCH_CRYPTO 0)
endif()
if(NOT DEFINED BENCH_RTT_N)
    set(BENCH_RTT_N 1000)
endif()
target_compile_definitions(${COMPONENT_LIB} PRIVATE
    BENCH_SECURITY=${BENCH_SECURITY} BENCH_RTT_N=${BENCH_RTT_N} BENCH_CRYPTO=${BENCH_CRYPTO})
