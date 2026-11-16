// Author: Krishna Inukonda (benchmarking).
// #include "bench_measure.h"

// #include <stdio.h>
// #include <string.h>
// #include "esp_timer.h"
// #include "esp_heap_caps.h"
// #include "freertos/FreeRTOS.h"
// #include "freertos/task.h"

// #ifndef BENCH_RTT_N
// #define BENCH_RTT_N 1000
// #endif

// void bench_heap(const char *label)
// {
//     printf("HEAP,%s,%u\n", label, (unsigned)heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
// }

// void bench_min_heap(const char *label)
// {
//     printf("MINHEAP,%s,%u\n", label, (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT));
// }

// void bench_stack(const char *label)
// {
//     printf("STACK,%s,%u\n", label, (unsigned)uxTaskGetStackHighWaterMark(NULL));
// }

// static int64_t hs_t0;

// void bench_handshake_start(void)
// {
//     hs_t0 = esp_timer_get_time();
// }

// void bench_handshake_end(const char *label)
// {
//     printf("HANDSHAKE,%s,%lld\n", label, (long long)(esp_timer_get_time() - hs_t0));
// }

// #if BENCH_RTT_N > 0
// static uint32_t rtt_us[BENCH_RTT_N]; // send time, then RTT once echoed
// static uint8_t rtt_sent[(BENCH_RTT_N + 7) / 8];
// static uint8_t rtt_done[(BENCH_RTT_N + 7) / 8];

// #define RTT_BIT(a, i) ((a)[(i) / 8] & (1u << ((i) % 8)))
// #define RTT_SET(a, i) ((a)[(i) / 8] |= (uint8_t)(1u << ((i) % 8)))

// void bench_rtt_reset(void)
// {
//     memset(rtt_sent, 0, sizeof rtt_sent);
//     memset(rtt_done, 0, sizeof rtt_done);
// }

// void bench_rtt_send(uint32_t seq)
// {
//     if (seq >= BENCH_RTT_N)
//         return;
//     rtt_us[seq] = (uint32_t)esp_timer_get_time();
//     RTT_SET(rtt_sent, seq);
// }

// void bench_rtt_recv(uint32_t seq)
// {
//     // ignore echoes for pings never sent and duplicate echoes
//     if (seq >= BENCH_RTT_N || !RTT_BIT(rtt_sent, seq) || RTT_BIT(rtt_done, seq))
//         return;
//     rtt_us[seq] = (uint32_t)esp_timer_get_time() - rtt_us[seq]; // wraps correctly
//     RTT_SET(rtt_done, seq);
// }

// void bench_rtt_report(const char *label, uint32_t n)
// {
//     for (uint32_t i = 0; i < n && i < BENCH_RTT_N; i++)
//     {
//         if (RTT_BIT(rtt_done, i))
//             printf("RTT,%s,%u,%u\n", label, (unsigned)i, (unsigned)rtt_us[i]);
//         else
//             printf("RTT,%s,%u,-1\n", label, (unsigned)i);
//     }
// }
// #else
// void bench_rtt_reset(void) {}
// void bench_rtt_send(uint32_t seq) { (void)seq; }
// void bench_rtt_recv(uint32_t seq) { (void)seq; }
// void bench_rtt_report(const char *label, uint32_t n)
// {
//     (void)label;
//     (void)n;
// }
// #endif

// static int64_t tp_t0;
// static volatile uint32_t tp_count; // bumped from the receive path, read by the reporter

// void bench_tp_start(void)
// {
//     tp_count = 0;
//     tp_t0 = esp_timer_get_time();
// }

// void bench_tp_count(void)
// {
//     tp_count++;
// }

// void bench_tp_end(const char *label)
// {
//     printf("TPUT,%s,%u,%lld\n", label, (unsigned)tp_count, (long long)(esp_timer_get_time() - tp_t0));
// }
// Author: Krishna Inukonda (benchmarking).
#include "bench_measure.h"

#include <stdio.h>
#include <string.h>
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#ifndef BENCH_RTT_N
#define BENCH_RTT_N 1000
#endif

void bench_heap(const char *label)
{
    printf("HEAP,%s,%u\n", label, (unsigned)heap_caps_get_free_size(MALLOC_CAP_DEFAULT));
}

void bench_min_heap(const char *label)
{
    printf("MINHEAP,%s,%u\n", label, (unsigned)heap_caps_get_minimum_free_size(MALLOC_CAP_DEFAULT));
}

void bench_stack(const char *label)
{
    printf("STACK,%s,%u\n", label, (unsigned)uxTaskGetStackHighWaterMark(NULL));
}

static int64_t hs_t0;

void bench_handshake_start(void)
{
    hs_t0 = esp_timer_get_time();
}

void bench_handshake_end(const char *label)
{
    printf("HANDSHAKE,%s,%lld\n", label, (long long)(esp_timer_get_time() - hs_t0));
}

#if BENCH_RTT_N > 0
static uint32_t rtt_us[BENCH_RTT_N]; // send time, then RTT once echoed
static uint8_t rtt_sent[(BENCH_RTT_N + 7) / 8];
static uint8_t rtt_done[(BENCH_RTT_N + 7) / 8];

#define RTT_BIT(a, i) ((a)[(i) / 8] & (1u << ((i) % 8)))
#define RTT_SET(a, i) ((a)[(i) / 8] |= (uint8_t)(1u << ((i) % 8)))

void bench_rtt_reset(void)
{
    memset(rtt_sent, 0, sizeof rtt_sent);
    memset(rtt_done, 0, sizeof rtt_done);
}

void bench_rtt_send(uint32_t seq)
{
    if (seq >= BENCH_RTT_N)
        return;
    rtt_us[seq] = (uint32_t)esp_timer_get_time();
    RTT_SET(rtt_sent, seq);
}

void bench_rtt_recv(uint32_t seq)
{
    // ignore echoes for pings never sent and duplicate echoes
    if (seq >= BENCH_RTT_N || !RTT_BIT(rtt_sent, seq) || RTT_BIT(rtt_done, seq))
        return;
    rtt_us[seq] = (uint32_t)esp_timer_get_time() - rtt_us[seq]; // wraps correctly
    RTT_SET(rtt_done, seq);
}

void bench_rtt_report(const char *label, uint32_t n)
{
    for (uint32_t i = 0; i < n && i < BENCH_RTT_N; i++)
    {
        if (RTT_BIT(rtt_done, i))
            printf("RTT,%s,%u,%u\n", label, (unsigned)i, (unsigned)rtt_us[i]);
        else
            printf("RTT,%s,%u,-1\n", label, (unsigned)i);
    }
}
#else
void bench_rtt_reset(void) {}
void bench_rtt_send(uint32_t seq) { (void)seq; }
void bench_rtt_recv(uint32_t seq) { (void)seq; }
void bench_rtt_report(const char *label, uint32_t n)
{
    (void)label;
    (void)n;
}
#endif

static int64_t tp_t0;
static volatile uint32_t tp_count; // bumped from the receive path, read by the reporter

void bench_tp_start(void)
{
    tp_count = 0;
    tp_t0 = esp_timer_get_time();
}

void bench_tp_count(void)
{
    tp_count++;
}

void bench_tp_end(const char *label)
{
    printf("TPUT,%s,%u,%lld\n", label, (unsigned)tp_count, (long long)(esp_timer_get_time() - tp_t0));
}
