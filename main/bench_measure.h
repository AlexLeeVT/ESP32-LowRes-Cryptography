// Author: Krishna Inukonda (benchmarking).
#ifndef BENCH_MEASURE_H
#define BENCH_MEASURE_H

// Benchmark instrumentation shared by baseline 1, baseline 2 and the custom protocol.
// Every build prints identical records so bench_parse.py can compare them:
//   HEAP,label,bytes          free heap now
//   MINHEAP,label,bytes       lowest free heap since boot (catches transient crypto peaks)
//   STACK,label,bytes         stack high-water mark of the calling task (ESP-IDF counts bytes)
//   HANDSHAKE,label,us        one handshake duration
//   RTT,label,seq,us          one round trip; us = -1 means the echo never arrived
//   TPUT,label,count,us       messages counted over a timed window
//
// Timed paths only store timestamps; printing happens afterwards, so printf
// never distorts a measurement.
//
// State lives in bench_measure.c, so start/end calls may sit in different .c files.
// Build with BENCH_RTT_N=0 (see main/CMakeLists.txt) for runs used as absolute RAM
// numbers: the RTT buffers are ~4.3 KB of static RAM, which lowers every free-heap
// reading by that much (differences between checkpoints are unaffected).
//   PDR,label,received,sent   (bench_app) delivery ratio of a throughput run

#include <stdint.h>

void bench_heap(const char *label);
void bench_min_heap(const char *label);
void bench_stack(const char *label);

void bench_handshake_start(void);
void bench_handshake_end(const char *label);

// Ping-pong RTT, timed on the pinging board's clock only (boards are not synchronized).
void bench_rtt_reset(void);
void bench_rtt_send(uint32_t seq); // right before sending ping seq
void bench_rtt_recv(uint32_t seq); // when the echo for seq arrives
void bench_rtt_report(const char *label, uint32_t n);

// Throughput, counted on the receiver.
void bench_tp_start(void);
void bench_tp_count(void); // once per correctly received (and authenticated) message
void bench_tp_end(const char *label);

#endif // BENCH_MEASURE_H
