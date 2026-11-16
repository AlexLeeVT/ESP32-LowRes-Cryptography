# Two-board ESP-NOW benchmark

Author: Krishna Inukonda (benchmarking).

Separate ESP-IDF project; it does not touch `main/`. Flash the **same build** to
both boards. They find each other by broadcast; the lower MAC becomes the
initiator and runs the tests, the other is the responder.

## Build, flash, monitor

From the repo root, in a terminal where the ESP-IDF environment is set (the same
one `tools/*.py` use). Use one build folder per mode so they never mix:

```sh
IDF="$IDF_PYTHON_ENV_PATH/bin/python $IDF_PATH/tools/idf.py"

# baseline 1 (no encryption)
$IDF -C bench_app -B bench_app/build/b1 -DBENCH_SECURITY=0 build
# baseline 2 (ESP-NOW CCMP)
$IDF -C bench_app -B bench_app/build/b2 -DBENCH_SECURITY=1 build
# absolute RAM numbers: add -DBENCH_RTT_N=0 and use its own folder, e.g. build/b1ram

# flash both boards (python tools/list_ports.py shows the ports), then monitor each
$IDF -C bench_app -B bench_app/build/b1 -p <PORT_A> flash
$IDF -C bench_app -B bench_app/build/b1 -p <PORT_B> flash
$IDF -C bench_app -B bench_app/build/b1 -p <PORT_A> monitor   # Ctrl+] to exit
```

Monitor the initiator until `BENCH_DONE` (about 1-2 minutes). Save both boards'
output, e.g. by copying from the terminal, into one file per mode
(`baseline1.log`, `baseline2.log`), then:

```sh
python3 tools/bench_parse.py baseline1.log baseline2.log
```

## What each board prints

- Both: `ROLE`, `HEAP` at pre_wifi_init / post_wifi_init / post_espnow_init / peer_added
- Initiator: `HANDSHAKE,setup` x50 (add peer until first probe echoed), `RTT` x1000 at
  32 and 250-byte frames, `MINHEAP`, `STACK`
- Responder: `TPUT` (msgs/s over 5 s) and `PDR` (received vs sent) per frame size

## Single-board crypto benchmark (no second board needed)

```sh
$IDF -C bench_app -B bench_app/build/crypto -DBENCH_CRYPTO=1 build
$IDF -C bench_app -B bench_app/build/crypto -p <PORT> flash monitor
```

Times 100 runs each of the custom protocol's building blocks:

- Ascon-AEAD128 encrypt and decrypt at 16/64/128/224-byte payloads (per-packet cost)
- X25519 keygen and shared secret, Ed25519 keygen, sign and verify of a 96-byte
  transcript, and HKDF-SHA256 (handshake compute cost)
- Free stack after each group (the task has 16 KB), which tells you how much
  stack the protocol task needs

Correctness of Ascon, X25519 and Ed25519 is covered by Yvvy's known-answer tests
in `main/ascon` and `main/compact25519`.
Save the output as `crypto.log` and run `python3 tools/bench_parse.py crypto.log`.

## Custom protocol

`BENCH_SECURITY=2` stops the build on purpose until the three `PROTO` points in
`main/bench_app.c` call the protocol's handshake, seal and open functions.
