#!/usr/bin/env python3
# Author: Krishna Inukonda (benchmarking).
"""Turn saved serial logs into one markdown results table.
Usage: python3 bench_parse.py baseline1.log baseline2.log custom.log
The file name (without .log) becomes the System column."""
import statistics as st
import sys
from collections import defaultdict
from pathlib import Path

UNITS = {"HEAP": "bytes", "MINHEAP": "bytes", "STACK": "bytes", "HANDSHAKE": "us", "RTT": "us"}


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(p / 100 * len(xs)))]


def parse(path):
    vals, lost, tput = defaultdict(list), defaultdict(int), defaultdict(list)
    pdr = defaultdict(lambda: [0, 0])  # label -> [received, sent]
    kats, mhz = {}, None
    for line in Path(path).read_text(errors="replace").splitlines():
        f = line.strip().split(",")
        try:
            if f[0] in ("HEAP", "MINHEAP", "STACK", "HANDSHAKE") and len(f) == 3:
                vals[(f[0], f[1])].append(int(f[2]))
            elif f[0] == "RTT" and len(f) == 4:
                us = int(f[3])
                if us < 0:
                    lost[f[1]] += 1
                else:
                    vals[("RTT", f[1])].append(us)
            elif f[0] == "TPUT" and len(f) == 4 and int(f[3]) > 0:
                tput[f[1]].append(int(f[2]) / (int(f[3]) / 1e6))
            elif f[0] == "CRYPTO" and len(f) == 3:
                vals[("CRYPTO", f[1])].append(int(f[2]))
            elif f[0] == "CPU_MHZ" and len(f) == 2:
                mhz = int(f[1])
            elif f[0] == "KAT" and len(f) == 3:
                kats[f[1]] = f[2] if kats.get(f[1], "PASS") == "PASS" else kats[f[1]]
            elif f[0] == "PDR" and len(f) == 4:
                pdr[f[1]][0] += int(f[2])
                pdr[f[1]][1] += int(f[3])
        except ValueError:
            pass  # boot noise or a line cut off mid-print
    return vals, lost, tput, pdr, kats, mhz


def row(name, metric, label, xs, fmt="{:.0f}"):
    print(f"| {name} | {metric} | {label} | {len(xs)} | " +
          " | ".join(fmt.format(v) for v in (st.mean(xs), st.median(xs), pct(xs, 95), max(xs))) + " |")


def main(paths):
    print("| System | Metric | Label | n | mean | median | p95 | max |")
    print("|---|---|---|---|---|---|---|---|")
    for p in paths:
        name = Path(p).stem
        vals, lost, tput, pdr, kats, mhz = parse(p)
        for (kind, label), xs in sorted(vals.items()):
            if kind == "CRYPTO":
                if mhz:  # cycles -> microseconds
                    row(name, "CRYPTO (us)", label, [x / mhz for x in xs], "{:.1f}")
                else:
                    row(name, "CRYPTO (cycles)", label, xs)
            else:
                row(name, f"{kind} ({UNITS[kind]})", label, xs)
        for label, result in sorted(kats.items()):
            print(f"| {name} | KAT | {label} | | {result} | | | |")
        for label, xs in sorted(tput.items()):
            row(name, "TPUT (msgs/s)", label, xs)
        for label in sorted({l for k, l in vals if k == "RTT"} | set(lost)):
            got = len(vals.get(("RTT", label), []))
            total = got + lost[label]
            print(f"| {name} | RTT delivered (%) | {label} | {total} | {100 * got / total:.1f} | | | |")
        for label, (got, sent) in sorted(pdr.items()):
            if sent:
                print(f"| {name} | Delivered (%) | {label} | {sent} | {100 * got / sent:.1f} | | | |")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    main(sys.argv[1:])
