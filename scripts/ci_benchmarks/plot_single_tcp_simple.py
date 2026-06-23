#!/usr/bin/env python3
"""Plot a SIMPLIFIED single-TCP aggregation figure for the README.

Unlike plot_single_tcp.py (the full 6-variant report figure), this renders just
three series — direct-single, mqproxy-single, mqproxy-tcp — so the README graphic
shows the core story (one TCP stream aggregates across two paths) without the
mqvpn comparison clutter.

Usage: plot_single_tcp_simple.py <csv> <out-png> [profile]
  profile defaults to "symmetric" (matches the README's 1.8x-1.9x prose).
"""
import csv
import math
import statistics
import sys
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Only the mqproxy story + the no-tunnel baseline. Same hues as the full figure.
VARIANTS = ["direct", "mqproxy-single", "mqproxy-tcp"]
COLORS = {
    "direct":         "#9e9e9e",   # neutral single-path baseline (no tunnel)
    "mqproxy-single": "#a9cfe5",   # mqproxy, 1 path (muted)
    "mqproxy-tcp":    "#1f77b4",   # mqproxy, 2-path aggregating
}
HATCH = {"direct": "///", "mqproxy-single": "///"}
LABEL = {"direct": "direct-single", "mqproxy-single": "mqproxy-single",
         "mqproxy-tcp": "mqproxy-tcp"}
TITLE_SUB = {
    "symmetric":  "symmetric 2-path: 2x100 Mbit / 25 ms",
    "asymmetric": "asymmetric 2-path: 300 Mbit-10 ms + 80 Mbit-30 ms",
}


def load(csv_path):
    rows = defaultdict(list)
    with open(csv_path) as f:
        for r in csv.DictReader(f):
            try:
                m = float(r["goodput_mbps"])
                if math.isnan(m):
                    continue
                s = int(r["streams"])
            except (ValueError, TypeError):
                continue
            rows[(r["variant"], r["profile"], s)].append(m)
    return rows


def main():
    if len(sys.argv) not in (3, 4):
        print("usage: plot_single_tcp_simple.py <csv> <out-png> [profile]",
              file=sys.stderr)
        sys.exit(1)
    csv_path, out = sys.argv[1], sys.argv[2]
    profile = sys.argv[3] if len(sys.argv) == 4 else "symmetric"

    rows = load(csv_path)
    streams = sorted({k[2] for k in rows if k[1] == profile})
    if not streams:
        print(f"no rows for profile={profile}", file=sys.stderr)
        sys.exit(1)
    n_reps = max((len(v) for v in rows.values()), default=0)

    fig, ax = plt.subplots(figsize=(8, 4.5), dpi=150)
    n = len(VARIANTS)
    w = 0.8 / n
    for i, var in enumerate(VARIANTS):
        meds, lo, hi = [], [], []
        for s in streams:
            vals = rows.get((var, profile, s)) or [0.0]
            m = statistics.median(vals)
            meds.append(m)
            lo.append(m - min(vals))
            hi.append(max(vals) - m)
        x = [j + (i - n / 2 + 0.5) * w for j in range(len(streams))]
        hatch = HATCH.get(var)
        bars = ax.bar(x, meds, w, color=COLORS[var], label=LABEL[var],
                      yerr=[lo, hi], capsize=3, ecolor="#333", hatch=hatch,
                      edgecolor=("#5a5a5a" if hatch else "none"),
                      linewidth=(0.6 if hatch else 0))
        # Value label above each bar (clears the min/max whisker via padding).
        ax.bar_label(bars, fmt="%.0f", padding=3, fontsize=7, color="#222")

    ax.set_xticks(range(len(streams)))
    ax.set_xticklabels([f"-P {s}" for s in streams])
    ax.set_xlabel("iperf3 parallel TCP streams")
    ax.set_ylabel("aggregate goodput (Mbps)")
    ax.set_title(
        f"TCP aggregation — {TITLE_SUB.get(profile, profile)}\n"
        f"(bars = median of {n_reps} reps; hatched = single-path baselines)"
    )
    ax.legend(loc="upper left", fontsize=7.5, framealpha=0.9)
    ax.set_ylim(top=ax.get_ylim()[1] * 1.18)
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    fig.tight_layout()
    fig.savefig(out)
    print(f"wrote {out}", file=sys.stderr)


if __name__ == "__main__":
    main()
