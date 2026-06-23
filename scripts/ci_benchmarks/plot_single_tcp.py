#!/usr/bin/env python3
"""Plot single-TCP aggregation bench CSV → 2 grouped-bar PNGs.

Usage: plot_single_tcp.py <csv> <out-dir>
"""
import csv
import datetime as dt
import math
import re
import statistics
import sys
from collections import defaultdict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# Order: baselines (direct + per-tunnel single-path) on the LEFT, then the
# aggregating multipath variants on the RIGHT. Hue groups the family
# (gray=direct, warm=mqvpn, blue=mqproxy); the single-path baselines use a
# muted shade of their family colour + a hatch so they read as baselines.
COLORS = {
    "direct":         "#9e9e9e",   # neutral single-path baseline (no tunnel)
    "mqvpn-single":   "#f3b9a0",   # mqvpn family, muted (1 path)
    "mqproxy-single": "#a9cfe5",   # mqproxy family, muted (1 path)
    "mqvpn-minrtt":   "#d62728",   # mqvpn, 2-path, minrtt
    "mqvpn-wlb":      "#ff7f0e",   # mqvpn, 2-path, wlb
    "mqproxy-tcp":    "#1f77b4",   # mqproxy, 2-path
}
HATCH = {"direct": "///", "mqvpn-single": "///", "mqproxy-single": "///"}
# Display labels (CSV keeps the raw "direct" variant name). Naming it
# "direct-single" unifies the three single-path baselines visually.
LABEL = {"direct": "direct-single"}
VARIANT_PREF_ORDER = [
    "direct", "mqvpn-single", "mqproxy-single",   # baselines (left)
    "mqvpn-minrtt", "mqvpn-wlb", "mqproxy-tcp",    # aggregating (right)
]
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


def plot(rows, profile, out, variants, n_reps):
    streams = sorted({k[2] for k in rows if k[1] == profile})
    if not streams:
        print(f"no rows for profile={profile}", file=sys.stderr)
        return
    fig, ax = plt.subplots(figsize=(9, 5.5), dpi=150)
    n = len(variants)
    w = 0.8 / n
    for i, var in enumerate(variants):
        meds, lo, hi = [], [], []
        for s in streams:
            vals = rows.get((var, profile, s)) or [0.0]
            m = statistics.median(vals)
            meds.append(m)
            lo.append(m - min(vals))
            hi.append(max(vals) - m)
        x = [j + (i - n / 2 + 0.5) * w for j in range(len(streams))]
        hatch = HATCH.get(var)
        ax.bar(x, meds, w, color=COLORS.get(var, "#666"),
               label=LABEL.get(var, var), yerr=[lo, hi], capsize=3,
               # Always render the cap (a top tick) even when spread is 0, so
               # deterministic baselines (e.g. direct, ~0 variance) don't look
               # "missing" next to bars that have whiskers. Zero stem = zero
               # spread, honestly shown. Keep the default (thicker) line weight.
               ecolor="#333",
               hatch=hatch,
               edgecolor=("#5a5a5a" if hatch else "none"),
               linewidth=(0.6 if hatch else 0))

    # Reference line at the single-path (direct) level so the aggregation
    # headroom above one path is obvious at a glance.
    direct_vals = [v for s in streams for v in (rows.get(("direct", profile, s)) or [])]
    if direct_vals:
        base = statistics.median(direct_vals)
        ax.axhline(base, color="#444", linestyle="--", linewidth=1, alpha=0.7)
        ax.text(len(streams) - 0.5, base, f" 1-path ~{base:.0f}",
                va="bottom", ha="right", fontsize=8, color="#444")

    ax.set_xticks(range(len(streams)))
    ax.set_xticklabels([f"-P {s}" for s in streams])
    ax.set_xlabel("iperf3 parallel TCP streams")
    ax.set_ylabel("aggregate goodput (Mbps)")
    ax.set_title(
        f"TCP aggregation — {TITLE_SUB.get(profile, profile)}\n"
        f"(bars = median; error bars = min/max spread of {n_reps} reps; "
        f"hatched = single-path baselines, path A only)"
    )
    ax.legend(loc="upper left", ncol=2, fontsize=8, framealpha=0.9)
    ax.set_ylim(top=ax.get_ylim()[1] * 1.12)  # headroom for the 2-col legend
    ax.grid(axis="y", linestyle=":", alpha=0.5)
    fig.tight_layout()
    fig.savefig(out)
    print(f"wrote {out}", file=sys.stderr)


def date_prefix_from_csv(csv_path):
    # csv name: single_tcp_aggregation_<epoch>.csv  → YYYY-MM-DD
    m = re.search(r"_(\d{9,11})\.csv$", str(csv_path))
    if m:
        try:
            return dt.datetime.fromtimestamp(int(m.group(1))).strftime("%Y-%m-%d")
        except (ValueError, OSError):
            pass
    return dt.date.today().strftime("%Y-%m-%d")


def main():
    if len(sys.argv) != 3:
        print("usage: plot_single_tcp.py <csv> <out-dir>", file=sys.stderr)
        sys.exit(1)
    csv_path, out_dir = sys.argv[1], Path(sys.argv[2])
    out_dir.mkdir(parents=True, exist_ok=True)
    rows = load(csv_path)
    present = {k[0] for k in rows}
    variants = [v for v in VARIANT_PREF_ORDER if v in present] \
               + sorted(present - set(VARIANT_PREF_ORDER))
    n_reps = max((len(v) for v in rows.values()), default=0)
    prefix = date_prefix_from_csv(csv_path)
    plot(rows, "symmetric",  out_dir / f"{prefix}-single-tcp-symmetric.png",
         variants, n_reps)
    plot(rows, "asymmetric", out_dir / f"{prefix}-single-tcp-asymmetric.png",
         variants, n_reps)


if __name__ == "__main__":
    main()
