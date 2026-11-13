#!/usr/bin/env python3
"""plot.py — EXP-001 figures from the processed CSVs (no hand-typed numbers).

Usage (repo root): .venv/bin/python eval/scripts/plot.py [--network hardhat]
Writes eval/figures/<ID>.png (300 dpi) and .svg, each with its CSV next to it:
  V1_verify_gas_vs_N       verify gas vs registry size (S1, S2)
  V2_gas_breakdown         where the verify gas goes, N = 1024
  V7_cost_usd              cost per verification at 1 / 5 / 20 gwei
Palette: baselines in greys with distinct markers and direct labels (plan style rule);
gas components use the validated categorical slots 1-5; gas price uses one blue ramp.
"""
import argparse
import csv
import json
import subprocess
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.ticker import FuncFormatter  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
EVAL = REPO / "eval"
PROC = EVAL / "data" / "processed"
FIG = EVAL / "figures"

INK, INK2, GRID, SURFACE = "#0b0b0b", "#52514e", "#e6e5e1", "#fcfcfb"
DESIGN = {"S1": {"color": "#3d3c39", "marker": "o", "label": "S1 Merkle, revealed ID"},
          "S2": {"color": "#8f8d87", "marker": "s", "label": "S2 KZG, revealed ID"}}
SEGMENTS = [("base", "21,000 base", "#2a78d6"), ("calldata", "calldata (M3)", "#eb6834"),
            ("precompile", "precompiles (M2)", "#1baf7a"), ("remainder", "execution remainder (M4)", "#eda100"),
            ("floor", "EIP-7623 floor top-up", "#e87ba4")]
PRICE_RAMP = ["#86b6ef", "#3987e5", "#184f95"]

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": INK2, "axes.labelcolor": INK2,
    "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
    "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
    "text.usetex": False, "text.parse_math": False,
    "figure.facecolor": SURFACE, "axes.facecolor": SURFACE, "savefig.facecolor": SURFACE,
})
thousands = FuncFormatter(lambda v, _: f"{v:,.0f}")


def rows(name):
    return list(csv.DictReader(open(PROC / name)))


def source_line(fig, network):
    commit = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], cwd=REPO, text=True).strip()
    dirty = "-dirty" if subprocess.check_output(["git", "status", "--porcelain"], cwd=REPO, text=True).strip() else ""
    date = json.loads((EVAL / "reports" / "manifest.json").read_text())["generated_utc"][:10]
    fig.text(0.01, 0.01, f"Source: {network} (Prague, real EIP-2537 precompiles), commit {commit}{dirty}, {date}. EXP-001.",
             fontsize=7, color=INK2, ha="left", va="bottom")


def save(fig, name, data_rows):
    FIG.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIG / f"{name}.png", dpi=300)
    fig.savefig(FIG / f"{name}.svg")
    with open(FIG / f"{name}.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(data_rows[0].keys()))
        w.writeheader()
        w.writerows(data_rows)
    plt.close(fig)


def v1(network):
    data = [r for r in rows("verify_summary.csv") if r["state"] == "seeded"]
    ns = sorted({int(r["N"]) for r in data})
    pos = {n: i for i, n in enumerate(ns)}
    by = {(r["sut"], int(r["N"])): float(r["M1_median_gas"]) for r in data}
    s1_hi, s2_lo = by[("S1", ns[-1])], min(by[("S2", n)] for n in ns)
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    for sut, st in DESIGN.items():
        ys = [by[(sut, n)] for n in ns]
        ax.plot([pos[n] for n in ns], ys, color=st["color"], linewidth=2, marker=st["marker"], markersize=6,
                markeredgecolor=SURFACE, markeredgewidth=1.2, label=st["label"], zorder=3)
        ax.annotate(f"{ys[-1]:,.0f}", (pos[ns[-1]], ys[-1]), xytext=(8, 0), textcoords="offset points", va="center", color=INK, fontsize=8)
        ax.annotate(f"{ys[0]:,.0f}", (0, ys[0]), xytext=(0, 9 if sut == "S2" else -14), textcoords="offset points", ha="center", color=INK, fontsize=8)
    floor = 21_000 + 30_528 + 102_900
    ax.axhline(floor, color=INK2, linestyle=(0, (4, 3)), linewidth=1)
    ax.text(len(ns) - 1, floor - 9000, "S2 floor: 21,000 + EIP-2537 prices = 154,428", ha="right", fontsize=7.5, color=INK2)
    ax.axhline(21_000, color=INK2, linestyle=":", linewidth=1)
    ax.text(len(ns) - 1, 24_000, "21,000 transaction base", ha="right", fontsize=7.5, color=INK2)
    ax.set_xticks(range(len(ns)), [f"{n:,}" for n in ns])
    ax.set_xlim(-0.3, len(ns) - 0.4)
    ax.set_ylim(0, 200_000)
    ax.yaxis.set_major_formatter(thousands)
    ax.set_xlabel("Revoked handles N (Merkle depth = ceil(log2(N + 1)))")
    ax.set_ylabel("Verify transaction gas (M1, median of 10)")
    ax.legend(loc="center right", frameon=False, fontsize=8)
    ax.set_title(f"Revealed-ID Merkle verifies {s2_lo / s1_hi:.1f}–{max(by[('S2', n)] / by[('S1', n)] for n in ns):.1f}× cheaper than KZG at every N",
                 loc="left", fontsize=10, color=INK, fontweight="bold")
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    source_line(fig, network)
    save(fig, "V1_verify_gas_vs_N", [{"sut": s, "N": n, "M1_median_gas": by[(s, n)]} for s in DESIGN for n in ns])


def v2(network, n=1024):
    data = {r["sut"]: r for r in rows("verify_summary.csv") if r["state"] == "seeded" and int(r["N"]) == n}
    out = []
    fig, ax = plt.subplots(figsize=(6.4, 3.0))
    for i, sut in enumerate(["S2", "S1"]):
        r = data[sut]
        m1 = float(r["M1_median_gas"])
        cd = float(r["M3_calldata_median_gas"])
        pc = float(r["M2_precompile_gas"])
        rem = float(r["M4_exec_remainder_median_gas"])
        floor = float(r["floor_gas_median"])
        std = 21_000 + cd + pc + rem
        top = max(0.0, m1 - std) if float(r["floor_binds_share"]) > 0.5 else 0.0
        parts = {"base": 21_000, "calldata": cd, "precompile": pc, "remainder": rem, "floor": top}
        left = 0
        for key, label, color in SEGMENTS:
            v = parts[key]
            if v <= 0:
                continue
            ax.barh(i, v, left=left, color=color, height=0.55, edgecolor=SURFACE, linewidth=2)
            if v >= 15000:
                ax.text(left + v / 2, i, f"{v:,.0f}", ha="center", va="center", fontsize=7, color=INK)
            left += v
        ax.text(left + 2000, i, f"{m1:,.0f}", va="center", fontsize=8, color=INK, fontweight="bold")
        out.append({"sut": sut, "N": n, **parts, "M1_median_gas": m1, "standard_gas": std, "floor_gas": floor})
    ax.set_yticks([0, 1], [DESIGN["S2"]["label"], DESIGN["S1"]["label"]])
    ax.set_xlim(0, 200_000)
    ax.xaxis.set_major_formatter(thousands)
    ax.set_xlabel(f"Gas per verify transaction at N = {n:,} (medians; segments sum to M1)")
    ax.grid(axis="y", visible=False)
    handles = [plt.Rectangle((0, 0), 1, 1, color=c) for _, _, c in SEGMENTS]
    ax.legend(handles, [l for _, l, _ in SEGMENTS], ncol=3, fontsize=7, frameon=False, loc="upper center", bbox_to_anchor=(0.5, -0.42))
    pc_share = float(data["S2"]["M2_precompile_gas"]) / float(data["S2"]["M1_median_gas"])
    ax.set_title(f"Precompiles are {pc_share:.0%} of KZG verify gas (N = {n:,})", loc="left", fontsize=10, color=INK, fontweight="bold")
    fig.tight_layout(rect=(0, 0.05, 1, 1))
    source_line(fig, network)
    save(fig, "V2_gas_breakdown", out)


def v7(network, n=1024):
    data = [r for r in rows("cost_usd.csv") if int(r["N"]) == n]
    prices = sorted({float(r["gas_price_gwei"]) for r in data})
    eth = data[0]["eth_price_usd"]
    fig, ax = plt.subplots(figsize=(6.4, 3.4))
    width = 0.26
    for j, gwei in enumerate(prices):
        for i, sut in enumerate(["S1", "S2"]):
            v = next(float(r["usd_per_verification"]) for r in data if r["sut"] == sut and float(r["gas_price_gwei"]) == gwei)
            x = i + (j - 1) * width
            ax.bar(x, v, width=width - 0.03, color=PRICE_RAMP[j], label=f"{gwei:g} gwei" if i == 0 else None)
            ax.text(x, v, f"${v:.3f}", ha="center", va="bottom", fontsize=7, color=INK)
    ax.set_xticks([0, 1], [DESIGN["S1"]["label"], DESIGN["S2"]["label"]])
    ax.set_ylabel("USD per verification (M12)")
    ax.legend(frameon=False, fontsize=8, title="gas price", title_fontsize=8)
    ax.grid(axis="x", visible=False)
    top = max(float(r["usd_per_verification"]) for r in data if r["sut"] == "S2")
    ax.set_title(f"At 20 gwei a KZG verification costs ${top:.2f}", loc="left", fontsize=10, color=INK, fontweight="bold", pad=16)
    ax.text(0, 1.015, f"ETH = ${float(eth):,.0f} (fixed assumption, eval/config/cost.json), N = {n:,}",
            transform=ax.transAxes, fontsize=7.5, color=INK2, va="bottom")
    fig.tight_layout(rect=(0, 0.04, 1, 1))
    source_line(fig, network)
    save(fig, "V7_cost_usd", data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--network", default="hardhat")
    net = ap.parse_args().network
    v1(net)
    v2(net)
    v7(net)
    print(f"figures written to {FIG.relative_to(REPO)}")


if __name__ == "__main__":
    main()
