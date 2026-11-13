#!/usr/bin/env python3
"""aggregate.py — raw JSONL -> tidy CSVs and the environment manifest (EXP-001).

Usage (repo root): .venv/bin/python eval/scripts/aggregate.py [--network hardhat]

Reads the newest smoke / sweep_verify / sweep_revoke run per network from eval/data/raw/.
Writes:
  eval/data/processed/tidy.csv            one row per (sut, network, N, metric, rep)
  eval/data/processed/verify_summary.csv  per (sut, N, state): M1 median/IQR, M2, M3, M4, floor share, M5
  eval/data/processed/update_summary.csv  M6 per (sut, N, first/later)
  eval/data/processed/batch.csv           S2 batch amortisation
  eval/data/processed/negatives.csv       E7 outcomes
  eval/data/processed/cost_usd.csv        M12 on the fixed grid in eval/config/cost.json
  eval/data/processed/ratios.csv          derived ratios, base named
  eval/data/raw/bytecode.json             runtime-code SHA-256 per deployed contract
  eval/reports/manifest.json
No number is typed by hand: every value comes from a raw row.
"""
import argparse
import csv
import hashlib
import json
import os
import platform
import statistics as st
import subprocess
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
EVAL = REPO / "eval"
RAW = EVAL / "data" / "raw"
PROC = EVAL / "data" / "processed"
CONFIG = EVAL / "config"


def latest(script, network):
    files = sorted(RAW.glob(f"{script}-{network}-*.jsonl"))
    if not files:
        return None, []
    lines = [json.loads(l) for l in files[-1].read_text().splitlines() if l.strip()]
    return lines[0], lines[1:]


def quartiles(v):
    if len(v) < 2:
        return v[0], v[0]
    q = st.quantiles(v, n=4, method="inclusive")
    return q[0], q[2]


def sh(cmd):
    try:
        return subprocess.check_output(cmd, cwd=REPO, stderr=subprocess.DEVNULL, text=True).strip()
    except Exception:
        return "unknown"


def write_csv(path, rows, fields=None):
    path.parent.mkdir(parents=True, exist_ok=True)
    fields = fields or list(rows[0].keys())
    with path.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in fields})


def manifest(headers, network):
    build_info = sorted((REPO / "artifacts" / "build-info").glob("*.json"), key=os.path.getmtime)
    settings = {}
    if build_info:
        bi = json.loads(build_info[-1].read_text())
        s = bi["input"]["settings"]
        settings = {"solc": bi.get("solcVersion"), "optimizer": s.get("optimizer"), "evmVersion": s.get("evmVersion", "compiler default")}
    try:
        import ckzg  # noqa: F401
        from importlib.metadata import version
        pkgs = {p: version(p) for p in ("ckzg", "py_ecc", "matplotlib", "pycryptodome")}
    except Exception:
        pkgs = {}
    ram = sh(["sysctl", "-n", "hw.memsize"])
    srs = REPO / "src" / "trusted_setup.txt"
    return {
        "experiment": "EXP-001 (evaluation plan rev 25, 2026-11-13), S1 and S2 only",
        "git_commit": sh(["git", "rev-parse", "HEAD"]),
        "git_branch": sh(["git", "branch", "--show-current"]),
        "dirty": sh(["git", "status", "--porcelain", "--untracked-files=no"]) != "",
        "spec_version": "n/a for S1/S2",
        "srs_sha256": hashlib.sha256(srs.read_bytes()).hexdigest(),
        "node": sh(["node", "--version"]),
        "hardhat": sh(["npx", "hardhat", "--version"]).splitlines()[-1] if sh(["npx", "hardhat", "--version"]) != "unknown" else "unknown",
        "compiler": settings,
        "python": sys.version.split()[0],
        "python_packages": pkgs,
        "cpu": sh(["sysctl", "-n", "machdep.cpu.brand_string"]),
        "cores": os.cpu_count(),
        "ram_gb": round(int(ram) / 2**30, 1) if ram.isdigit() else ram,
        "os": f"{platform.system()} {platform.mac_ver()[0] or platform.release()}",
        "cpu_governor": "not settable on macOS",
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "network": network,
        "runs": [{k: h.get(k) for k in ("run_id", "script", "commit", "chain_id", "started_utc", "finished_utc", "first_block", "last_block", "rows")} for h in headers if h],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--network", default="hardhat")
    net = ap.parse_args().network
    cost = json.loads((CONFIG / "cost.json").read_text())

    h_smoke, smoke = latest("smoke", net)
    h_ver, ver = latest("sweep_verify", net)
    h_rev, rev = latest("sweep_revoke", net)
    if not ver:
        sys.exit("no sweep_verify run found")

    tidy = []
    groups = defaultdict(list)
    for r in ver:
        if r.get("kind") != "verify_accept":
            continue
        groups[(r["sut"], r["N"], r["state"])].append(r)
        exec_rem = r["exec_gas_traced"] - r["precompile_gas_traced"]
        floor_topup = r["gas_used"] - r["standard_gas"] if r["floor_binds"] else 0
        for metric, unit, value in [
            ("M1_verify_tx_gas", "gas", r["gas_used"]), ("M2_precompile_gas", "gas", r["precompile_gas_traced"]),
            ("M3_calldata_gas", "gas", r["calldata_gas"]), ("M4_execution_remainder_gas", "gas", exec_rem),
            ("floor_topup_gas", "gas", floor_topup), ("M5_proof_bytes", "bytes", r.get("proof_bytes")),
        ]:
            tidy.append({"run_id": r["run_id"], "sut": r["sut"], "network": net, "N": r["N"], "state": r["state"], "scope": r["scope"],
                         "metric": metric, "unit": unit, "value": value, "rep": r["rep"], "tx_hash": r["tx_hash"]})

    vsum = []
    for (sut, n, state), rows in sorted(groups.items()):
        g = [r["gas_used"] for r in rows]
        q1, q3 = quartiles(g)
        exec_rem = [r["exec_gas_traced"] - r["precompile_gas_traced"] for r in rows]
        vsum.append({
            "sut": sut, "network": net, "N": n, "state": state, "scope": rows[0]["scope"], "reps": len(rows),
            "M1_median_gas": st.median(g), "M1_min_gas": min(g), "M1_max_gas": max(g), "M1_q1_gas": q1, "M1_q3_gas": q3,
            "M1_spread_gas": max(g) - min(g),
            "M2_precompile_gas": st.median(r["precompile_gas_traced"] for r in rows),
            "M2_formula_gas": rows[0]["precompile_gas_formula"],
            "M3_calldata_median_gas": st.median(r["calldata_gas"] for r in rows),
            "M4_exec_remainder_median_gas": st.median(exec_rem),
            "floor_gas_median": st.median(r["floor_gas"] for r in rows),
            "floor_binds_share": sum(r["floor_binds"] for r in rows) / len(rows),
            "calldata_bytes_median": st.median(r["calldata_bytes"] for r in rows),
            "zero_bytes_median": st.median(r["zero_bytes"] for r in rows),
            "M5_proof_bytes_median": st.median(r["proof_bytes"] for r in rows),
            "proof_len_values": "|".join(str(x) for x in sorted({r.get("proof_len") for r in rows if r.get("proof_len") is not None})),
            "tree_depth": rows[0].get("tree_depth", ""),
        })
    write_csv(PROC / "verify_summary.csv", vsum)

    usum, batch = [], []
    ug = defaultdict(list)
    for r in rev:
        if r.get("kind") in ("update_first", "update_later"):
            ug[(r["sut"], r["N"], r["kind"])].append(r)
            tidy.append({"run_id": r["run_id"], "sut": r["sut"], "network": net, "N": r["N"], "state": r["state"], "scope": r["scope"],
                         "metric": "M6_update_gas_" + r["kind"].split("_")[1], "unit": "gas", "value": r["gas_used"], "rep": r["rep"], "tx_hash": r["tx_hash"]})
        elif r.get("kind") == "batch_summary":
            batch.append({k: r[k] for k in ("sut", "k", "base_N", "incremental_total_gas", "single_update_gas_median", "batch_gas_median", "gain_formula", "gain_pct", "label")})
    for (sut, n, kind), rows in sorted(ug.items()):
        g = [r["gas_used"] for r in rows]
        usum.append({"sut": sut, "network": net, "N": n, "kind": kind, "reps": len(g), "M6_median_gas": st.median(g), "M6_min_gas": min(g), "M6_max_gas": max(g),
                     "tx_hashes": "|".join(r["tx_hash"] for r in rows)})
    write_csv(PROC / "update_summary.csv", usum)
    if batch:
        write_csv(PROC / "batch.csv", batch)

    negs = [{"sut": r["sut"], "N": r["N"], "case": r["case"], "expected": r["expected"], "outcome": r["outcome"],
             "revert_reason": r.get("revert_reason", ""), "gas_used": r.get("gas_used", ""), "tx_hash": r.get("tx_hash", ""), "pass": r["pass"]}
            for r in ver if r.get("kind") == "verify_reject"]
    write_csv(PROC / "negatives.csv", negs)

    costs = []
    for v in vsum:
        if v["state"] != "seeded":
            continue
        for gwei in cost["gas_price_gwei"]:
            costs.append({"sut": v["sut"], "N": v["N"], "gas": v["M1_median_gas"], "gas_price_gwei": gwei, "eth_price_usd": cost["eth_price_usd"],
                          "usd_per_verification": round(v["M1_median_gas"] * gwei * 1e-9 * cost["eth_price_usd"], 6)})
    write_csv(PROC / "cost_usd.csv", costs)

    by = {(v["sut"], v["N"]): v for v in vsum if v["state"] == "seeded"}
    ratios = []
    for n in sorted({k[1] for k in by}):
        if ("S1", n) in by and ("S2", n) in by:
            s1, s2 = by[("S1", n)]["M1_median_gas"], by[("S2", n)]["M1_median_gas"]
            ratios.append({"N": n, "ratio": "S2 / S1 verify gas", "base": "S1 median M1", "value": round(s2 / s1, 3), "S1": s1, "S2": s2})
    write_csv(PROC / "ratios.csv", ratios)

    write_csv(PROC / "tidy.csv", tidy, ["run_id", "sut", "network", "N", "state", "scope", "metric", "unit", "value", "rep", "tx_hash"])

    bytecode = {f"{r['sut']}@{r['address']}": r["runtime_sha256"] for r in ver if r.get("kind") == "deploy"}
    if h_smoke:
        bytecode["PrecompileProbe@" + h_smoke.get("probe_address", "")] = h_smoke.get("probe_runtime_sha256")
    (RAW / "bytecode.json").write_text(json.dumps(bytecode, indent=1))
    (EVAL / "reports").mkdir(parents=True, exist_ok=True)
    (EVAL / "reports" / "manifest.json").write_text(json.dumps(manifest([h_smoke, h_ver, h_rev], net), indent=1))
    print(f"processed {len(ver)} verify rows, {len(rev)} update rows -> {PROC.relative_to(REPO)}")


if __name__ == "__main__":
    main()
