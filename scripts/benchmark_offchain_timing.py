#!/usr/bin/env python3
"""benchmark_offchain_timing.py

Off-chain cost of the KZG revocation scheme as the number of revoked IDs d
grows. Every measurement uses a real revocation polynomial
f(x) = prod(x - id) with d roots, in the evaluation form c-kzg expects.

Usage:
    python3 scripts/benchmark_offchain_timing.py            # full run (30 runs + 2 warm-ups)
    python3 scripts/benchmark_offchain_timing.py --quick    # 3 runs, small d, for a smoke test

Writes:
    results/offchain_timing.csv         mean and SD in ms per step and d
    results/offchain_timing_meta.json   machine, library versions, commit, date

Steps:
    build_blob          coefficients of f from the revoked IDs, then evaluation
                        over the 4096-point domain (pure Python)
    commit              ckzg.blob_to_kzg_commitment
    prove               ckzg.compute_kzg_proof (the holder's witness)
    verify              ckzg.verify_kzg_proof
    witness_update_k    holder's cost after k new revocations bring the set to
                        d IDs: extend f by k factors, rebuild the blob,
                        recompute the witness. Skipped when k >= d.
"""
import argparse
import csv
import json
import platform
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from importlib import metadata
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "bindings" / "python"))

import ckzg  # noqa: E402
import oneProofOffChain_KZG as kzg  # noqa: E402

TS_PATH = REPO_ROOT / "src" / "trusted_setup.txt"
RESULTS_DIR = REPO_ROOT / "results"

DEGREES = [2, 16, 256, 1024, 4095]
UPDATE_SIZES = [1, 10, 100]
RUNS = 30
WARMUPS = 2


def timed(fn, runs, warmups):
    """Run fn runs + warmups times; return (last result, kept durations in ms)."""
    durations = []
    result = None
    for _ in range(runs + warmups):
        t0 = time.perf_counter_ns()
        result = fn()
        durations.append((time.perf_counter_ns() - t0) / 1e6)
    return result, durations[warmups:]


def revoked_ids(d):
    return list(range(1, d + 1))


def measure_degree(d, ts, runs, warmups):
    """Yield (step, k, durations_ms) for one d."""
    ids = revoked_ids(d)
    z = 10 * d + 7  # a non-revoked ID
    z_bytes = kzg.int_to_field_bytes(z)

    blob, t = timed(lambda: kzg.revoked_ids_to_blob(ids), runs, warmups)
    yield "build_blob", "", t

    commitment, t = timed(lambda: ckzg.blob_to_kzg_commitment(blob, ts), runs, warmups)
    yield "commit", "", t

    (proof, y_bytes), t = timed(lambda: ckzg.compute_kzg_proof(blob, z_bytes, ts), runs, warmups)
    yield "prove", "", t

    y = int.from_bytes(bytes(y_bytes), "big")
    assert y == kzg.evaluate_revoked_poly(ids, z) and y != 0

    ok, t = timed(lambda: ckzg.verify_kzg_proof(commitment, z_bytes, y_bytes, proof, ts), runs, warmups)
    assert ok
    yield "verify", "", t

    for k in UPDATE_SIZES:
        if k >= d:
            continue
        old_poly = kzg.build_revoked_poly(ids[:d - k])
        new_ids = ids[d - k:]

        def update():
            poly = old_poly
            for rid in new_ids:
                poly = kzg.poly_mul(poly, [-rid, 1])
            return ckzg.compute_kzg_proof(kzg.coeffs_to_blob(poly), z_bytes, ts)

        (new_proof, new_y), t = timed(update, runs, warmups)
        # after the update the witness must be the one for the full set
        assert bytes(new_proof) == bytes(proof) and bytes(new_y) == bytes(y_bytes)
        yield "witness_update", k, t


def cpu_model():
    try:
        if platform.system() == "Darwin":
            return subprocess.check_output(["sysctl", "-n", "machdep.cpu.brand_string"], text=True).strip()
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith("model name"):
                return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "unknown"


def git_commit():
    try:
        head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO_ROOT, text=True).strip()
        dirty = subprocess.check_output(
            ["git", "status", "--porcelain", "--untracked-files=no"], cwd=REPO_ROOT, text=True).strip()
        return head + ("-dirty" if dirty else "")
    except Exception:
        return "unknown"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--quick", action="store_true", help="3 runs, d <= 256, no warm-up drop; for smoke tests")
    parser.add_argument("--runs", type=int, default=RUNS)
    parser.add_argument("--warmups", type=int, default=WARMUPS)
    parser.add_argument("--out-dir", type=Path, default=RESULTS_DIR)
    args = parser.parse_args()

    degrees = [d for d in DEGREES if d <= 256] if args.quick else DEGREES
    runs = 3 if args.quick else args.runs
    warmups = 0 if args.quick else args.warmups

    ts = ckzg.load_trusted_setup(str(TS_PATH), 0)
    rows = []
    print(f"{'d':>5} {'step':<16} {'k':>4} {'mean ms':>12} {'SD ms':>10}")
    for d in degrees:
        for step, k, durations in measure_degree(d, ts, runs, warmups):
            mean = statistics.fmean(durations)
            sd = statistics.stdev(durations) if len(durations) > 1 else 0.0
            rows.append({
                "degree": d, "step": step, "k_new_revocations": k,
                "mean_ms": f"{mean:.4f}", "sd_ms": f"{sd:.4f}", "runs": len(durations),
            })
            print(f"{d:>5} {step:<16} {str(k):>4} {mean:>12.4f} {sd:>10.4f}")

    args.out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = args.out_dir / "offchain_timing.csv"
    with open(csv_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    meta = {
        "experiment": "offchain_timing",
        "date": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "commit": git_commit(),
        "runs_kept": runs,
        "warmups_dropped": warmups,
        "degrees": degrees,
        "update_sizes": UPDATE_SIZES,
        "cpu": cpu_model(),
        "machine": platform.machine(),
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "ckzg_version": metadata.version("ckzg"),
        "ckzg_build": "prebuilt PyPI wheel (c-kzg-4844 with blst); compiler flags are those of the upstream wheel build",
        "trusted_setup": "src/trusted_setup.txt (EIP-4844 mainnet), loaded with precompute = 0",
        "timer": "time.perf_counter_ns, single thread",
        "notes": [
            "build_blob and the polynomial part of witness_update run in pure Python; "
            "commit, prove and verify run in C.",
            "witness_update with k new revocations starts from d - k revoked IDs and ends at d.",
        ],
    }
    meta_path = args.out_dir / "offchain_timing_meta.json"
    meta_path.write_text(json.dumps(meta, indent=2) + "\n")
    print(f"\nwrote {csv_path}\nwrote {meta_path}")


if __name__ == "__main__":
    main()
