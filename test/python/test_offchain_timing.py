"""T5: the off-chain timing benchmark runs and regenerates its CSV."""
import csv
import json
import subprocess
import sys

from conftest import REPO_ROOT


def test_quick_run_writes_csv_and_metadata(tmp_path):
    subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "benchmark_offchain_timing.py"),
         "--quick", "--out-dir", str(tmp_path)],
        check=True, capture_output=True,
    )
    rows = list(csv.DictReader(open(tmp_path / "offchain_timing.csv")))
    steps = {(int(r["degree"]), r["step"], r["k_new_revocations"]) for r in rows}
    for d in (2, 16, 256):
        for step in ("build_blob", "commit", "prove", "verify"):
            assert (d, step, "") in steps
    assert (256, "witness_update", "100") in steps
    assert (2, "witness_update", "10") not in steps  # k >= d is skipped
    assert all(float(r["mean_ms"]) > 0 for r in rows)

    meta = json.loads((tmp_path / "offchain_timing_meta.json").read_text())
    for key in ("cpu", "os", "python", "ckzg_version", "commit", "date"):
        assert meta[key]
