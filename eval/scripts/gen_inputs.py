#!/usr/bin/env python3
"""gen_inputs.py — deterministic inputs for the EXP-001 sweeps (S1, S2, smoke test).

Usage (from the repo root):
    .venv/bin/python eval/scripts/gen_inputs.py

Writes eval/data/inputs/:
    handles.json          the seeded handle stream; R_N = first N handles (nested sets)
    smoke_vectors.json    G1MSM and pairing inputs with expected outputs and EIP-2537 prices
    s2_N<N>.json          per size N: seeded commitment, real-path commitments (N <= 256),
                          update targets, 10+ fresh proofs, negative cases
    s2_batch.json         commitments for the batch sweep from base R_16

Every S2 opening is checked three ways before it is written:
  y from c-kzg == prod(z - r) mod r computed directly, the proof verifies off-chain,
  and (for the real path) the incrementally built blob gives the same commitment
  as the from-scratch blob.
"""
import hashlib
import json
import random
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "bindings" / "python"))

import ckzg  # noqa: E402
from py_ecc.bls.point_compression import decompress_G1  # noqa: E402
from py_ecc.bls.typing import G1Compressed  # noqa: E402
from py_ecc.optimized_bls12_381 import G1, G2, add, multiply, neg  # noqa: E402

import eip2537  # noqa: E402
import oneProofOffChain_KZG as kzg  # noqa: E402
from kzg_constants import BLS_MODULUS as R, FIELD_ELEMENTS_PER_BLOB  # noqa: E402

CFG = json.loads((REPO / "eval" / "config" / "sizes.json").read_text())
OUT = REPO / "eval" / "data" / "inputs"
TS_PATH = REPO / "src" / "trusted_setup.txt"
DOMAIN = kzg.evaluation_domain()


def hx(b) -> str:
    return "0x" + bytes(b).hex()


def fe(v: int) -> bytes:
    return (v % R).to_bytes(32, "big")


class HandleStream:
    """Uniform handles in [1, r - 2] from a recorded seed."""

    def __init__(self, seed: int):
        self.rng = random.Random(seed)

    def next(self) -> int:
        while True:
            v = self.rng.getrandbits(255)
            if 1 <= v <= R - 2:
                return v


def blob_from_evals(evals):
    return b"".join(v.to_bytes(32, "big") for v in evals)


def evals_times(evals, handle):
    """Pointwise update after one revocation: f'(w_i) = f(w_i) * (w_i - handle)."""
    return [e * (d - handle) % R for e, d in zip(evals, DOMAIN)]


def opening(blob, commitment, revoked_set, revoked_list, z, ts):
    proof, y = ckzg.compute_kzg_proof(blob, fe(z), ts)
    y = int.from_bytes(bytes(y), "big")
    y_direct = kzg.evaluate_revoked_poly(revoked_list, z)
    assert y == y_direct, f"c-kzg y != direct evaluation at z={z}"
    ok = bool(ckzg.verify_kzg_proof(commitment, fe(z), fe(y), proof, ts))
    assert ok, f"off-chain verify failed at z={z}"
    return {"z": str(z), "y": str(y), "w": hx(eip2537.g1_to_eip2537(bytes(proof))), "w_compressed": hx(proof),
            "revoked": z in revoked_set, "offchain_verifies": ok, "y_matches_direct": True}


def smoke_vectors():
    rng = random.Random(CFG["seed"] + 1)
    discount = {1: 1000, 2: 949, 3: 848, 4: 797}
    msm = []
    for k in (1, 2, 3, 4):
        pts = [multiply(G1, i + 2) for i in range(k)]
        scal = [rng.randrange(1, R) for _ in range(k)]
        acc = None
        for p, s in zip(pts, scal):
            term = multiply(p, s)
            acc = term if acc is None else add(acc, term)
        inp = b"".join(eip2537._encode_g1(p) + s.to_bytes(32, "big") for p, s in zip(pts, scal))
        msm.append({"k": k, "input": hx(inp), "expected_output": hx(eip2537._encode_g1(acc)),
                    "price": k * 12000 * discount[k] // 1000})
    g1, g2 = eip2537._encode_g1(G1), eip2537._encode_g2(G2)
    pairing = [
        {"k": 2, "name": "e(G1,G2)*e(-G1,G2) = 1", "input": hx(g1 + g2 + eip2537._encode_g1(neg(G1)) + g2),
         "expected_output": hx((1).to_bytes(32, "big")), "price": 32600 * 2 + 37700},
        {"k": 2, "name": "e(G1,G2)*e(G1,G2) != 1", "input": hx(g1 + g2 + g1 + g2),
         "expected_output": hx((0).to_bytes(32, "big")), "price": 32600 * 2 + 37700},
    ]
    return {"g1msm": msm, "pairing": pairing,
            "formula": "G1MSM k*12000*discount(k)/1000, discount 1000/949/848/797 for k=1..4; pairing 32600*k + 37700"}


def main():
    t0 = time.time()
    OUT.mkdir(parents=True, exist_ok=True)
    ts = ckzg.load_trusted_setup(str(TS_PATH), 0)
    sizes = CFG["hardhat_sizes"]
    reps = CFG["verify_repetitions_hardhat"]
    n_max = max(sizes)

    stream = HandleStream(CFG["seed"])
    handles = []
    seen = set()
    while len(handles) < n_max + 2 + 200:  # revoked prefix, update targets, batch
        h = stream.next()
        if h not in seen:
            seen.add(h)
            handles.append(h)
    # Query handles come from an independent stream so they never coincide with revocations.
    query_stream = HandleStream(CFG["seed"] + 2)

    srs_sha = hashlib.sha256(TS_PATH.read_bytes()).hexdigest()
    (OUT / "handles.json").write_text(json.dumps({
        "seed": CFG["seed"], "domain": CFG["handle_domain"], "srs_sha256": srs_sha,
        "note": "R_N = handles[:N]. handles[N], handles[N+1] are the next revocations at size N.",
        "handles": [str(h) for h in handles]}, indent=1))
    (OUT / "smoke_vectors.json").write_text(json.dumps(smoke_vectors(), indent=1))

    for n in sizes:
        revoked = handles[:n]
        rset = set(revoked)
        # Seeded path: coefficient form through the library (NTT), from scratch.
        blob = kzg.revoked_ids_to_blob(revoked)
        c = bytes(ckzg.blob_to_kzg_commitment(blob, ts))
        evals = [int.from_bytes(blob[32 * i:32 * i + 32], "big") for i in range(FIELD_ELEMENTS_PER_BLOB)]

        # Real path (N <= 256): one revocation at a time, pointwise evaluation updates.
        real_path = None
        if n in CFG["real_path_sizes"]:
            ev = [1] * FIELD_ELEMENTS_PER_BLOB
            commits = []
            for h in revoked:
                ev = evals_times(ev, h)
                commits.append(hx(eip2537.g1_to_eip2537(bytes(ckzg.blob_to_kzg_commitment(blob_from_evals(ev), ts)))))
            assert blob_from_evals(ev) == blob, f"N={n}: incremental blob != from-scratch blob"
            assert commits[-1] == hx(eip2537.g1_to_eip2537(c)), f"N={n}: real-path C != seeded C"
            real_path = {"initial_commitment": hx(eip2537._encode_g1(G1)),
                         "note": "commitments[i] = C after revoking handles[0..i]; initial = C of f = 1 (= G1)",
                         "commitments": commits}

        # Update targets: the next two revocations from state R_N.
        ev1 = evals_times(evals, handles[n])
        ev2 = evals_times(ev1, handles[n + 1])
        c1 = bytes(ckzg.blob_to_kzg_commitment(blob_from_evals(ev1), ts))
        c2 = bytes(ckzg.blob_to_kzg_commitment(blob_from_evals(ev2), ts))

        valid = []
        while len(valid) < reps + 2:
            z = query_stream.next()
            if z in rset or z in (handles[n], handles[n + 1]):
                continue
            valid.append(opening(blob, c, rset, revoked, z, ts))
        rz = revoked[len(revoked) // 2]
        revoked_open = opening(blob, c, rset, revoked, rz, ts)
        assert revoked_open["y"] == "0"
        # A proof that would verify against the NEXT state (stale-commitment case uses the
        # current state's proof after the registry moves on).
        stale = valid[reps]
        w0 = decompress_G1(G1Compressed(int.from_bytes(bytes.fromhex(valid[0]["w_compressed"][2:]), "big")))
        tampered_w = hx(eip2537._encode_g1(add(w0, G1)))
        assert tampered_w != valid[0]["w"]
        negatives = [
            {"case": "revoked_handle_honest_opening", "w": revoked_open["w"], "z": revoked_open["z"], "y": "0",
             "expect": "ok=false", "note": "y = f(z) = 0; the opening itself is valid"},
            {"case": "revoked_handle_claim_y1", "w": revoked_open["w"], "z": revoked_open["z"], "y": "1",
             "expect": "ok=false"},
            # w + G1: a valid group element that differs from the honest witness. (At N = 1 every
            # witness is the constant [1]_1, so another query's witness would not be a tamper.)
            {"case": "tampered_witness", "w": tampered_w, "z": valid[0]["z"], "y": valid[0]["y"], "expect": "ok=false"},
            {"case": "wrong_y", "w": valid[0]["w"], "z": valid[0]["z"], "y": str((int(valid[0]["y"]) + 1) % R),
             "expect": "ok=false"},
            {"case": "non_canonical_z", "w": valid[0]["w"], "z": str(int(valid[0]["z"]) + R), "y": valid[0]["y"],
             "expect": "revert NonCanonicalScalar"},
            {"case": "non_canonical_y", "w": valid[0]["w"], "z": valid[0]["z"], "y": str(int(valid[0]["y"]) + R),
             "expect": "revert NonCanonicalScalar"},
            {"case": "witness_not_on_curve", "w": "0x" + "00" * 63 + "01" + "00" * 63 + "01", "z": valid[0]["z"],
             "y": valid[0]["y"], "expect": "revert PrecompileFailed"},
            {"case": "stale_commitment", "w": stale["w"], "z": stale["z"], "y": stale["y"],
             "expect": "ok=false", "setup": "registry updated to next_commitment before this verify"},
        ]
        doc = {
            "N": n, "srs_sha256": srs_sha, "revoked": f"handles[:{n}]",
            "commitment": hx(eip2537.g1_to_eip2537(c)), "commitment_compressed": hx(c),
            "next_commitment": hx(eip2537.g1_to_eip2537(c1)), "next2_commitment": hx(eip2537.g1_to_eip2537(c2)),
            "valid": valid[:reps], "negatives": negatives, "real_path": real_path,
            "checks": {"y_direct_all": True, "offchain_verify_all": True,
                       "real_path_equals_seeded": real_path is not None or "n/a"},
        }
        (OUT / f"s2_N{n}.json").write_text(json.dumps(doc, indent=1))
        print(f"N={n}: done ({time.time() - t0:.1f}s)", flush=True)

    base = CFG["batch_base_size"]
    ev = [int.from_bytes(b, "big") for b in
          (kzg.revoked_ids_to_blob(handles[:base])[32 * i:32 * i + 32] for i in range(FIELD_ELEMENTS_PER_BLOB))]
    batch = [hx(eip2537.g1_to_eip2537(bytes(ckzg.blob_to_kzg_commitment(blob_from_evals(ev), ts))))]
    for i in range(max(CFG["batch_sizes"])):
        ev = evals_times(ev, handles[n_max + 2 + i])
        batch.append(hx(eip2537.g1_to_eip2537(bytes(ckzg.blob_to_kzg_commitment(blob_from_evals(ev), ts)))))
    (OUT / "s2_batch.json").write_text(json.dumps({
        "base": f"handles[:{base}]", "added": f"handles[{n_max + 2}:{n_max + 2 + max(CFG['batch_sizes'])}]",
        "note": "commitments[k] = C after k extra revocations on top of the base set", "commitments": batch}, indent=1))
    print(f"all inputs written to {OUT.relative_to(REPO)} in {time.time() - t0:.1f}s")


if __name__ == "__main__":
    main()
