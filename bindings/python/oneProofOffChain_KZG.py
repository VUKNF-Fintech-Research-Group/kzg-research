"""
oneProofOffChain_KZG.py

Same high-level API as oneProofOffChain_toySRS.py but using the C `ckzg` wrapper.

Notes:
- This module serializes small polynomials into a full-size `Blob` (FIELD_ELEMENTS_PER_BLOB = 4096),
  padding trailing coefficients with zeros. It then calls into the C library via the
  `ckzg` extension to compute commitments and proofs.
- Requires the Python C extension `ckzg` to be built (run `make` in this directory).
"""
import time
from typing import List
import math

try:
    import ckzg
except Exception as e:
    raise ImportError("Failed to import C KZG extension `ckzg`. Build it with `make` in bindings/python: " + str(e))

# Constants from the C implementation / spec
FIELD_ELEMENTS_PER_BLOB = 4096
BYTES_PER_FIELD_ELEMENT = 32
BYTES_PER_BLOB = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT
BYTES_PER_COMMITMENT = 48
BYTES_PER_PROOF = 48

# Helper: convert integer scalar -> 32-byte big-endian
# BLS12-381 scalar field modulus (r)
# r = 52435875175126190479447740508185965837690552500527637822603658699938581184512
FR_MODULUS = 52435875175126190479447740508185965837690552500527637822603658699938581184512


def int_to_field_bytes(v: int) -> bytes:
    """Convert an integer to a canonical 32-byte big-endian field element.

    This reduces modulo the BLS12-381 scalar field modulus and handles negative
    values by mapping into the field representative range [0, FR_MODULUS).
    """
    if v is None:
        v = 0
    # reduce to canonical representative
    v_mod = int(v) % FR_MODULUS
    return int(v_mod).to_bytes(BYTES_PER_FIELD_ELEMENT, byteorder="big")


def coeffs_to_blob(coeffs: List[int]) -> bytes:
    """Serialize an ascending-coefficient polynomial into a full Blob bytes object.

    The blob contains FIELD_ELEMENTS_PER_BLOB field elements (32 bytes each). Coeffs
    beyond the provided length are zero-filled.
    """
    coeffs = list(coeffs or [])
    out = bytearray(BYTES_PER_BLOB)
    for i in range(FIELD_ELEMENTS_PER_BLOB):
        v = coeffs[i] if i < len(coeffs) else 0
        b = int_to_field_bytes(v)
        start = i * BYTES_PER_FIELD_ELEMENT
        out[start:start + BYTES_PER_FIELD_ELEMENT] = b
    return bytes(out)


def kzg_commit_from_coeffs(coeffs: List[int], ts) -> bytes:
    """Commit to polynomial coefficients (ascending) using the C wrapper.

    Returns commitment bytes (BYTES_PER_COMMITMENT).
    """
    blob = coeffs_to_blob(coeffs)
    return ckzg.blob_to_kzg_commitment(blob, ts)


def compute_kzg_proof_from_coeffs(coeffs: List[int], z: int, ts):
    """Compute proof and evaluation y for polynomial at point z using C wrapper.

    Returns (proof_bytes, y_int)
    """
    blob = coeffs_to_blob(coeffs)
    z_bytes = int_to_field_bytes(z)
    proof_bytes, y_bytes = ckzg.compute_kzg_proof(blob, z_bytes, ts)
    # y_bytes is BYTES_PER_FIELD_ELEMENT; convert to int
    y_int = int.from_bytes(bytes(y_bytes), byteorder="big")
    return proof_bytes, y_int


def verify_kzg_proof(commitment_bytes: bytes, proof_bytes: bytes, z: int, y: int, ts) -> bool:
    zb = int_to_field_bytes(z)
    yb = int_to_field_bytes(y)
    return bool(ckzg.verify_kzg_proof(commitment_bytes, zb, yb, proof_bytes, ts))


def load_trusted_setup(path: str, precompute: int = 0):
    """Load trusted setup file using the C wrapper and return the capsule."""
    return ckzg.load_trusted_setup(path, precompute)


def poly_mul(a: List[int], b_: List[int]) -> List[int]:
    res = [0] * (len(a) + len(b_) - 1)
    for i, av in enumerate(a):
        for j, bv in enumerate(b_):
            res[i + j] += av * bv
    return res


def build_revoked_poly(revoked_ids: List[int]) -> List[int]:
    poly = [1]
    for rid in revoked_ids:
        poly = poly_mul(poly, [-rid, 1])
    return poly


class RevocationAccumulatorKZG:
    """Accumulator using the C KZG binding.

    Note: incremental updates here are implemented by recomputing the commitment
    after each coefficient change (full commit per add). This mirrors the
    semantics of the toy module but leverages the C implementation for the
    heavy work.
    """

    def __init__(self, revoked_ids: List[int] = None, ts_path: str = 'trusted_setup.txt', precompute: int = 0):
        self.revoked_ids = list(revoked_ids or [])
        self.ts = load_trusted_setup(ts_path, precompute)
        self.poly = build_revoked_poly(self.revoked_ids)
        self.commitment = None
        self.rebuild()

    def rebuild(self):
        t0 = time.perf_counter()
        self.poly = build_revoked_poly(self.revoked_ids)
        t1 = time.perf_counter()
        self.commitment = kzg_commit_from_coeffs(self.poly, self.ts)
        t2 = time.perf_counter()
        return {'poly_build_ms': (t1 - t0) * 1000, 'commit_ms': (t2 - t1) * 1000}

    def add_revoke(self, rid: int):
        if rid in self.revoked_ids:
            return {'poly_build_ms': 0.0, 'commit_ms': 0.0, 'skipped': True}
        t0 = time.perf_counter()
        # update coefficients
        self.poly = poly_mul(self.poly, [-rid, 1])
        t1 = time.perf_counter()
        # recompute commitment (C work in C)
        self.commitment = kzg_commit_from_coeffs(self.poly, self.ts)
        t2 = time.perf_counter()

        self.revoked_ids.append(rid)
        return {'poly_build_ms': (t1 - t0) * 1000, 'commit_ms': (t2 - t1) * 1000, 'skipped': False}

    def add_revokes(self, ids: List[int]):
        new = [i for i in ids if i not in self.revoked_ids]
        if not new:
            return {'poly_build_ms': 0.0, 'commit_ms': 0.0, 'skipped': True, 'added': 0}
        t0 = time.perf_counter()
        total_poly = 0.0
        total_commit = 0.0
        for a in new:
            res = self.add_revoke(a)
            total_poly += res['poly_build_ms']
            total_commit += res['commit_ms']
        t1 = time.perf_counter()
        return {'poly_build_ms': total_poly, 'commit_ms': total_commit, 'skipped': False, 'added': len(new), 'total_ms': (t1 - t0) * 1000}

    def add_revokes_batch(self, ids: List[int]):
        new = [i for i in ids if i not in self.revoked_ids]
        if not new:
            return {'poly_build_ms': 0.0, 'commit_ms': 0.0, 'skipped': True, 'added': 0}
        t0 = time.perf_counter()
        batch_poly = [1]
        for a in new:
            batch_poly = poly_mul(batch_poly, [-a, 1])
        t_mid = time.perf_counter()
        new_poly = poly_mul(self.poly, batch_poly)
        t1 = time.perf_counter()
        self.commitment = kzg_commit_from_coeffs(new_poly, self.ts)
        t2 = time.perf_counter()
        self.revoked_ids.extend(new)
        self.poly = new_poly
        return {'poly_build_ms': (t1 - t_mid) * 1000, 'commit_ms': (t2 - t1) * 1000, 'skipped': False, 'added': len(new), 'total_ms': (t2 - t0) * 1000}


def benchmark_incremental_vs_batch(base_deg: int = 10, add_count: int = 20, ts_path: str = 'trusted_setup.txt'):
    base = list(range(1, base_deg + 1))
    new_ids = list(range(1000, 1000 + add_count))

    # prepare accumulators using same trusted setup
    acc_batch = RevocationAccumulatorKZG(revoked_ids=base, ts_path=ts_path)
    res_batch = acc_batch.add_revokes_batch(new_ids)

    acc_inc = RevocationAccumulatorKZG(revoked_ids=base, ts_path=ts_path)
    t0 = time.perf_counter()
    acc_inc.add_revokes(new_ids)
    t1 = time.perf_counter()
    total_inc_ms = (t1 - t0) * 1000

    # compare commitments bytes
    if acc_batch.commitment != acc_inc.commitment:
        raise AssertionError('Commitments differ after updates (KZG wrapper)')

    return {'batch': res_batch, 'incremental_total_ms': total_inc_ms}
