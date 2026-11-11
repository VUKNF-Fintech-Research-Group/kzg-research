"""
oneProofOffChain_KZG.py

Same high-level API as oneProofOffChain_toySRS.py but using the C `ckzg` wrapper.

Notes:
- c-kzg-4844 reads a `Blob` as the polynomial's 4096 *evaluations* over the
  bit-reversed 4096th roots of unity, not as its coefficients. `coeffs_to_blob`
  therefore converts coefficients to that evaluation form (one NTT) before
  calling into the C library for commitments and proofs.
- The SRS bounds the degree at 4095, so at most 4095 revoked IDs fit in one
  polynomial. Larger inputs raise `ValueError`.
- Requires the `ckzg` package from PyPI (`pip install -r requirements.txt`).
"""
import time
from typing import List
import math

try:
    import ckzg
except Exception as e:
    raise ImportError("Failed to import `ckzg`. Install it with `pip install -r requirements.txt`: " + str(e))

from kzg_constants import (
    BLS_MODULUS,
    BYTES_PER_BLOB,
    BYTES_PER_COMMITMENT,
    BYTES_PER_FIELD_ELEMENT,
    BYTES_PER_PROOF,
    FIELD_ELEMENTS_PER_BLOB,
    PRIMITIVE_ROOT_OF_UNITY,
)

# Highest polynomial degree the EIP-4844 SRS supports, and so the largest
# number of revoked IDs one polynomial can hold.
MAX_DEGREE = FIELD_ELEMENTS_PER_BLOB - 1
MAX_REVOKED_IDS = MAX_DEGREE

_LOG_N = FIELD_ELEMENTS_PER_BLOB.bit_length() - 1
# Primitive N-th root of unity, derived as in c-kzg-4844.
ROOT_OF_UNITY = pow(PRIMITIVE_ROOT_OF_UNITY, (BLS_MODULUS - 1) // FIELD_ELEMENTS_PER_BLOB, BLS_MODULUS)


def _bit_reverse(i: int) -> int:
    return int(format(i, f"0{_LOG_N}b")[::-1], 2)


_BIT_REVERSED_INDEX = [_bit_reverse(i) for i in range(FIELD_ELEMENTS_PER_BLOB)]


def evaluation_domain() -> List[int]:
    """The blob's evaluation points: blob[i] holds f(domain[i]).

    These are the N-th roots of unity in bit-reversed order, as c-kzg-4844 uses.
    """
    return [pow(ROOT_OF_UNITY, j, BLS_MODULUS) for j in _BIT_REVERSED_INDEX]


def _ntt(values: List[int]) -> List[int]:
    """Forward NTT: returns [f(w^0), f(w^1), ..., f(w^(N-1))] for coefficients `values`."""
    n = len(values)
    a = [values[j] for j in _BIT_REVERSED_INDEX]
    length = 2
    while length <= n:
        w_len = pow(ROOT_OF_UNITY, n // length, BLS_MODULUS)
        half = length // 2
        for start in range(0, n, length):
            w = 1
            for k in range(start, start + half):
                u = a[k]
                v = a[k + half] * w % BLS_MODULUS
                a[k] = (u + v) % BLS_MODULUS
                a[k + half] = (u - v) % BLS_MODULUS
                w = w * w_len % BLS_MODULUS
        length *= 2
    return a


def int_to_field_bytes(v: int) -> bytes:
    """Convert an integer to a canonical 32-byte big-endian field element.

    This reduces modulo the BLS12-381 scalar field modulus and handles negative
    values by mapping into the field representative range [0, BLS_MODULUS).
    """
    if v is None:
        v = 0
    # reduce to canonical representative
    v_mod = int(v) % BLS_MODULUS
    return int(v_mod).to_bytes(BYTES_PER_FIELD_ELEMENT, byteorder="big")


def coeffs_to_blob(coeffs: List[int]) -> bytes:
    """Encode an ascending-coefficient polynomial as a c-kzg Blob.

    The blob holds the polynomial's evaluations over `evaluation_domain()`, which
    is the form c-kzg-4844 expects. Raises ValueError if the degree exceeds
    MAX_DEGREE (4095), because the SRS cannot commit to such a polynomial.
    """
    coeffs = [int(c) % BLS_MODULUS for c in (coeffs or [])]
    while coeffs and coeffs[-1] == 0:
        coeffs.pop()
    if len(coeffs) > FIELD_ELEMENTS_PER_BLOB:
        raise ValueError(
            f"polynomial degree {len(coeffs) - 1} exceeds the SRS bound of {MAX_DEGREE}"
        )
    coeffs += [0] * (FIELD_ELEMENTS_PER_BLOB - len(coeffs))
    evals = _ntt(coeffs)  # natural order: evals[j] = f(w^j)
    return b"".join(
        evals[j].to_bytes(BYTES_PER_FIELD_ELEMENT, "big") for j in _BIT_REVERSED_INDEX
    )


def revoked_ids_to_blob(revoked_ids: List[int]) -> bytes:
    """Blob for the revocation polynomial f(x) = prod(x - id) over the revoked IDs."""
    return coeffs_to_blob(build_revoked_poly(revoked_ids))


def evaluate_revoked_poly(revoked_ids: List[int], z: int) -> int:
    """Directly evaluate f(z) = prod(z - id) mod r, without c-kzg.

    Used as an independent cross-check of the y value c-kzg returns.
    """
    acc = 1
    for rid in revoked_ids:
        acc = acc * (z - rid) % BLS_MODULUS
    return acc


def kzg_commit_from_coeffs(coeffs: List[int], ts) -> bytes:
    """Commit to the polynomial with these coefficients (ascending order).

    The coefficients are converted to evaluation form first (see `coeffs_to_blob`).
    Returns commitment bytes (BYTES_PER_COMMITMENT).
    """
    blob = coeffs_to_blob(coeffs)
    return ckzg.blob_to_kzg_commitment(blob, ts)


def compute_kzg_proof_from_coeffs(coeffs: List[int], z: int, ts):
    """Open the polynomial with these coefficients (ascending order) at z.

    The coefficients are converted to evaluation form first (see `coeffs_to_blob`).
    Returns (proof_bytes, y_int) with y = f(z).
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
            res[i + j] = (res[i + j] + av * bv) % BLS_MODULUS
    return res


def _check_revoked_ids(revoked_ids: List[int]) -> None:
    if len(revoked_ids) > MAX_REVOKED_IDS:
        raise ValueError(
            f"{len(revoked_ids)} revoked IDs exceed the SRS bound of {MAX_REVOKED_IDS} per polynomial"
        )
    for rid in revoked_ids:
        if not 0 <= int(rid) < BLS_MODULUS:
            raise ValueError(f"revoked ID {rid} is not a canonical field element")


def build_revoked_poly(revoked_ids: List[int]) -> List[int]:
    """Coefficients (ascending, reduced mod r) of f(x) = prod(x - id)."""
    revoked_ids = list(revoked_ids or [])
    _check_revoked_ids(revoked_ids)
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
        _check_revoked_ids(self.revoked_ids + [rid])
        t0 = time.perf_counter()
        # update coefficients
        new_poly = poly_mul(self.poly, [-rid, 1])
        t1 = time.perf_counter()
        # recompute commitment (C work in C)
        self.commitment = kzg_commit_from_coeffs(new_poly, self.ts)
        t2 = time.perf_counter()

        self.poly = new_poly
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
        _check_revoked_ids(self.revoked_ids + new)
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
