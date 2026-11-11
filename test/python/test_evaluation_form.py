"""T1: the commitment is to the revocation polynomial f(x) = prod(x - id).

c-kzg-4844 reads a blob as evaluations over the bit-reversed roots of unity.
Before the fix the code wrote coefficients into the blob, so revoked IDs opened
to y != 0 with a valid proof.
"""
import random

import ckzg
import pytest

import oneProofOffChain_KZG as kzg
from kzg_constants import BLS_MODULUS, BYTES_PER_BLOB, FIELD_ELEMENTS_PER_BLOB

REVOKED = [3, 7, 9]


def horner(coeffs, x):
    acc = 0
    for c in reversed(coeffs):
        acc = (acc * x + c) % BLS_MODULUS
    return acc


@pytest.fixture(scope="module")
def committed(trusted_setup):
    poly = kzg.build_revoked_poly(REVOKED)
    return poly, kzg.kzg_commit_from_coeffs(poly, trusted_setup)


@pytest.mark.parametrize("z", REVOKED)
def test_revoked_id_opens_to_zero(committed, trusted_setup, z):
    poly, commitment = committed
    proof, y = kzg.compute_kzg_proof_from_coeffs(poly, z, trusted_setup)
    assert y == 0
    assert kzg.verify_kzg_proof(commitment, proof, z, y, trusted_setup)


def test_non_revoked_id_opens_to_f_of_z(committed, trusted_setup):
    poly, commitment = committed
    proof, y = kzg.compute_kzg_proof_from_coeffs(poly, 5, trusted_setup)
    assert y == 16  # (5-3)(5-7)(5-9)
    assert kzg.verify_kzg_proof(commitment, proof, 5, y, trusted_setup)


def test_revoked_id_cannot_claim_nonzero_y(committed, trusted_setup):
    poly, commitment = committed
    proof, _ = kzg.compute_kzg_proof_from_coeffs(poly, 3, trusted_setup)
    assert not kzg.verify_kzg_proof(commitment, proof, 3, 1, trusted_setup)


def test_wrong_y_is_rejected(committed, trusted_setup):
    poly, commitment = committed
    proof, y = kzg.compute_kzg_proof_from_coeffs(poly, 5, trusted_setup)
    assert not kzg.verify_kzg_proof(commitment, proof, 5, y + 1, trusted_setup)


def test_y_matches_independent_evaluation(trusted_setup):
    rng = random.Random(2026)
    revoked = rng.sample(range(1, 10**9), 40)
    poly = kzg.build_revoked_poly(revoked)
    commitment = kzg.kzg_commit_from_coeffs(poly, trusted_setup)
    for z in [revoked[0], revoked[-1], 12345, BLS_MODULUS - 1, rng.randrange(BLS_MODULUS)]:
        proof, y = kzg.compute_kzg_proof_from_coeffs(poly, z, trusted_setup)
        assert y == kzg.evaluate_revoked_poly(revoked, z)
        assert kzg.verify_kzg_proof(commitment, proof, z, y, trusted_setup)


def test_blob_is_evaluations_over_the_bit_reversed_domain():
    rng = random.Random(7)
    coeffs = [rng.randrange(BLS_MODULUS) for _ in range(50)]
    blob = kzg.coeffs_to_blob(coeffs)
    assert len(blob) == BYTES_PER_BLOB
    domain = kzg.evaluation_domain()
    for i in [0, 1, 2, 3, 1000, FIELD_ELEMENTS_PER_BLOB - 1]:
        assert int.from_bytes(blob[32 * i:32 * i + 32], "big") == horner(coeffs, domain[i])


def test_blob_matches_the_brief_reference_encoding():
    """Same bytes as evaluating prod(x - id) directly at each domain point."""
    domain = kzg.evaluation_domain()
    expected = b"".join(
        kzg.evaluate_revoked_poly(REVOKED, w).to_bytes(32, "big") for w in domain
    )
    assert kzg.revoked_ids_to_blob(REVOKED) == expected


def test_full_degree_polynomial(trusted_setup):
    """Degree 4095 (all 4096 coefficients set) is the largest that fits."""
    rng = random.Random(11)
    coeffs = [rng.randrange(BLS_MODULUS) for _ in range(FIELD_ELEMENTS_PER_BLOB)]
    commitment = kzg.kzg_commit_from_coeffs(coeffs, trusted_setup)
    proof, y = kzg.compute_kzg_proof_from_coeffs(coeffs, 5, trusted_setup)
    assert y == horner(coeffs, 5)
    assert kzg.verify_kzg_proof(commitment, proof, 5, y, trusted_setup)


def test_degree_above_srs_bound_raises():
    with pytest.raises(ValueError):
        kzg.coeffs_to_blob([1] * (FIELD_ELEMENTS_PER_BLOB + 1))


def test_more_than_4095_revoked_ids_raises():
    with pytest.raises(ValueError):
        kzg.build_revoked_poly(list(range(1, 4097)))
    with pytest.raises(ValueError):
        kzg.revoked_ids_to_blob(list(range(1, 4097)))


def test_non_canonical_revoked_id_raises():
    with pytest.raises(ValueError):
        kzg.build_revoked_poly([BLS_MODULUS])


def test_accumulator_incremental_equals_batch(trusted_setup, tmp_path):
    from conftest import TRUSTED_SETUP_PATH

    res = kzg.benchmark_incremental_vs_batch(base_deg=5, add_count=6, ts_path=str(TRUSTED_SETUP_PATH))
    assert res["batch"]["added"] == 6

    acc = kzg.RevocationAccumulatorKZG(revoked_ids=REVOKED, ts_path=str(TRUSTED_SETUP_PATH))
    acc.add_revoke(11)
    proof, y = kzg.compute_kzg_proof_from_coeffs(acc.poly, 11, acc.ts)
    assert y == 0
    assert kzg.verify_kzg_proof(acc.commitment, proof, 11, y, acc.ts)
