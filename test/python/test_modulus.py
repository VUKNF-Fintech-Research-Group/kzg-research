"""T4: the scalar modulus is the BLS12-381 subgroup order r, defined once."""
import subprocess
from pathlib import Path

import ckzg
import pytest

import oneProofOffChain_KZG as kzg
from kzg_constants import BLS_MODULUS, BYTES_PER_BLOB, FIELD_ELEMENTS_PER_BLOB

REPO_ROOT = Path(__file__).resolve().parents[2]
R_DECIMAL = 52435875175126190479447740508185965837690552500527637822603658699938581184513


def test_modulus_value():
    assert BLS_MODULUS == R_DECIMAL


def test_minus_one_plus_one_is_r():
    assert (-1 % BLS_MODULUS) + 1 == BLS_MODULUS


def test_negative_coefficient_encoding():
    minus_one = int.from_bytes(kzg.int_to_field_bytes(-1), "big")
    assert minus_one == BLS_MODULUS - 1
    assert (minus_one + 1) % BLS_MODULUS == 0


def test_r_is_the_order_ckzg_uses(trusted_setup):
    """c-kzg accepts r - 1 as a canonical field element and rejects r."""
    blob = bytes(BYTES_PER_BLOB)
    ckzg.compute_kzg_proof(blob, (BLS_MODULUS - 1).to_bytes(32, "big"), trusted_setup)
    with pytest.raises(Exception):
        ckzg.compute_kzg_proof(blob, BLS_MODULUS.to_bytes(32, "big"), trusted_setup)


def test_domain_root_of_unity_exists():
    omega = pow(7, (BLS_MODULUS - 1) // FIELD_ELEMENTS_PER_BLOB, BLS_MODULUS)
    assert pow(omega, FIELD_ELEMENTS_PER_BLOB, BLS_MODULUS) == 1
    assert pow(omega, FIELD_ELEMENTS_PER_BLOB // 2, BLS_MODULUS) != 1


def test_no_stale_modulus_left_in_tracked_files():
    """The old off-by-one value (r - 1) must not reappear."""
    stale_suffix = str(R_DECIMAL - 1)[-6:]  # built here so this file never matches
    out = subprocess.run(
        ["git", "grep", "-n", stale_suffix, "--", ".", ":!_to_delete"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    assert out.stdout == "", out.stdout
