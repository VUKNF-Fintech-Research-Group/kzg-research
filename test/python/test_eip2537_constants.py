"""The constants in contracts/KZGVerifier.sol match the EIP-4844 trusted setup."""
import re

import eip2537
from conftest import REPO_ROOT, TRUSTED_SETUP_PATH
from kzg_constants import BLS_MODULUS

SOURCE = (REPO_ROOT / "contracts" / "KZGVerifier.sol").read_text()


def solidity_bytes_constant(name: str) -> str:
    body = re.search(rf"bytes internal constant {name} =(.*?);", SOURCE, re.S).group(1)
    return "".join(re.findall(r'hex"([0-9a-f]+)"', body))


def test_point_constants():
    g1, g2, tau = eip2537.solidity_constants(TRUSTED_SETUP_PATH)
    assert solidity_bytes_constant("G1_GEN") == g1
    assert solidity_bytes_constant("G2_GEN") == g2
    assert solidity_bytes_constant("TAU_G2") == tau


def test_scalar_modulus_constant():
    value = re.search(r"uint256 internal constant R = (0x[0-9a-f]+);", SOURCE).group(1)
    assert int(value, 16) == BLS_MODULUS


def test_precompile_addresses():
    assert "G1MSM = address(0x0c)" in SOURCE
    assert "G2MSM = address(0x0e)" in SOURCE
    assert "PAIRING_CHECK = address(0x0f)" in SOURCE


def test_infinity_encodes_as_zero_bytes():
    assert eip2537.g1_to_eip2537(bytes([0xC0]) + bytes(47)) == bytes(128)
