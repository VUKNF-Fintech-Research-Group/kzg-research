"""eip2537.py

Convert BLS12-381 points from the 48/96-byte compressed form (used by c-kzg and
the EIP-4844 trusted setup) to the uncompressed encoding the EIP-2537
precompiles expect:

  G1: x || y                      2 x 64 bytes = 128 bytes
  G2: x.c0 || x.c1 || y.c0 || y.c1  4 x 64 bytes = 256 bytes

Each coordinate is a 48-byte big-endian field element left-padded to 64 bytes.
The point at infinity is all zero bytes. Note the G2 order: the compressed
form stores x.c1 first, EIP-2537 stores x.c0 first.
"""
from pathlib import Path
from typing import List, Tuple

from py_ecc.bls.point_compression import decompress_G1, decompress_G2
from py_ecc.bls.typing import G1Compressed, G2Compressed
from py_ecc.optimized_bls12_381 import G1, G2, is_inf, normalize

G1_EIP2537_BYTES = 128
G2_EIP2537_BYTES = 256


def _fp(v) -> bytes:
    return int(v).to_bytes(64, "big")


def _encode_g1(point) -> bytes:
    if is_inf(point):
        return bytes(G1_EIP2537_BYTES)
    x, y = normalize(point)
    return _fp(x) + _fp(y)


def _encode_g2(point) -> bytes:
    if is_inf(point):
        return bytes(G2_EIP2537_BYTES)
    x, y = normalize(point)
    return _fp(x.coeffs[0]) + _fp(x.coeffs[1]) + _fp(y.coeffs[0]) + _fp(y.coeffs[1])


def g1_to_eip2537(compressed: bytes) -> bytes:
    """48-byte compressed G1 point -> 128-byte EIP-2537 encoding."""
    compressed = bytes(compressed)
    if len(compressed) != 48:
        raise ValueError("compressed G1 point must be 48 bytes")
    return _encode_g1(decompress_G1(G1Compressed(int.from_bytes(compressed, "big"))))


def g2_to_eip2537(compressed: bytes) -> bytes:
    """96-byte compressed G2 point -> 256-byte EIP-2537 encoding."""
    compressed = bytes(compressed)
    if len(compressed) != 96:
        raise ValueError("compressed G2 point must be 96 bytes")
    z1 = int.from_bytes(compressed[:48], "big")
    z2 = int.from_bytes(compressed[48:], "big")
    return _encode_g2(decompress_G2(G2Compressed((z1, z2))))


def g1_generator_eip2537() -> bytes:
    return _encode_g1(G1)


def g2_generator_eip2537() -> bytes:
    return _encode_g2(G2)


def read_srs_g2_points(trusted_setup_path) -> List[bytes]:
    """Compressed G2 monomial points [tau^0]_2, [tau^1]_2, ... from trusted_setup.txt."""
    tokens = Path(trusted_setup_path).read_text().split()
    n_g1, n_g2 = int(tokens[0]), int(tokens[1])
    return [bytes.fromhex(t) for t in tokens[2 + n_g1:2 + n_g1 + n_g2]]


def srs_tau_g2_eip2537(trusted_setup_path) -> bytes:
    """[tau]_2 (the second G2 point of the SRS) in EIP-2537 encoding."""
    points = read_srs_g2_points(trusted_setup_path)
    if g2_to_eip2537(points[0]) != g2_generator_eip2537():
        raise ValueError("first SRS G2 point is not the G2 generator")
    return g2_to_eip2537(points[1])


def solidity_constants(trusted_setup_path) -> Tuple[str, str, str]:
    """(G1_GEN, G2_GEN, TAU_G2) as hex strings for contracts/KZGVerifier.sol."""
    return (
        g1_generator_eip2537().hex(),
        g2_generator_eip2537().hex(),
        srs_tau_g2_eip2537(trusted_setup_path).hex(),
    )


if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parents[2]
    for name, value in zip(
        ("G1_GEN", "G2_GEN", "TAU_G2"),
        solidity_constants(repo_root / "src" / "trusted_setup.txt"),
    ):
        print(f"{name} = hex\"{value}\"")
