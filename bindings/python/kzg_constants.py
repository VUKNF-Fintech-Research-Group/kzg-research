"""kzg_constants.py

Single source of truth for the BLS12-381 / EIP-4844 constants used by the
off-chain code. Import from here; do not redefine these values elsewhere.
"""

# Order r of the BLS12-381 scalar field (the G1/G2 subgroup order).
# Same value as BLS_MODULUS in c-kzg-4844 and the EIP-4844 spec.
BLS_MODULUS = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001

# Blob layout (EIP-4844).
FIELD_ELEMENTS_PER_BLOB = 4096
BYTES_PER_FIELD_ELEMENT = 32
BYTES_PER_BLOB = FIELD_ELEMENTS_PER_BLOB * BYTES_PER_FIELD_ELEMENT
BYTES_PER_COMMITMENT = 48
BYTES_PER_PROOF = 48

# Generator of the multiplicative group of the scalar field, as in c-kzg-4844.
PRIMITIVE_ROOT_OF_UNITY = 7

# r - 1 must be divisible by the domain size for the root of unity to exist.
assert (BLS_MODULUS - 1) % FIELD_ELEMENTS_PER_BLOB == 0
