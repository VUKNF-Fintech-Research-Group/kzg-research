# Superseded files

Files moved here are no longer used. They are kept until the repository owner
approves deleting them.

- `bindings/python/`: the custom c-kzg Python extension build (`ckzg_wrap.c`,
  `Makefile`, upstream `tests.py`, `README.md`). Replaced by the `ckzg` package
  from PyPI, pinned in `requirements.txt` (audit task T7).
- `contracts/`: the pre-audit contracts. `KZGRevocation.sol` (contract
  `KZGRevocationFixed`) forwarded a 160-byte compressed payload to a
  configurable pairing address and never ran a real pairing check.
  `KZGVerifier.sol` / `KZGVerifier_flattened.sol` only forwarded caller-built
  bytes. `AlwaysTruePairing.sol` and `MockPairing.sol` are pairing mocks; the
  new contract hard-codes the EIP-2537 precompiles, so no mock can be linked
  in (audit task T2).
- `scripts/`: helpers tied to the old contracts and their payload format
  (`benchmark_update_commitment_gas.py`, `hoodi_revocation_helper.py`,
  `encode_constructor_manual.js`). Replaced by `bindings/python/eip2537.py` and
  `scripts/gen_kzg_fixtures.py`.
