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
- `contracts/merkle/MerkleRevocation.sol` and `test/MerkleRevocation.test.js`:
  the pre-audit Merkle baseline, which returned "not revoked" whenever an
  inclusion proof failed, so any invalid proof passed (audit task T6).
- `src/benchmark_kzg_timing.c`: the old off-chain timing benchmark. It filled
  all 4,096 blob entries with a byte pattern for every "degree", so the degree
  had no effect on what was measured. Replaced by
  `scripts/benchmark_offchain_timing.py` (audit task T5).
- `results/`: pre-audit result files. `gas_sweep_update_commitment.json` came
  from the `AlwaysTruePairing` mock with dummy proofs, `baseline_merkle.json`
  from dummy Merkle proofs, and `hoodi_kzg_test_results.json` from the old
  contract. None of them reflects a successful on-chain verification.
  Replaced by `results/kzg_gas_sweep_<network>.json`,
  `results/merkle_baseline_<network>.json` and `results/offchain_timing.csv`.
- `Makefile`, `src/Makefile`: build files inherited from upstream c-kzg-4844.
  They expect a `blst` submodule, C tests and language bindings that this
  repository does not contain (audit task T7).
