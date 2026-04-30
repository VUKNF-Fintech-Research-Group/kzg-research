# KZG Revocation Analysis

Compares **KZG polynomial commitments** (O(1) gas) against a **Merkle tree baseline** (O(depth) gas) for blockchain-based credential revocation, benchmarked on the Hoodi testnet with the EIP-4844 trusted setup.

## Results

### KZG vs. Merkle

| Property               | KZG                          | Merkle                    |
|------------------------|------------------------------|---------------------------|
| Verify gas             | **O(1)** — 43,026 gas        | O(depth) — 27k–32k gas    |
| Update gas             | O(1) — 39,997 gas            | O(1) — 30,075 gas         |
| Commitment size        | 48 bytes (G1 point)          | 32 bytes (keccak256)      |
| Proof size             | 160 bytes (constant)         | 32 × depth bytes          |
| Security bound         | ≤ 4,095 credentials/poly     | Unlimited                 |
| Off-chain verify       | 0.59 ms (C backend)          | Sub-ms                    |

KZG gas is constant because the commitment is always a 48-byte G1 point and the verification payload always 160 bytes, independent of polynomial degree. Merkle verification adds ~906 gas per depth level (one keccak256 per proof element).

### Merkle Batch Efficiency (Hoodi testnet)

| Batch size | Gas per revocation | Saving |
|-----------:|-------------------:|-------:|
| 1          | 30,074             | —      |
| 10         | 3,008              | 90%    |
| 50         | 602                | 98%    |
| 100        | 301                | 99%    |

## Structure

```
contracts/   KZGRevocation.sol, KZGVerifier.sol, MerkleRevocation.sol
scripts/     benchmarkUpdateCommitmentGas.js, benchmarkBaseline.js, compareResults.js
results/     gas_sweep_update_commitment.json, baseline_merkle.json, hoodi_kzg_test_results.json
src/         C implementation (c-kzg-4844)
bindings/    Python bindings
test/        MerkleRevocation.test.js
```

## Running the Benchmarks

```bash
npm install

# KZG gas sweep — no external node needed
npx hardhat run scripts/benchmarkUpdateCommitmentGas.js --network hardhat

# Merkle baseline — requires Hoodi RPC in hardhat.config.js
npx hardhat run scripts/benchmarkBaseline.js --network hoodi

# C backend timing
cd src && make benchmark_kzg_timing && ./benchmark_kzg_timing

# Merkle contract tests
npx hardhat test test/MerkleRevocation.test.js
```

## Security Note

KZG security requires degree ≤ 4,095 (EIP-4844 trusted setup bound). Gas costs are identical beyond this limit but cryptographic guarantees are not. Scale horizontally with multiple polynomials rather than increasing degree.

## License

Apache-2.0

## Citation

```bibtex
@misc{kzg_revocation_analysis_2026,
  title        = {KZG Polynomial Commitment for Shared SSI Revocation},
  author       = {Kosubiene, Gintare and Masteika, Saulius},
  year         = {2026},
  howpublished = {GitHub Repository}
}
```
