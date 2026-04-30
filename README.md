# KZG Polynomial Commitment Revocation Analysis

## Overview

Performance analysis comparing **KZG polynomial commitments** against a **Merkle tree baseline** for blockchain-based credential revocation. The study demonstrates that KZG verification is O(1) in gas cost regardless of credential set size, while Merkle verification scales O(depth).

Both systems were benchmarked on the Hoodi testnet under identical conditions using the EIP-4844 trusted setup and BLS12-381 precompile.

## Key Research Findings

- **KZG Gas Cost**: 39,997 gas (`updateCommitment`) / 43,026 gas (`verifyNonRevocation`) — constant across all polynomial degrees
- **Merkle Gas Cost**: 27,465–31,995 gas (`verifyNonRevocation`) — scales linearly with tree depth
- **C Backend Performance**: 0.59 ms `verify_kzg_proof`, 1.01 ms `verify_blob_kzg_proof`
- **Batch Savings**: up to 99% gas reduction when revocations are batched
- **Security Boundary**: Cryptographic security guaranteed up to degree 4,095 (EIP-4844 limit)

## Repository Structure

```
├── contracts/
│   ├── KZGRevocation.sol          # KZG-based revocation (main contract)
│   ├── KZGVerifier.sol            # KZG proof verification via BLS12-381 precompile
│   ├── KZGVerifier_flattened.sol  # Single-file version for deployment
│   ├── MerkleRevocation.sol       # Merkle tree baseline for comparison
│   ├── AlwaysTruePairing.sol      # Mock pairing (gas-only testing)
│   └── MockPairing.sol            # Test mock
├── scripts/
│   ├── benchmarkUpdateCommitmentGas.js   # KZG gas sweep (degrees 2–4096)
│   ├── benchmarkBaseline.js              # Merkle depth/batch benchmark
│   ├── compareResults.js                 # Cross-method comparison
│   ├── deployMerkle.js                   # Merkle contract deployment
│   ├── merkleHelper.js                   # Off-chain Merkle utilities
│   ├── kzg_helper.py                     # KZG proof generation helpers
│   └── hoodi_revocation_helper.py        # Hoodi testnet integration
├── results/
│   ├── gas_sweep_update_commitment.json  # KZG O(1) gas sweep results
│   ├── baseline_merkle.json              # Merkle depth scaling + batch results
│   └── hoodi_kzg_test_results.json       # On-chain KZG timing and gas
├── src/                           # C implementation (c-kzg-4844)
├── bindings/python/               # Python bindings
├── test/
│   └── MerkleRevocation.test.js   # Merkle contract unit tests
└── deployments/
    └── merkle_hoodi.json          # Deployed Merkle contract address
```

## Quick Start

### Prerequisites

```bash
# macOS
brew install gcc python3

# Ubuntu/Debian
sudo apt install build-essential python3 python3-pip
```

### KZG Gas Sweep (no external node needed)

```bash
npm install
npx hardhat run scripts/benchmarkUpdateCommitmentGas.js --network hardhat
```

Expected output:
```
=== KZG Gas Sweep: updateCommitment() vs verifyNonRevocation() ===
 Degree | updateCommitment gas | verifyNonRevocation gas | commit | payload
--------+---------------------+------------------------+--------+--------
      2 |              39,997 |                  43,026 |   48 B |   160 B
     16 |              39,997 |                  43,026 |   48 B |   160 B
    256 |              39,997 |                  43,026 |   48 B |   160 B
   1024 |              39,997 |                  43,026 |   48 B |   160 B
   4096 |              39,997 |                  43,026 |   48 B |   160 B

  updateCommitment()    : ✓ O(1) – identical across all degrees
  verifyNonRevocation() : ✓ O(1) – identical across all degrees
```

Both functions are O(1) because a KZG commitment is always a fixed-size 48-byte G1 point and the verification payload is always 160 bytes (`commit‖proof‖z‖y`), independent of polynomial degree.

### Merkle Baseline Benchmark (Hoodi testnet)

```bash
npx hardhat run scripts/benchmarkBaseline.js --network hoodi
```

### C Backend Benchmarking

```bash
cd src
make benchmark_kzg_timing
./benchmark_kzg_timing
```

Expected output:
```
=== KZG Non-Revocation Proof Verification Benchmark ===
| Degree  | verify_kzg_proof (ms) | verify_blob_kzg_proof (ms) | Total Avg (ms) |
|---------|-----------------------|----------------------------|----------------|
| 2       | 0.588                 | 1.020                      | 0.804          |
| 1000000 | 0.591                 | 1.025                      | 0.808          |
```

### Python Bindings

```bash
cd bindings/python
make
python3 tests.py
```

## Performance Results

### KZG — Gas Sweep (degrees 2–4,096)

| Degree | `updateCommitment` gas | `verifyNonRevocation` gas | Commitment size | Payload size |
|-------:|----------------------:|-------------------------:|----------------:|-------------:|
| 2      | 39,997                | 43,026                   | 48 B            | 160 B        |
| 16     | 39,997                | 43,026                   | 48 B            | 160 B        |
| 256    | 39,997                | 43,026                   | 48 B            | 160 B        |
| 1,024  | 39,997                | 43,026                   | 48 B            | 160 B        |
| 4,096  | 39,997                | 43,026                   | 48 B            | 160 B        |

### Merkle — Depth Scaling (Hoodi testnet)

| Depth | Leaf count | `updateRoot` gas | `verify` gas | Proof size |
|------:|-----------:|-----------------:|-------------:|-----------:|
| 2     | 4          | 30,075           | 27,465       | 2 × 32 B   |
| 4     | 16         | 30,075           | 28,371       | 4 × 32 B   |
| 8     | 256        | 30,075           | 30,183       | 8 × 32 B   |
| 10    | 1,024      | 30,075           | 31,089       | 10 × 32 B  |
| 12    | 4,096      | 30,075           | 31,995       | 12 × 32 B  |

Merkle `verifyNonRevocation` gas grows ~906 gas per depth level (one keccak256 per proof element).

### KZG vs. Merkle — Summary

| Property                  | KZG                         | Merkle                     |
|---------------------------|-----------------------------|----------------------------|
| Verify gas complexity     | **O(1)** — 43,026 gas       | O(depth) — 27k–32k gas     |
| Update gas complexity     | O(1) — 39,997 gas           | O(1) — 30,075 gas          |
| Commitment / root size    | 48 bytes (G1 point)         | 32 bytes (keccak256)       |
| Proof payload size        | 160 bytes (constant)        | 32 × depth bytes (grows)   |
| Cryptographic primitive   | BLS12-381 pairing (EIP-4844)| keccak256                  |
| Security bound            | ≤ 4,095 credentials/poly    | Unlimited (depth scales)   |
| Off-chain verify time     | 0.59 ms (C backend)         | Sub-ms (hash chain)        |

### Batch Revocation Efficiency (Merkle, Hoodi testnet)

| Batch size | Gas per revocation | vs. individual | Efficiency gain |
|-----------:|-------------------:|---------------:|----------------:|
| 1          | 30,074             | baseline       | —               |
| 10         | 3,008              | 10×            | 90%             |
| 25         | 1,203              | 25×            | 96%             |
| 50         | 602                | 50×            | 98%             |
| 100        | 301                | 100×           | 99%             |

## Research Methodology

1. **C Backend Analysis** — direct library timing with `CLOCK_MONOTONIC`, 10+ iterations
2. **KZG Gas Sweep** — `benchmarkUpdateCommitmentGas.js` on Hardhat in-process EVM (no external node), `AlwaysTruePairing` mock isolates storage/ABI overhead from pairing cost
3. **Merkle Baseline** — `benchmarkBaseline.js` on Hoodi testnet; Scenario A tests depth scaling (2–12), Scenario B tests batch amortisation (batch size 10–100)
4. **On-chain KZG** — `hoodi_revocation_helper.py` with real BLS12-381 precompile at `0x0f`

## Security Analysis

- **Secure range**: 2 ≤ degree ≤ 4,095 — covered by the EIP-4844 trusted setup ceremony
- **Beyond degree 4,095**: gas costs remain identical but cryptographic security is not guaranteed
- **Production rule**: never exceed degree 4,095; scale horizontally with multiple polynomials
- **Timing attacks**: BLS12-381 constant-time algorithms mitigate side-channel leakage

## Production Guidelines

| Parameter              | Value                                    |
|------------------------|------------------------------------------|
| Max degree             | 4,095                                    |
| Credentials/polynomial | ~4,000                                   |
| Scaling strategy       | Multiple degree-4,095 polynomials        |
| Total capacity         | Unlimited (4,000 × N polynomials)        |
| Verify gas budget      | 43,026 gas (constant)                    |

## Development Setup

```bash
# Build C library
cd src && make all && make test

# Run Merkle contract tests
npm install
npx hardhat test test/MerkleRevocation.test.js

# Deploy Merkle contract to Hoodi
npx hardhat run scripts/deployMerkle.js --network hoodi
```

## License

Apache-2.0 — see [LICENSE](LICENSE).

## Citation

```bibtex
@misc{kzg_revocation_analysis_2026,
  title   = {KZG Polynomial Commitment for Shared SSI Revocation},
  author  = {Kosubiene, Gintare and Masteika, Saulius},
  year    = {2026},
  howpublished = {GitHub Repository},
  url     = {https://github.com/[username]/kzg-revocation-analysis-public}
}
```

## References

- [EIP-4844: Proto-Danksharding](https://eips.ethereum.org/EIPS/eip-4844)
- [KZG Polynomial Commitments — Kate et al. 2010](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf)
- [BLS12-381 Curve Specification](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04)
