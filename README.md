# KZG Polynomial Commitment Revocation Analysis

## Overview

Comprehensive performance analysis of KZG polynomial commitments for blockchain based revocation systems, demonstrating **constant-time verification** across polynomial degrees 2 to 1,000,000.

## Key Research Findings

- **Constant Gas Costs**: ~33,380 gas regardless of polynomial degree (2 to 1,000,000)
- **C Backend Performance**: ~0.59ms verify_kzg_proof, ~1.01ms verify_blob_kzg_proof  
- **Security Boundaries**: Cryptographic security guaranteed up to degree 4,095 (EIP-4844 limit)

## Repository Structure

```
├── 📁 src/            # C implementation with benchmarking
├── 📁 contracts/      # Solidity smart contracts
├── 📁 scripts/        # Analysis / helper tools
├── 📁 results/        # Performance data and test results
├── 📁 bindings/       # Language bindings (Python)
```

## 🚀 Quick Start

### Prerequisites
```bash
# Install dependencies (Ubuntu/Debian)
sudo apt install build-essential python3 python3-pip

# Install dependencies (macOS)
brew install gcc python3
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
| Degree | verify_kzg_proof (ms) | verify_blob_kzg_proof (ms) | Total Avg (ms) |
|--------|----------------------|----------------------------|-----------------|
| 2      | 0.588                | 1.020                      | 0.804           |
| 1000000| 0.591                | 1.025                      | 0.808           |
```

### Helper Functions
```bash
cd scripts
python3 kzg_helper.py  # Test KZG helper functions
```

### Python Bindings
```bash
cd bindings/python
make  # Build Python bindings
python3 tests.py  # Run binding tests
```

### Gas Sweep: updateCommitment() vs verifyNonRevocation()
```bash
# No external node required – Hardhat runs an in-process EVM
npm install
npx hardhat run scripts/benchmarkUpdateCommitmentGas.js --network hardhat

# Results are saved automatically to results/gas_sweep_update_commitment.json
```

Expected output:
```
=== KZG Gas Sweep: updateCommitment() vs verifyNonRevocation() ===
 Degree | updateCommitment gas | verifyNonRevocation gas | commit | payload
--------+---------------------+------------------------+--------+--------
      2 |              35,XXX |                 33,XXX |   48 B |    160 B
     16 |              35,XXX |                 33,XXX |   48 B |    160 B
    256 |              35,XXX |                 33,XXX |   48 B |    160 B
   1024 |              35,XXX |                 33,XXX |   48 B |    160 B
   4096 |              35,XXX |                 33,XXX |   48 B |    160 B

  updateCommitment()    : ✓ O(1) – identical across all degrees
  verifyNonRevocation() : ✓ O(1) – identical across all degrees
```

Both functions are O(1) because a KZG commitment is always a fixed-size 48-byte G1
point and the verification payload is always 160 bytes (commit||proof||z||y),
independent of the polynomial degree it was computed from.

## 📈 Performance Results Summary

| Metric | Value | Scalability | Notes |
|--------|-------|-------------|--------|
| **updateCommitment() gas** | ~35,000 | O(1) Constant | 48-byte G1 point, same for all degrees |
| **verifyNonRevocation() gas** | ~33,380 | O(1) Constant | 160-byte payload, same for all degrees |
| **C verify_kzg_proof** | 0.59ms | O(1) Constant | Direct mathematical verification |
| **C verify_blob_kzg_proof** | 1.01ms | O(1) Constant | Includes Fiat-Shamir challenge |
| **End-to-End Blockchain** | 8.5s | Network bound | 99.97% network consensus time |
| **Security Limit** | Degree 4,095 | EIP-4844 bound | Cryptographically secure maximum |

## Research Methodology

### Testing Approach
1. **C Backend Analysis**: Direct library performance measurement using `CLOCK_MONOTONIC`
2. **Blockchain Analysis**: Real network testing on Hoodi with BLS12-381 precompile (0x12)
3. **Gas Sweep Experiment**: `scripts/benchmarkUpdateCommitmentGas.js` (Hardhat) measures both
   `updateCommitment()` and `verifyNonRevocation()` across degrees {2, 16, 256, 1024, 4096}
4. **Degree Scaling**: Systematic testing across degrees 2, 16, 256, 1024, 4096, 1,000,000
5. **Statistical Rigor**: 10+ iterations per test with comprehensive error analysis

### Verification Functions Compared
- **verify_kzg_proof**: Direct mathematical verification with external challenge
- **verify_blob_kzg_proof**: EIP-4844 blob verification with Fiat-Shamir challenge generation
- **updateCommitment()**: On-chain commitment rotation (admin operation, ~35k gas)
- **verifyNonRevocation()**: On-chain KZG proof verification (~33k gas, excludes precompile)

## Production Implications

### Enterprise Deployment
- **Capacity**: ~4,000 certificates per degree-4095 polynomial
- **Scaling**: Horizontal via multiple polynomials (unlimited total capacity)
- **Performance**: Predictable constant costs regardless of database size

### Blockchain Integration
- **Gas Efficiency**: 33,380 gas constant enables precise cost modeling
- **Batching Strategy**: Amortize network costs across multiple verifications

## Security Analysis

### Cryptographic Guarantees
- **Secure Degrees**: 2 ≤ degree ≤ 4,095 (EIP-4844 trusted setup bounds)
- **Insecure Degrees**: degree > 4,095 (same gas cost but compromised security)
- **Production Rule**: Never exceed degree 4,095 for real deployments

### Attack Resistance
- **Mathematical Security**: Based on discrete logarithm hardness in BLS12-381
- **Implementation Security**: Constant-time algorithms prevent timing attacks
- **Network Security**: Depends on underlying blockchain consensus mechanism

## Performance Data

The repository includes performance analysis results:

- **C Backend Results**: Direct measurement data in the benchmark output
- **Gas Analysis**: Constant 33,380 gas cost documented in research findings
- **Security Analysis**: Degree bounds and cryptographic guarantees detailed above
- **Helper Functions**: Use `scripts/kzg_helper.py` to generate and verify KZG proofs

## 🔧 Development Setup

### Building C Library
```bash
cd src
make clean
make all
make test
```

### Blockchain Testing
1. Deploy KZGVerifier contract using `contracts/KZGVerifier.sol`
2. Configure constructor with BLS12-381 pairing precompile address
3. Use `scripts/kzg_helper.py` to generate test proofs
4. Measure gas costs via smart contract calls

## 📄 Documentation

Key research findings and technical details are documented in this README. For additional information:

- Run analysis scripts in `scripts/` directory to reproduce findings
- Review C source code in `src/` for implementation details  
- Examine smart contracts in `contracts/` for blockchain integration
- Check test results in `results/` directory

## 🎓 Academic Context

This research validates KZG polynomial commitments for practical blockchain based revocation systems, proving that cryptographic verification complexity is constant regardless of certificate database size - a critical finding for enterprise adoption.

## 📜 License

Apache-2.0 - See LICENSE file for details.

## 🤝 Contributing

This is a research repository. For questions or discussions about the methodology or findings, please contact the author.

## 📧 Citation

If you use this research in your work, please cite:

```bibtex
@misc{kzg_revocation_analysis_2025,
  title={KZG Polynomial Commitment for Shared SSI Revocation},
  author={[Gintare Kosubiene; Saulius Masteika]},
  year={2025},
  howpublished={GitHub Repository},
  url={https://github.com/[username]/kzg-revocation-analysis}
}
```

## 🔗 References

- [EIP-4844: Proto-Danksharding](https://eips.ethereum.org/EIPS/eip-4844)
- [KZG Polynomial Commitments](https://www.iacr.org/archive/asiacrypt2010/6477178/6477178.pdf)
- [BLS12-381 Curve Specification](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-bls-signature-04)

---

**Research Focus**: Proving KZG verification exhibits O(1) complexity for practical blockchain revocation deployment  
**Key Result**: 33,380 constant gas cost enables predictable enterprise adoption  
**Security**: Full analysis of cryptographic boundaries and production guidelines