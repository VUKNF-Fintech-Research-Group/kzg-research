# KZG Revocation Analysis

Compares two ways of publishing a credential revocation list on Ethereum:

- **KZG polynomial commitment.** The issuer commits to f(x) = ∏(x − id) over the revoked IDs. A holder shows that credential z is not revoked by opening f at z to a value y ≠ 0. The contract checks the opening with the BLS12-381 precompiles from [EIP-2537](https://eips.ethereum.org/EIPS/eip-2537), using the EIP-4844 trusted setup.
- **Merkle tree baseline.** A sorted tree over the gaps between revoked IDs, with a real non-membership proof.

## Status

The code was audited and corrected in November 2026. Earlier result files came from a mock pairing contract. They are kept in [`_to_delete/`](_to_delete/) for reference and must not be cited.

The gas figures below were measured on the Hoodi testnet with the real EIP-2537 precompiles. Every figure links to a transaction hash in [`results/`](results/README.md).

## Results

### On-chain gas (Hoodi testnet, median of 5)

| Revoked IDs | KZG update | KZG verify | Merkle update | Merkle verify | KZG proof | Merkle proof |
|------------:|-----------:|-----------:|--------------:|--------------:|----------:|-------------:|
| 2 / 3       | 49,193     | 179,043    | 28,036        | 28,696        | 128 B     | 128 B        |
| 16 / 15     | 49,205     | 179,175    | 28,036        | 30,320        | 128 B     | 192 B        |
| 256 / 255   | 49,205     | 179,439    | 28,036        | 33,672        | 128 B     | 320 B        |
| 1024 / 1023 | 49,193     | 179,439    | 28,036        | 35,680        | 128 B     | 384 B        |
| 4095        | 49,193     | 179,439    | 28,024        | 38,300        | 128 B     | 448 B        |

- KZG verification gas does not depend on the number of revoked IDs. Most of it is the pairing check (102,900 gas for two pairs) and one 3-term G1 multi-scalar multiplication.
- Merkle verification grows by about 900 gas per tree level and is cheaper at every size measured.
- The KZG commitment is stored uncompressed (128 bytes) because the precompiles do not accept compressed points. Its compressed form is 48 bytes. The KZG witness is likewise 128 bytes in calldata, 48 compressed.
- One polynomial holds at most 4,095 revoked IDs (the degree bound of the EIP-4844 setup).

### Batch revocation (Hoodi testnet)

An update costs the same however many IDs it revokes, so revoking k IDs in one update divides the cost per revocation by k.

| k   | KZG, k updates | KZG, 1 update | Merkle, k updates | Merkle, 1 update | Saving |
|----:|---------------:|--------------:|------------------:|-----------------:|-------:|
| 1   | 49,181         | 49,181        | 28,036            | 28,036           | 0% |
| 10  | 491,990        | 49,205        | 280,348           | 28,036           | 90% |
| 25  | 1,229,993      | 49,205        | 700,852           | 28,036           | 96% |
| 50  | 2,459,974      | 49,193        | 1,401,692         | 28,036           | 98% |
| 75  | 3,690,039      | 49,193        | 2,102,580         | 28,036           | 98.67% |
| 100 | 4,920,032      | 49,193        | 2,803,444         | 28,036           | 99% |

Source files and checks: [`results/README.md`](results/README.md). The result files record every transaction with its hash, gas and logged result. The local Hardhat network gives the same gas for every measurement.

Deployed contracts on Hoodi, source verified: KZGRevocation [`0x24fFED6Ff447c457829cce7c1F3Ec6C766c40fAa`](https://hoodi.etherscan.io/address/0x24fFED6Ff447c457829cce7c1F3Ec6C766c40fAa#code), MerkleRevocation [`0xb6fC7e264Cf5e6d4d682Ac0d779E3A4297650C4c`](https://hoodi.etherscan.io/address/0xb6fC7e264Cf5e6d4d682Ac0d779E3A4297650C4c#code). See [`deployments/hoodi.json`](deployments/hoodi.json).

### Off-chain time (ms, mean of 30 runs)

| Revoked IDs | Build blob | Commit | Prove | Verify | Witness update, 1 new | 10 new | 100 new |
|------------:|-----------:|-------:|------:|-------:|----------------------:|-------:|--------:|
| 2           | 9.4        | 25.4   | 25.6  | 0.66   | 36.5                  | –      | –       |
| 16          | 11.7       | 25.1   | 25.5  | 0.64   | 37.5                  | 37.1   | –       |
| 256         | 22.6       | 25.3   | 25.8  | 0.64   | 41.6                  | 41.2   | 47.3    |
| 1024        | 146.5      | 28.3   | 25.8  | 0.64   | 42.8                  | 44.4   | 65.8    |
| 4095        | 2,058.0    | 26.8   | 26.8  | 0.66   | 44.7                  | 54.0   | 141.3   |

Commit, prove and verify run in C (c-kzg-4844) and do not depend on the number of revoked IDs, because the blob always holds 4,096 evaluations. Building the blob runs in pure Python and grows quadratically. Standard deviations and the machine description are in [`results/offchain_timing.csv`](results/offchain_timing.csv) and [`results/offchain_timing_meta.json`](results/offchain_timing_meta.json).

## Structure

```
contracts/         KZGVerifier.sol (EIP-2537 pairing check), KZGRevocation.sol, MerkleRevocation.sol
bindings/python/   off-chain KZG: polynomial and blob encoding, EIP-2537 point encoding, constants
scripts/           benchmarks, fixture generator, Merkle tree helper, comparison table
test/              Hardhat tests (*.test.js), Python tests (python/), generated proofs (fixtures/)
results/           benchmark outputs
deployments/       testnet deployment records
src/               EIP-4844 trusted setup (trusted_setup.txt) and a vendored, unbuilt copy of c-kzg-4844
_to_delete/        superseded files, kept for reference
```

## Setup

Requires Node.js 22 or newer and Python 3.12 or newer.

```bash
npm install

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

`ckzg` (the official c-kzg-4844 bindings) is installed from PyPI. No C build is needed.

## Tests

```bash
npm test            # Solidity tests on the Hardhat network, real EIP-2537 precompiles
npm run test:py     # off-chain KZG tests
```

## Benchmarks

```bash
npm run benchmark             # KZG gas sweep      -> results/kzg_gas_sweep_hardhat.json
npm run benchmark:merkle      # Merkle baseline    -> results/merkle_baseline_hardhat.json
npm run compare               # side-by-side table
npm run benchmark:offchain    # off-chain timing   -> results/offchain_timing.csv (about 2 minutes)
```

Each gas benchmark checks the result the contract logged for every transaction before recording its gas, and exits with an error on any mismatch. The KZG benchmark only runs against the real precompiles.

To run on the Hoodi testnet, put a funded **testnet-only** key in `contracts/.env` (this file is gitignored; never commit it):

```
PRIVATE_KEY=<hex key>
HOODI_RPC=https://rpc.hoodi.ethpandaops.io
```

```bash
npx hardhat run scripts/deploy.js --network hoodi    # deploy and verify (needs ETHERSCAN_API_KEY in contracts/.env)
npx hardhat run scripts/benchmarkUpdateCommitmentGas.js --network hoodi
npx hardhat run scripts/benchmarkBaseline.js --network hoodi
node scripts/compareResults.js hoodi
```

The proofs used by the tests and the gas sweep are generated with `npm run fixtures` and committed in `test/fixtures/`.

## Security notes

- The contracts are research prototypes. They are unaudited and not intended for production use.
- A polynomial of degree above 4,095 cannot be committed with the EIP-4844 setup. Use several polynomials for larger revocation lists.
- Credential IDs are visible on-chain when a proof is verified.

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
