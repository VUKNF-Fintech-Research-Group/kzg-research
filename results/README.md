# Results

Benchmark outputs for the KZG revocation contract and the Merkle baseline. Every figure below can be traced to a transaction hash in the JSON files or to a script run.

| File | Produced by | Contents |
|---|---|---|
| `kzg_gas_sweep_hoodi.json` | `scripts/benchmarkUpdateCommitmentGas.js --network hoodi` | KZG degree sweep and batch sweep on the Hoodi testnet |
| `merkle_baseline_hoodi.json` | `scripts/benchmarkBaseline.js --network hoodi` | Merkle depth sweep and batch sweep on Hoodi |
| `kzg_gas_sweep_hardhat.json`, `merkle_baseline_hardhat.json` | the same scripts with `--network hardhat` | Local reference runs (Prague hardfork) |
| `offchain_timing.csv`, `offchain_timing_meta.json` | `scripts/benchmark_offchain_timing.py` | Off-chain time per step, with the machine description |

The Hoodi runs were made on 2026-11-11 from commit `c29cd13` with the real EIP-2537 precompiles (`pairing_backend: "eip2537"`), 5 samples per measurement. The result files record 376 measured KZG transactions and 371 measured Merkle transactions.

## Deployed contracts (Hoodi, source verified)

- **KZGRevocation**: [`0x24fFED6Ff447c457829cce7c1F3Ec6C766c40fAa`](https://hoodi.etherscan.io/address/0x24fFED6Ff447c457829cce7c1F3Ec6C766c40fAa), 869,940 gas to deploy, source verification: verified
- **MerkleRevocation**: [`0xb6fC7e264Cf5e6d4d682Ac0d779E3A4297650C4c`](https://hoodi.etherscan.io/address/0xb6fC7e264Cf5e6d4d682Ac0d779E3A4297650C4c), 334,004 gas to deploy, source verification: verified

The benchmarks deploy their own instances of the same bytecode, one per degree, so that each measurement starts from a known commitment. Their addresses are in the result files.

## KZG gas by number of revoked IDs (Hoodi, median of 5)

| Revoked IDs (degree) | updateCommitment | Verify, non-revoked (`ok = true`) | Verify, revoked (`ok = false`) | Example verify transaction |
|---:|---:|---:|---:|---|
| 2 | 49,193 | 179,043 | 179,043 | [`0x7075c00d…`](https://hoodi.etherscan.io/tx/0x7075c00d84543b2c5e141f641e726a9b0c83851b12f3af2578ba4e602c03e878) |
| 16 | 49,205 | 179,175 | 179,043 | [`0x9a5b6cd0…`](https://hoodi.etherscan.io/tx/0x9a5b6cd0a8ca0110a00eff68d6d180596fb1bdeac8c9467e31505351bf2fbde0) |
| 256 | 49,205 | 179,439 | 179,043 | [`0x1a32a29f…`](https://hoodi.etherscan.io/tx/0x1a32a29f979d9cf7e533a4510814e57179a7dc025140f8ccb2232f62541e9f6b) |
| 1024 | 49,193 | 179,439 | 179,031 | [`0x05fd600c…`](https://hoodi.etherscan.io/tx/0x05fd600c6202a15c2aa12cdb2602422fa719b2661865e33bdb604dff6c4b3358) |
| 4095 | 49,193 | 179,439 | 179,031 | [`0xb690dafa…`](https://hoodi.etherscan.io/tx/0xb690dafa9d7ce5dc22c1f1e251db0dd82f48ef72e42b5087311413870be28a6f) |

The commitment is stored in 128 bytes (48 compressed). A proof is a 128-byte witness (48 compressed) plus z and y, 32 bytes each. The small differences between rows come from the number of zero bytes in the calldata.

## Merkle baseline gas by tree depth (Hoodi, median of 5)

| Depth | Revoked IDs | updateRoot | Verify, non-revoked | Proof size | Example verify transaction |
|---:|---:|---:|---:|---:|---|
| 2 | 3 | 28,036 | 28,696 | 128 B | [`0xb9297121…`](https://hoodi.etherscan.io/tx/0xb9297121f0c67912f627fee5f8e4d1544b1b0cb50e6c16a5c5b9fa8f641137ec) |
| 4 | 15 | 28,036 | 30,320 | 192 B | [`0x280f72ae…`](https://hoodi.etherscan.io/tx/0x280f72aea5d8f7e6fd941d2269647fcf26c40f05aab6b4ba5059c544182b48aa) |
| 8 | 255 | 28,036 | 33,672 | 320 B | [`0xbfb2c23f…`](https://hoodi.etherscan.io/tx/0xbfb2c23f22a167d15b0143e1c2e83ea48e440b10cafc6aba1a56ed9ee6ffe990) |
| 10 | 1,023 | 28,036 | 35,680 | 384 B | [`0x0b5a12cb…`](https://hoodi.etherscan.io/tx/0x0b5a12cbcfc7a51bb883ac462e10020b3a5ce0c0e49168a547e210dbdd255e27) |
| 12 | 4,095 | 28,024 | 38,300 | 448 B | [`0xfc185438…`](https://hoodi.etherscan.io/tx/0xfc185438ace855eb1992ed292fef6325a4d6a2e47e6608a451d4567d2dc01cc9) |

The gas of a rejected (revoked) Merkle verification is not comparable: the contract returns early when the ID is not strictly inside the supplied range.

## Batch revocation (Hoodi)

Revoking k IDs with k updates, one per ID, or with a single update. Gain = 1 − (batch gas ÷ k) ÷ single-update gas.

| k | KZG: k updates | KZG: 1 update | KZG gas per revocation | KZG gain | Merkle: k updates | Merkle: 1 update | Merkle gas per revocation | Merkle gain |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 49,181 | 49,181 | 49,181 | 0% | 28,036 | 28,036 | 28,036 | 0% |
| 10 | 491,990 | 49,205 | 4,921 | 90% | 280,348 | 28,036 | 2,804 | 90% |
| 25 | 1,229,993 | 49,205 | 1,968 | 96% | 700,852 | 28,036 | 1,121 | 96% |
| 50 | 2,459,974 | 49,193 | 984 | 98% | 1,401,692 | 28,036 | 561 | 98% |
| 75 | 3,690,039 | 49,193 | 656 | 98.67% | 2,102,580 | 28,036 | 374 | 98.67% |
| 100 | 4,920,032 | 49,193 | 492 | 99% | 2,803,444 | 28,036 | 280 | 99% |

Worked example, KZG with k = 100: batch gas 49,193, single-update gas 49,205, so the gain is 1 − (49,193 ÷ 100) ÷ 49,205 = 99%. The on-chain cost of an update does not depend on how many IDs it revokes, in either scheme; the gain is entirely from sending fewer transactions.

## Checks applied to every run

The benchmark scripts stop with an error, and write no file, unless all of these hold:

| Check | Result on Hoodi |
|---|---|
| `Verified` event says `ok = true` for a non-revoked ID | 25 of 25 KZG verifications |
| `Verified` event says `ok = false` for a revoked ID | 25 of 25 KZG verifications |
| A valid KZG verification uses at least 123,900 gas (21,000 base + 102,900 for a 2-pair pairing check) | lowest measured: 179,043 |
| Wrong y and wrong witness are rejected (negative controls) | `ok = false` at every degree |
| On-chain result equals the off-chain `verify_kzg_proof` result for the same (C, z, y, w) | match at every degree |
| y from c-kzg equals an independent evaluation of ∏(z − id) mod r | asserted when the inputs are generated |
| `gasUsed` equals fee ÷ effective gas price | holds for every transaction sent, including deployments and resets |
| Merkle: a non-revoked ID with a real proof logs `notRevoked = true`; a revoked ID logs `false`, also with a dummy proof | holds at every depth |
| No contract code at the precompile addresses | checked before each KZG run |

Gas on Hoodi equals gas on the local Hardhat network for every measurement.

## Off-chain time

See `offchain_timing.csv` (mean and standard deviation in ms, 30 runs after 2 warm-ups) and the table in the top-level README.
