# eval/ — EXP-001 same-harness benchmark

Same-harness gas benchmark of credential-revocation verifiers (evaluation plan of 13 Nov 2026).
Status: **S1 (Merkle, revealed ID) and S2 (KZG, revealed ID) on Hardhat only.** S3–S6 are not in this repository yet.

## Run (from the repo root)

```bash
.venv/bin/pip install -r eval/requirements.txt
npm run eval:inputs     # deterministic inputs -> eval/data/inputs/ (~1 min)
npm run eval:smoke      # EIP-2537 precompile smoke test (Hardhat step 2)
npm run eval:verify     # E1 verify gas, E7 negatives, Q7 determinism, Q11 real path
npm run eval:revoke     # E3 update gas and S2 batch
npm run eval:report     # aggregate -> qc -> plot -> results.md
```

## Layout

| Path | Contents |
|---|---|
| `config/` | `sizes.json` (N, seed, repetitions), `sut.json` (designs and status), `networks.json`, `cost.json` (fixed gas-price grid and ETH price) |
| `scripts/` | `gen_inputs.py`, `smoke.js`, `sweep_verify.js`, `sweep_revoke.js`, `aggregate.py`, `qc.py`, `plot.py`, `report.py`, `lib/evalUtils.js` |
| `data/inputs/` | Generated inputs (handles, commitments, proofs, negative cases) |
| `data/raw/` | One JSONL per run: a header line, then one line per transaction |
| `data/processed/` | Tidy CSVs, QC JSON |
| `figures/` | V1, V2, V7 as PNG (300 dpi), SVG and CSV |
| `reports/` | `results.md`, `qc-report.md`, `manifest.json` |
| `../contracts/eval/PrecompileProbe.sol` | Test-only probe for the smoke test |

## Rules kept from the plan
- Real transactions only; the logged result is asserted before gas is recorded; negatives are kept apart.
- Real EIP-2537 precompiles only: scripts refuse to run if code sits at 0x0b–0x11.
- No hand-typed numbers: `results.md` is generated from the CSVs.
- Every raw row records run ID, commit (with `-dirty`), network and tx hash.
