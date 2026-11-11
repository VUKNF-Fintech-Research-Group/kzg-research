# CLAUDE.md

Guidance for Claude Code (and other contributors) working in this repository.

> **This is a PUBLIC repository.** Everything committed here is visible to anyone.
> Read the [Security & Privacy](#security--privacy-read-before-every-commit) section before any `git add`, commit or push.

## What this project is

Research artifact for the paper *"KZG Polynomial Commitment for Shared SSI Revocation"*.
It compares two on-chain credential-revocation schemes on Ethereum (Hoodi testnet + Hardhat in-process EVM):

- **KZG polynomial commitment** (BLS12-381, EIP-4844 trusted setup): the revoked set is the roots of f(x) = ∏(x − id). The chain stores the commitment C and checks an opening (w, z, y) with the EIP-2537 precompiles. y ≠ 0 means not revoked. Gas is constant in the number of revoked IDs (about 179k).
- **Merkle tree baseline** (keccak256, OpenZeppelin `MerkleProof`): a sorted tree over the gaps between revoked IDs, with real non-membership proofs. Gas grows with depth (about 29k–38k).

Headline results are in [README.md](README.md); raw numbers are in [results/](results/).

The code was corrected after an audit in Nov 2026 (tasks T1–T8, branch `fix/audit-2026-11`). Pre-audit contracts, scripts and results are in [_to_delete/](_to_delete/): they are superseded, and are moved there instead of deleted until the author approves removal.

## Repository layout

| Path | Contents |
|------|----------|
| `contracts/KZGVerifier.sol` | Library. Hard-coded EIP-2537 addresses (G1MSM `0x0c`, G2MSM `0x0e`, pairing `0x0f`), G1/G2 generators and [τ]₂ as constants. `verify` (one 3-term G1MSM + pairing) and `verifyWithG2Msm` (textbook form, kept for cross-checks). Reverts on non-canonical scalars, bad lengths or a failing precompile. |
| `contracts/KZGRevocation.sol` | Stores C uncompressed (128 bytes). `updateCommitment()` (owner-only), `checkNonRevocation(w, z, y)` (view), `verifyNonRevocation(w, z, y)` (emits `Verified(caller, ok, z, y)`). |
| `contracts/MerkleRevocation.sol` | Range-leaf tree: leaf = hash of (lo, hi) for neighbouring revoked IDs, sentinels 0 and r − 1. `verifyNonRevocation(id, lo, hi, proof)` is true only if lo < id < hi and the leaf is in the tree. |
| `contracts/test/` | Test-only harness contracts. |
| `bindings/python/kzg_constants.py` | The single definition of the scalar modulus r (`BLS_MODULUS`) and blob sizes. Never redefine these elsewhere. |
| `bindings/python/oneProofOffChain_KZG.py` | Off-chain KZG on the PyPI `ckzg` package: `build_revoked_poly`, `coeffs_to_blob` (converts coefficients to the evaluation form c-kzg expects), commit / prove / verify wrappers, accumulator class. |
| `bindings/python/eip2537.py` | Compressed points (48/96 bytes) → EIP-2537 encoding (128/256 bytes). Prints the Solidity constants. |
| `scripts/gen_kzg_fixtures.py` | Generates real commitments and proofs into `test/fixtures/`. Deterministic; a pytest fails if the committed fixtures are stale. |
| `scripts/benchmarkUpdateCommitmentGas.js` + `scripts/lib/kzgGasSweep.js` | KZG gas sweep over degrees {2, 16, 256, 1024, 4095} → `results/kzg_gas_sweep_<network>.json`. |
| `scripts/benchmarkBaseline.js` + `scripts/lib/merkleSweep.js` | Merkle depth sweep and batch sweep → `results/merkle_baseline_<network>.json`. |
| `scripts/lib/benchUtils.js` | Shared benchmark helpers (assertions, fee reconciliation, median, commit hash). |
| `scripts/merkleHelper.js` | `buildRevocationTree`, `getNonRevocationProof`, `proofForLeaf` (merkletreejs, keccak256, sorted pairs). |
| `scripts/benchmark_offchain_timing.py` | Off-chain timing per step and d → `results/offchain_timing.csv` + metadata JSON. |
| `scripts/compareResults.js` | Pure Node: KZG vs Merkle table from the result files of one network. |
| `scripts/deployMerkle.js` | Deploys `MerkleRevocation` and writes `deployments/merkle_<network>.json`. |
| `test/*.test.js` | Hardhat + chai tests, run against the real precompiles (hardfork `prague`). |
| `test/python/` | pytest: modulus, evaluation-form encoding, Solidity constants vs the SRS, fixtures, timing smoke test. |
| `test/fixtures/` | Generated proofs. Do not edit by hand; run `npm run fixtures`. |
| `src/trusted_setup.txt` | EIP-4844 trusted setup (the SRS). [τ]₂ is its second G2 point. |
| `src/` (other files), `inc/` | Vendored, unbuilt copy of c-kzg-4844. Nothing in the repo compiles it; the Python code uses the PyPI `ckzg` wheel. |
| [results/](results/) | Benchmark outputs. Each file records backend, network, commit and date. |
| [deployments/](deployments/) | Public deployment records (contract address, timestamp). |

## Common commands

```bash
npm install
python3 -m venv .venv && source .venv/bin/activate && pip install -r requirements.txt

npm test                     # Hardhat tests
npm run test:py              # pytest test/python
npm run fixtures             # regenerate test/fixtures/*.json
npm run benchmark            # KZG gas sweep on the Hardhat network
npm run benchmark:merkle     # Merkle baseline on the Hardhat network
npm run compare              # comparison table (add a network name after `--`)
npm run benchmark:offchain   # off-chain timing, about 2 minutes

# Live Hoodi testnet (needs PRIVATE_KEY in contracts/.env, see below)
npx hardhat run scripts/benchmarkUpdateCommitmentGas.js --network hoodi
npx hardhat run scripts/benchmarkBaseline.js --network hoodi
```

Notes / gotchas:
- **Reported numbers must come from the real precompiles.** There is no pairing mock in `contracts/`, and none may be added to a benchmark path. The benchmarks assert the logged result (`ok` / `notRevoked`) of every transaction before recording gas, and exit non-zero on any mismatch. Keep that property when changing them. A valid KZG verification can never cost less than 123,900 gas.
- **Blob encoding:** c-kzg reads a blob as evaluations over the bit-reversed 4096th roots of unity, not as coefficients. Always go through `coeffs_to_blob` / `revoked_ids_to_blob`.
- **Point encoding:** EIP-2537 wants uncompressed points with 64-byte coordinates, and G2 as x.c0 ‖ x.c1 ‖ y.c0 ‖ y.c1 (the compressed form has c1 first). Use `eip2537.py`.
- **Degree bound:** at most 4,095 revoked IDs per polynomial. The Python code raises `ValueError` above that.
- Hardhat compiles with solc 0.8.20, optimizer on (200 runs), and the `hardhat` network uses `hardfork: "prague"`. Without Prague the precompiles do not exist.
- If a constant in `KZGVerifier.sol` or a fixture changes, the pytest suite must still pass: it checks both against `src/trusted_setup.txt`.
- The RPC env var is `HOODI_RPC` (read by `hardhat.config.js`). It defaults to the public endpoint `https://rpc.hoodi.ethpandaops.io`.
- Result files written from a working tree with uncommitted changes get a `-dirty` commit suffix. Commit the code first, then run the benchmark, then commit the results.
- CI (`.github/workflows/ci.yml`) runs both test suites and the benchmark self-checks.

## Code style

- JS: CommonJS (`require`), **ethers v6** API, Hardhat 2.x. Keep the existing header-comment style (purpose, run command, outputs).
- Solidity: SPDX `Apache-2.0`, pragma `^0.8.20`, custom errors, owner-only state changes, an event on every state change.
- Python: stdlib, `ckzg` and `py_ecc`, with the local modules imported via `sys.path.insert(... 'bindings/python')`.

## Security & Privacy (read before every commit)

This repo is public and talks to a live testnet with a funded deployer key. Treat leaking a secret as an incident: rotating the key is the only fix, because git history and forks keep everything.

### Never commit or push

- **Private keys / mnemonics / seed phrases** of any kind (EOA keys, deployer keys, hardware-wallet exports, keystore JSON files).
- **`.env` files**: `contracts/.env` holds `PRIVATE_KEY` (and optionally `HOODI_RPC`). It is gitignored. Never un-ignore it, `git add -f` it, copy its contents into another file, or print it.
- **API keys / RPC URLs with embedded tokens** (Infura, Alchemy, QuickNode, Etherscan API keys, etc.). Keep them in `.env` only and never hardcode them in `hardhat.config.js` or scripts.
- Certificates and key material: `*.pem`, `*.key`, `*.p12`, `*.pfx`, `id_rsa*`, `*.keystore`, `*.jks`, GPG private keys.
- Local tool config: `.claude/` (`settings.local.json`), `.vscode/`, `.idea/`. These are gitignored and may contain local paths or permissions.
- Build outputs and dependencies: `node_modules/`, `artifacts/`, `cache/`, `lib/`, `*.o`, `*.a`, `*.so`, `*.dylib`, `dist/`, `__pycache__/`.
- Personal or unpublished material: private paper drafts, reviewer correspondence, emails, personal notes, absolute local paths (`/Users/...`), and any personal data about real people (including credential IDs from real users).
- OS junk: `.DS_Store`, `Thumbs.db`.

### Before every commit, Claude must

1. Run `git status` and `git diff --cached` and review **every** staged file. Stage files explicitly by name and avoid `git add -A` / `git add .`.
2. Scan the staged diff for secrets, for example:
   ```bash
   git diff --cached | grep -nEi 'private[_-]?key|mnemonic|seed|secret|api[_-]?key|token|passw|BEGIN .*PRIVATE KEY|0x[0-9a-fA-F]{64}'
   ```
   A 64-hex-char value may be a private key. Stop and ask the author unless it is clearly a public hash or commitment.
3. Confirm ignored files stay ignored: `git check-ignore -v contracts/.env`.
4. Never weaken `.gitignore`, never use `git add -f` on ignored files, and never commit with `--no-verify`.
5. Only commit or push when the author asks. Never force-push `main`.

### Handling secrets at runtime

- Never `cat`, `echo`, log or paste the contents of `.env` or any key file, and never put a key on a command line, where it would land in shell history. Load it through `dotenv` as `hardhat.config.js` already does.
- Scripts must not print `process.env.PRIVATE_KEY` or signer private keys. Printing the **public** deployer address is fine.
- Use a dedicated, low-value **testnet-only** key for Hoodi. Never reuse a mainnet or personal wallet key.
- Don't send repository secrets, local paths or the author's personal details to external services (web searches, pastebins, third-party APIs).

### If a secret is ever committed

Do **not** just delete it in a new commit. Tell the author immediately. They must rotate or revoke the key or token first, drain any testnet funds to a new address, and then purge it from history (e.g. `git filter-repo`) before any further push.

### Smart-contract safety notes

- Never reintroduce a configurable pairing address or a pairing mock into `contracts/`. The pre-audit mocks (`_to_delete/contracts/`) accept forged proofs.
- Deployments here are research prototypes on a testnet. They are unaudited and not for production or mainnet use.
- Keep owner-only access control on `updateCommitment` / `updateRoot`. Keep the `y != 0` and canonical-scalar checks in the KZG path, and the `lo < id < hi` check in the Merkle path. Removing any of them is a security regression.
