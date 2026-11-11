# CLAUDE.md

Guidance for Claude Code (and other contributors) working in this repository.

> **This is a PUBLIC repository.** Everything committed here is visible to anyone.
> Read the [Security & Privacy](#security--privacy-read-before-every-commit) section before any `git add`, commit or push.

## What this project is

Research artifact for the paper *"KZG Polynomial Commitment for Shared SSI Revocation"*.
It compares two on-chain credential-revocation schemes on Ethereum (Hoodi testnet + Hardhat in-process EVM):

- **KZG polynomial commitments** (BLS12-381, EIP-4844 trusted setup): the revoked set is encoded as the roots of a polynomial; the chain stores a 48-byte commitment and verifies a constant 160-byte payload. O(1) gas.
- **Merkle tree baseline** (keccak256, OpenZeppelin `MerkleProof`): stores a 32-byte root, proof size grows with depth. O(depth) gas.

Headline results are in [README.md](README.md); raw numbers are in [results/](results/).

## Repository layout

| Path | Contents |
|------|----------|
| [contracts/](contracts/) | Solidity sources |
| `contracts/KZGRevocation.sol` | Contract `KZGRevocationFixed`: stores commitment, `updateCommitment()` (owner-only), `verifyNonRevocation(payload)`, where payload = `commit(48) ‖ proof(48) ‖ z(32) ‖ y(32)`. Checks the payload commitment matches the stored one, forwards to the pairing address, and treats `y != 0` as not revoked. |
| `contracts/KZGVerifier.sol` / `KZGVerifier_flattened.sol` | Thin wrapper that forwards pre-encoded input to a pairing precompile (Hoodi BLS12-381 pairing at `0x…12`). The flattened file pins solc **0.8.19** (used for explorer verification). |
| `contracts/MerkleRevocation.sol` | Merkle baseline: `updateRoot()` (owner-only), `verifyNonRevocation(leaf, proof)`, `RootUpdated` event. |
| `contracts/AlwaysTruePairing.sol`, `MockPairing.sol` | **Test mocks only.** They make the pairing check pass without the precompile. Never deploy them as a real verifier. |
| [scripts/](scripts/) | Benchmarks and helpers (JS for Hardhat, Python for off-chain KZG) |
| `scripts/benchmarkUpdateCommitmentGas.js` | KZG gas sweep over degrees {2,16,256,1024,4096} → `results/gas_sweep_update_commitment.json` |
| `scripts/benchmarkBaseline.js` | Merkle Scenario A (depth sweep {2,4,8,10,12}) + Scenario B (batch sizes) → `results/baseline_merkle.json` |
| `scripts/compareResults.js` | Pure Node: prints the KZG vs Merkle table from the results JSON |
| `scripts/deployMerkle.js` | Deploys `MerkleRevocation` and writes `deployments/merkle_<network>.json` |
| `scripts/merkleHelper.js` | `buildTree`, `getProof`, `getRevocationProof` (merkletreejs, keccak256, sorted pairs; matches OZ) |
| `scripts/kzg_helper.py`, `hoodi_revocation_helper.py` | Off-chain KZG proof generation / precompile input encoding (via Python bindings) |
| `scripts/benchmark_update_commitment_gas.py` | Python/web3 variant of the KZG gas sweep against a local node |
| [src/](src/) | Vendored **c-kzg-4844** C library (`ckzg.c`, `eip4844/`, `eip7594/`, `common/`, `setup/`) plus `benchmark_kzg_timing.c` (off-chain timing) and `trusted_setup.txt` |
| `src/TASK.md` | Original spec for the Merkle baseline experiment (historical context) |
| [bindings/python/](bindings/python/) | c-kzg Python bindings + `oneProofOffChain_KZG.py` (revocation polynomial builder, commit/prove/verify, incremental vs batch benchmark) |
| [inc/](inc/) | blst headers. `lib/libblst.a` is a local prebuilt library (gitignored) |
| [test/](test/) | `MerkleRevocation.test.js` (Hardhat + chai) |
| [results/](results/) | Benchmark outputs used in the paper. Treat them as data of record and don't overwrite them casually. |
| [deployments/](deployments/) | Public deployment records (contract address, timestamp) |

## Common commands

```bash
npm install

npm test                    # npx hardhat test
npm run benchmark           # KZG gas sweep on in-process Hardhat network
npm run benchmark:merkle    # Merkle baseline on Hardhat network
npm run compare             # print comparison table

# Live Hoodi testnet (needs PRIVATE_KEY in contracts/.env, see below)
npx hardhat run scripts/deployMerkle.js --network hoodi
npx hardhat run scripts/benchmarkBaseline.js --network hoodi

# Python bindings (build + test)
make -C bindings/python
```

Notes / gotchas:
- Hardhat compiles with solc 0.8.20 and 0.8.19, optimizer on (200 runs). See `hardhat.config.js`.
- Gas on the `hardhat` network uses `AlwaysTruePairing`, so it **excludes** the ~43k-gas BLS12-381 pairing precompile cost. Live-network figures come from `results/hoodi_kzg_test_results.json`.
- The root `Makefile` and `src/Makefile` are inherited from upstream c-kzg-4844. Several targets (other language bindings, `src/test/tests.c`, the `blst` submodule) are **not present** in this repo, so `make -C src test` will not work as-is. `benchmark_kzg_timing.c` has no Makefile target; build it manually against `../lib/libblst.a` with `-I. -I../inc`, and run it from `src/` (it opens `trusted_setup.txt` from the CWD).
- The RPC env var is `HOODI_RPC` (read by `hardhat.config.js`). Some script comments say `HOODI_RPC_URL`, but that name is not read. It defaults to the public endpoint `https://rpc.hoodi.ethpandaops.io`.
- KZG security bound: polynomial degree ≤ 4,095 (EIP-4844 setup). Scale horizontally with more polynomials, never by raising the degree.
- The Nov 2026 audit found that the committed `results/*.json` and the current `KZGRevocation.sol` do not run a real pairing check. They are being fixed and re-measured on the `fix/audit-2026-11` branch. Change contracts or results only as part of that work or at the author's explicit request, and move superseded files to `_to_delete/` instead of deleting them.

## Code style

- JS: CommonJS (`require`), **ethers v6** API (`ethers.keccak256`, `ethers.toBeHex`, `getSigners()`), Hardhat 2.x. Keep the existing header-comment style (purpose, run command, outputs).
- Solidity: SPDX `Apache-2.0`, pragma `^0.8.19`, `onlyOwner` modifier pattern, emit an event on every state change.
- Python: stdlib + the local bindings via `sys.path.insert(... 'bindings/python')`.
- C under `src/` is upstream code. Avoid editing it unless the change is necessary, and keep the strict warning flags clean.

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

- `AlwaysTruePairing` and `MockPairing` accept forged proofs. They exist for gas benchmarking only and must never back a real deployment.
- Deployments here are research prototypes on a testnet. They are unaudited and not for production or mainnet use.
- Keep owner-only access control on `updateCommitment` / `updateRoot`, and keep the commitment-match check in `verifyNonRevocation`. Removing either one is a security regression.
