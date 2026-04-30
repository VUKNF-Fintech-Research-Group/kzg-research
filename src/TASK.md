# Task: Implement baseline comparison experiment on Hoodi testnet

## Context

This repository implements a KZG polynomial commitment based credential
revocation method (KZGRevocation.sol) benchmarked on the Hoodi Ethereum
testnet. The current performance evaluation compares gas consumption against
BAAS, which ran on a local EVM — not Hoodi. This task adds a controlled
apples-to-apples baseline by deploying a Merkle-tree-based revocation
verifier on the same Hoodi testnet and running identical benchmark scenarios
against both contracts.

The target paper section is Section 5 (Performance evaluation). Results will
populate a new Table comparing KZG vs Merkle on identical infrastructure.

---

## Goal

Deploy a minimal Merkle-tree revocation verifier on Hoodi and run the same
benchmark suite already used for KZGRevocation.sol, so that gas cost and
latency comparisons are made on identical network conditions.

---

## Step 1 — Implement MerkleRevocation.sol

Create `contracts/MerkleRevocation.sol`.

The contract must:
- Store a single bytes32 Merkle root representing the revocation set
- Expose `updateRoot(bytes32 newRoot)` restricted to contract owner
  (mirrors `updateCommitment()` in KZGRevocation.sol)
- Expose `verifyNonRevocation(bytes32 leaf, bytes32[] calldata proof)`
  which verifies a standard binary Merkle inclusion proof using
  OpenZeppelin's MerkleProof library and returns true if the leaf
  is NOT present in the revocation tree (i.e. proof fails = not revoked)
- Emit a `RootUpdated(bytes32 newRoot)` event on every root update

Use OpenZeppelin MerkleProof for the verification logic:
`@openzeppelin/contracts/utils/cryptography/MerkleProof.sol`

The contract must NOT use any pairing precompile. Verification must rely
solely on repeated SHA-256 or keccak256 hashing up the tree path.

Credential identifiers are bytes32 values (same domain as KZG index space).

---

## Step 2 — Write the off-chain Merkle helper

Create `scripts/merkleHelper.js` (or `.ts` if the repo uses TypeScript).

This script must expose the following functions for use in benchmarks:
```js
buildTree(leaves)
// takes array of bytes32 credential IDs
// returns { root, tree } where tree supports proof generation

getProof(tree, leaf)
// returns bytes32[] Merkle proof for a given leaf

getRevocationProof(tree, revokedLeaves, queryLeaf)
// returns proof that queryLeaf is NOT in revokedLeaves
// (i.e. build tree of revoked set, show queryLeaf not present)
```

Use the `merkletreejs` npm package with keccak256 as the hash function,
consistent with OpenZeppelin's MerkleProof library expectations.

---

## Step 3 — Write the benchmark script

Create `scripts/benchmarkBaseline.js`.

This script must reproduce the exact same experimental parameters used
in the existing KZG benchmark:

### Scenario A — Non-revocation verification gas and latency

For each tree depth in {2, 4, 8, 10, 12} (corresponding to leaf counts
of 4, 16, 256, 1024, 4096 — matching the KZG degree sweep):

1. Build a Merkle tree of `2^depth` credential leaves
2. Call `updateRoot(root)` and record gas + confirmation time
3. Generate a non-revocation proof for a leaf not in the revocation set
4. Call `verifyNonRevocation(leaf, proof)` and record gas + confirmation time
5. Repeat each measurement 5 times and report the median

### Scenario B — Batch revocation efficiency

For batch sizes {10, 25, 50, 75, 100}:

1. Incremental: call `updateRoot()` once per revoked credential, record
   total gas and transaction count
2. Batch: rebuild the full tree with all revocations and call `updateRoot()`
   once, record total gas and transaction count
3. Report gas/revocation and efficiency gain for both strategies

### Output format

Write results to `results/baseline_merkle.json` in this structure:
```json
{
  "scenario_a": [
    {
      "depth": 8,
      "leaf_count": 256,
      "updateRoot_gas": 0,
      "updateRoot_time_ms": 0,
      "verify_gas": 0,
      "verify_time_ms": 0,
      "proof_size_bytes32": 0
    }
  ],
  "scenario_b": [
    {
      "batch_size": 50,
      "incremental_total_gas": 0,
      "incremental_tx_count": 0,
      "batch_total_gas": 0,
      "batch_tx_count": 0,
      "gas_per_revocation_incremental": 0,
      "gas_per_revocation_batch": 0,
      "efficiency_gain_pct": 0
    }
  ]
}
```

---

## Step 4 — Write the comparison reporter

Create `scripts/compareResults.js`.

This script must:

1. Load `results/baseline_merkle.json` and the existing KZG results
   (use whatever JSON file the existing benchmark already produces,
   or hardcode the Table 2 values from the paper if no JSON exists yet)
2. Print a side-by-side comparison table to stdout in this format:
```
Degree / Depth | KZG updateCommitment | Merkle updateRoot | KZG verify | Merkle verify | Merkle proof size
-------------- | -------------------- | ----------------- | ---------- | ------------- | -----------------
2 / 2          | 41,041               | ???               | 44,891     | ???           | 1 × bytes32
16 / 4         | 41,041               | ???               | 44,879     | ???           | 4 × bytes32
256 / 8        | 41,053               | ???               | 44,903     | ???           | 8 × bytes32
1024 / 10      | 41,053               | ???               | 44,903     | ???           | 10 × bytes32
4096 / 12      | 41,053               | ???               | 44,903     | ???           | 12 × bytes32
```

3. Flag any result where Merkle verify gas exceeds KZG verify gas with
   a `[KZG wins]` label, and any where Merkle is cheaper with `[Merkle wins]`

---

## Step 5 — Add Hardhat deploy script

Create `scripts/deployMerkle.js`.

Deploy `MerkleRevocation.sol` to Hoodi using the same deployer account
already configured for KZGRevocation.sol. Print the deployed contract
address and write it to `deployments/merkle_hoodi.json`:
```json
{
  "network": "hoodi",
  "contract": "MerkleRevocation",
  "address": "0x...",
  "deployedAt": "2026-04-02T..."
}
```

---

## Step 6 — Write tests

Create `test/MerkleRevocation.test.js`.

Cover:
- `updateRoot()` reverts if called by non-owner
- `updateRoot()` emits `RootUpdated` event
- `verifyNonRevocation()` returns true for a leaf not in the revocation tree
- `verifyNonRevocation()` returns false for a leaf that IS in the revocation tree
- Gas usage for `verifyNonRevocation()` is recorded and logged per proof depth

---

## Acceptance criteria

- [ ] `npx hardhat test test/MerkleRevocation.test.js` passes with 0 failures
- [ ] `npx hardhat run scripts/deployMerkle.js --network hoodi` deploys
      successfully and writes `deployments/merkle_hoodi.json`
- [ ] `npx hardhat run scripts/benchmarkBaseline.js --network hoodi`
      completes and writes `results/baseline_merkle.json` with no null values
- [ ] `node scripts/compareResults.js` prints the comparison table to stdout
- [ ] Proof size (in number of bytes32 elements) is reported for each depth
      in `baseline_merkle.json` — this is a key differentiator vs KZG's
      constant 48-byte witness
- [ ] No modification to existing KZGRevocation.sol or its existing tests

---

## Key expected finding to surface

KZG verification gas should be constant (~44,903) regardless of registry size.
Merkle verification gas will grow with tree depth because each additional
hash in the proof path costs approximately 200–300 gas. At depth 12
(4096 leaves) the Merkle verifier is expected to consume roughly
12 × 300 + base ≈ 6,000+ gas for the proof traversal alone, on top of
the fixed call overhead. The comparison table must make this scaling
difference visible. This is the core experimental result that validates
the KZG scalability claim in the paper.

---

## Dependencies to install if not already present
```bash
npm install merkletreejs
npm install @openzeppelin/contracts
```

---

## Notes for Claude Code

- Match the existing code style in the repo (variable naming, import paths,
  use of ethers.js v5 or v6 depending on what is already installed)
- The Hoodi network config is already in hardhat.config.js — do not modify it
- Re-use the existing deployer private key setup from hardhat.config.js
- The existing benchmark for KZG is the reference for structure and style —
  follow it closely so results are directly comparable
- Do not add any new npm scripts to package.json without checking for
  conflicts with existing entries first
```

---

**Option B — as a GitHub Issue body** (paste directly into a new issue)

---

**Title:** `feat: Merkle baseline comparison on Hoodi testnet for Section 5`

**Labels:** `experiment`, `benchmarking`, `good first issue for Claude Code`
```
## Summary
The current performance evaluation compares KZG gas costs against BAAS,
which ran on a local EVM. This issue adds a controlled baseline by deploying
a Merkle-tree revocation verifier on the same Hoodi testnet and running
identical benchmarks, enabling a fair apples-to-apples comparison for the paper.

## Deliverables
See TASK.md in the repo root for full implementation spec.

## Why this matters
Without a same-network baseline, reviewers can reasonably argue that
the gas advantage over BAAS reflects testnet differences rather than
cryptographic design. A Merkle verifier on Hoodi provides a legitimate
controlled comparison that isolates the KZG vs Merkle cost difference
independently of network conditions.

## Expected result
KZG verify: ~44,903 gas (constant across all degrees)
Merkle verify: grows ~200–300 gas per tree depth level
At 4096 credentials (depth 12): Merkle ≈ 6,000+ gas vs KZG ≈ 44,903 gas
Note: KZG carries a higher base cost due to the pairing precompile,
but this cost does NOT scale — Merkle costs WILL scale, and this
crossover point is the key finding the experiment must surface.

## Files to create
- contracts/MerkleRevocation.sol
- scripts/merkleHelper.js
- scripts/benchmarkBaseline.js
- scripts/compareResults.js
- scripts/deployMerkle.js
- test/MerkleRevocation.test.js
- results/baseline_merkle.json (generated, not committed)
- deployments/merkle_hoodi.json (generated, not committed)