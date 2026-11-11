/**
 * merkleSweep.js
 *
 * Core of the Merkle baseline benchmark. Like the KZG sweep, every measured
 * verification is checked before its gas is recorded: a non-revoked ID with a
 * real non-membership proof must log notRevoked = true, and a revoked ID must
 * log notRevoked = false.
 */

const { check, median, send, findEvent } = require("./benchUtils");
const { MAX_ID, buildRevocationTree, getNonRevocationProof, proofForLeaf } = require("../merkleHelper");

async function measureVerify(contract, id, { lo, hi, proof }, expected, label) {
  const { receipt, record } = await send(contract.verifyNonRevocation(id, lo, hi, proof));
  const notRevoked = findEvent(contract, receipt, "Verified").args.notRevoked;
  check(notRevoked === expected,
    `${label}: expected notRevoked = ${expected}, the contract logged ${notRevoked} (tx ${receipt.hash})`);
  return { ...record, ok: notRevoked };
}

/** Revoked IDs 2, 4, 6, ...: odd IDs in between are not revoked. */
const evenIds = (count) => Array.from({ length: count }, (_, i) => BigInt(2 * (i + 1)));

/**
 * Scenario A: verification and update gas against tree depth.
 * Depth d means 2^d range leaves, i.e. 2^d - 1 revoked IDs.
 */
async function runDepthSweep(contract, { depths, samples = 1, breakProof = false, log = () => {} }) {
  const results = [];
  for (const depth of depths) {
    const label = `depth ${depth}`;
    const revoked = evenIds(2 ** depth - 1);
    const tree = buildRevocationTree(revoked);
    check(tree.depth === depth, `${label}: built a tree of depth ${tree.depth}`);
    // same size, one ID changed: a realistic steady-state root update
    const nextTree = buildRevocationTree([...revoked.slice(0, -1), revoked[revoked.length - 1] + 2n]);

    const validId = revoked[Math.floor(revoked.length / 2)] + 1n;
    let validProof = getNonRevocationProof(tree, validId);
    check(validProof.proof.length === depth, `${label}: proof has ${validProof.proof.length} elements`);
    if (breakProof) validProof = { ...validProof, proof: validProof.proof.map(() => "0x" + "00".repeat(32)) };

    // A revoked ID has no proof. Use the strongest attempt available: the
    // valid inclusion proof of the leaf that ends at the revoked ID.
    const revokedId = revoked[Math.floor(revoked.length / 2)];
    const attempt = proofForLeaf(tree, tree.bounds.indexOf(revokedId) - 1);

    await send(contract.updateRoot(tree.root));
    const update = [];
    const verifyValid = [];
    const verifyRevoked = [];
    for (let i = 0; i < samples; i++) {
      update.push((await send(contract.updateRoot(nextTree.root))).record);
      await send(contract.updateRoot(tree.root));
      verifyValid.push(await measureVerify(contract, validId, validProof, true, `${label} non-revoked id=${validId}`));
      verifyRevoked.push(await measureVerify(contract, revokedId, attempt, false, `${label} revoked id=${revokedId}`));
    }

    // Negative control: the pre-audit contract accepted any failing proof.
    const dummy = { lo: 0n, hi: MAX_ID, proof: validProof.proof.map(() => "0x" + "00".repeat(32)) };
    const control = await measureVerify(contract, revokedId, dummy, false, `${label} control: revoked ID with dummy proof`);

    const row = {
      depth,
      leaf_count: 2 ** depth,
      revoked_count: revoked.length,
      proof_elements: depth,
      proof_size_bytes: 32 * depth + 64, // siblings plus the (lo, hi) pair
      update_root_gas_median: median(update.map((r) => r.gas_used)),
      verify_non_revoked_gas_median: median(verifyValid.map((r) => r.gas_used)),
      verify_revoked_gas_median: median(verifyRevoked.map((r) => r.gas_used)),
      update_root_ms_median: median(update.map((r) => r.confirmation_ms)),
      verify_ms_median: median(verifyValid.map((r) => r.confirmation_ms)),
      samples: { update_root: update, verify_non_revoked: verifyValid, verify_revoked: verifyRevoked },
      negative_controls: { revoked_with_dummy_proof: control },
    };
    results.push(row);
    log(row);
  }
  return results;
}

/**
 * Scenario B: revoke k IDs with k root updates (one per ID) or with one update.
 * gain = 1 - (batch gas / k) / (single-update gas)
 */
async function runBatchSweep(contract, { batchSizes, log = () => {} }) {
  const results = [];
  const emptyRoot = buildRevocationTree([]).root;
  for (const k of batchSizes) {
    const ids = evenIds(k);

    await send(contract.updateRoot(emptyRoot));
    const incremental = [];
    for (let i = 1; i <= k; i++) {
      incremental.push((await send(contract.updateRoot(buildRevocationTree(ids.slice(0, i)).root))).record);
    }
    const finalRoot = buildRevocationTree(ids).root;
    check((await contract.root()) === finalRoot, `batch ${k}: incremental updates ended on a different root`);

    await send(contract.updateRoot(emptyRoot));
    const batch = (await send(contract.updateRoot(finalRoot))).record;

    const incrementalTotal = incremental.reduce((sum, r) => sum + r.gas_used, 0);
    const singleUpdateGas = median(incremental.map((r) => r.gas_used));
    const gasPerRevocationBatch = batch.gas_used / k;
    const row = {
      batch_size: k,
      incremental_tx_count: k,
      incremental_total_gas: incrementalTotal,
      single_update_gas_median: singleUpdateGas,
      batch_tx_count: 1,
      batch_total_gas: batch.gas_used,
      gas_per_revocation_incremental: Math.round(incrementalTotal / k),
      gas_per_revocation_batch: Math.round(gasPerRevocationBatch),
      batch_gain_formula: "1 - (batch_total_gas / batch_size) / single_update_gas_median",
      batch_gain_pct: Number(((1 - gasPerRevocationBatch / singleUpdateGas) * 100).toFixed(2)),
      batch_tx_hash: batch.tx_hash,
      incremental_tx_hashes: incremental.map((r) => r.tx_hash),
    };
    results.push(row);
    log(row);
  }
  return results;
}

module.exports = { runDepthSweep, runBatchSweep };
