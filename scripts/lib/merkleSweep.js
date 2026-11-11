/**
 * merkleSweep.js
 *
 * Core of the Merkle baseline benchmark. Like the KZG sweep, every measured
 * verification is checked before its gas is recorded: a non-revoked ID with a
 * real non-membership proof must log notRevoked = true, and a revoked ID must
 * log notRevoked = false.
 */

const { TxQueue, check, median, findEvent, readUntil, batchGainPct } = require("./benchUtils");
const { MAX_ID, buildRevocationTree, getNonRevocationProof, proofForLeaf } = require("../merkleHelper");

// Explicit gas limits (see TxQueue). Well above the measured use.
const GAS_LIMIT = { deploy: 700_000, update: 80_000, verify: 200_000 };

const ZERO = "0x" + "00".repeat(32);

const updateRequest = async (contract, root, meta = {}) => ({
  tx: await contract.updateRoot.populateTransaction(root),
  gasLimit: GAS_LIMIT.update,
  ...meta,
});

const verifyRequest = async (contract, id, { lo, hi, proof }, expectedOk, label, meta = {}) => ({
  tx: await contract.verifyNonRevocation.populateTransaction(id, lo, hi, proof),
  gasLimit: GAS_LIMIT.verify,
  expectedOk,
  label,
  ...meta,
});

function checkedVerify(contract, done) {
  const notRevoked = findEvent(contract, done.receipt, "Verified").args.notRevoked;
  check(notRevoked === done.expectedOk,
    `${done.label}: expected notRevoked = ${done.expectedOk}, the contract logged ${notRevoked} (tx ${done.receipt.hash})`);
  return { ...done.record, ok: notRevoked };
}

/** Revoked IDs 2, 4, 6, ...: odd IDs in between are not revoked. */
const evenIds = (count) => Array.from({ length: count }, (_, i) => BigInt(2 * (i + 1)));

/**
 * Scenario A: verification and update gas against tree depth.
 * Depth d means 2^d range leaves, i.e. 2^d - 1 revoked IDs.
 */
async function runDepthSweep(contract, { depths, samples = 1, breakProof = false, log = () => {}, queue }) {
  queue = queue || new TxQueue(contract.runner);
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
    if (breakProof) validProof = { ...validProof, proof: validProof.proof.map(() => ZERO) };

    // A revoked ID has no proof. Use the strongest attempt available: the
    // valid inclusion proof of the leaf that ends at the revoked ID.
    const revokedId = revoked[Math.floor(revoked.length / 2)];
    const attempt = proofForLeaf(tree, tree.bounds.indexOf(revokedId) - 1);
    // Negative control: the pre-audit contract accepted any failing proof.
    const dummy = { lo: 0n, hi: MAX_ID, proof: validProof.proof.map(() => ZERO) };

    const requests = [await updateRequest(contract, tree.root, { kind: "setup" })];
    for (let i = 0; i < samples; i++) {
      requests.push(await updateRequest(contract, nextTree.root, { kind: "update" }));
      requests.push(await updateRequest(contract, tree.root, { kind: "reset" }));
      requests.push(await verifyRequest(contract, validId, validProof, true, `${label} non-revoked id=${validId}`, { kind: "valid" }));
      requests.push(await verifyRequest(contract, revokedId, attempt, false, `${label} revoked id=${revokedId}`, { kind: "revoked" }));
    }
    requests.push(await verifyRequest(contract, revokedId, dummy, false, `${label} control: revoked ID with dummy proof`, { kind: "control" }));

    const done = await queue.run(requests);
    const of = (kind) => done.filter((d) => d.kind === kind);
    const update = of("update").map((d) => d.record);
    const verifyValid = of("valid").map((d) => checkedVerify(contract, d));
    const verifyRevoked = of("revoked").map((d) => checkedVerify(contract, d));

    const row = {
      depth,
      leaf_count: 2 ** depth,
      revoked_count: revoked.length,
      proof_elements: depth,
      proof_size_bytes: 32 * depth + 64, // siblings plus the (lo, hi) pair
      update_root_gas_median: median(update.map((r) => r.gas_used)),
      verify_non_revoked_gas_median: median(verifyValid.map((r) => r.gas_used)),
      verify_revoked_gas_median: median(verifyRevoked.map((r) => r.gas_used)),
      samples: { update_root: update, verify_non_revoked: verifyValid, verify_revoked: verifyRevoked },
      negative_controls: { revoked_with_dummy_proof: checkedVerify(contract, of("control")[0]) },
    };
    results.push(row);
    log(row);
  }
  return results;
}

/**
 * Scenario B: revoke k IDs with k root updates (one per ID) or with one update.
 */
async function runBatchSweep(contract, { batchSizes, samples = 1, log = () => {}, queue }) {
  queue = queue || new TxQueue(contract.runner);
  const results = [];
  const emptyRoot = buildRevocationTree([]).root;
  for (const k of batchSizes) {
    const ids = evenIds(k);
    const finalRoot = buildRevocationTree(ids).root;

    const incremental = [await updateRequest(contract, emptyRoot, { kind: "reset" })];
    for (let i = 1; i <= k; i++) {
      incremental.push(await updateRequest(contract, buildRevocationTree(ids.slice(0, i)).root, { kind: "incremental" }));
    }
    const incrementalRecords = (await queue.run(incremental)).filter((d) => d.kind === "incremental").map((d) => d.record);
    await readUntil(() => contract.root(), finalRoot, `batch ${k}: root after ${k} incremental updates`);

    const batch = [];
    for (let i = 0; i < samples; i++) {
      batch.push(await updateRequest(contract, emptyRoot, { kind: "reset" }));
      batch.push(await updateRequest(contract, finalRoot, { kind: "batch" }));
    }
    const batchRecords = (await queue.run(batch)).filter((d) => d.kind === "batch").map((d) => d.record);

    const incrementalTotal = incrementalRecords.reduce((sum, r) => sum + r.gas_used, 0);
    const singleUpdateGas = median(incrementalRecords.map((r) => r.gas_used));
    const batchGas = median(batchRecords.map((r) => r.gas_used));
    const row = {
      batch_size: k,
      incremental_tx_count: k,
      incremental_total_gas: incrementalTotal,
      single_update_gas_median: singleUpdateGas,
      batch_tx_count: 1,
      batch_total_gas_median: batchGas,
      gas_per_revocation_incremental: Math.round(incrementalTotal / k),
      gas_per_revocation_batch: Math.round(batchGas / k),
      batch_gain_formula: "1 - (batch_total_gas_median / batch_size) / single_update_gas_median",
      batch_gain_pct: batchGainPct(batchGas, k, singleUpdateGas),
      samples: { batch_update: batchRecords, incremental_update: incrementalRecords },
    };
    results.push(row);
    log(row);
  }
  return results;
}

module.exports = { runDepthSweep, runBatchSweep, GAS_LIMIT };
