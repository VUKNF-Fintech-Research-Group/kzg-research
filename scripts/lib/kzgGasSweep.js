/**
 * kzgGasSweep.js
 *
 * Core of the KZG gas benchmarks. Every measured transaction is checked before
 * its gas is recorded: the `Verified` event must say ok = true for a
 * non-revoked ID and ok = false for a revoked one. Any mismatch throws, so a
 * failed verification can never end up in a results table.
 *
 * Only the real EIP-2537 precompiles are accepted as the pairing backend.
 */

const {
  BenchmarkAssertionError, TxQueue, check, median, findEvent, readUntil, batchGainPct,
} = require("./benchUtils");

const PAIRING_BACKEND = "eip2537";
const PRECOMPILES = { G1MSM: "0x000000000000000000000000000000000000000c", PAIRING_CHECK: "0x000000000000000000000000000000000000000f" };

// EIP-2537: a 2-pair pairing check costs 32,600 * 2 + 37,700 = 102,900 gas.
// With the 21,000 transaction base cost, a real verification cannot use less.
const MIN_VERIFY_GAS = 21_000 + 102_900;

// Explicit gas limits (see TxQueue). Well above the measured use.
const GAS_LIMIT = { deploy: 1_500_000, update: 150_000, verify: 350_000 };

/**
 * Refuse to run unless the pairing backend is the real precompile set.
 * A precompile address has no bytecode; code there means a mock was planted.
 * The negative controls additionally catch any backend that accepts invalid proofs.
 */
async function assertRealPrecompiles(ethers) {
  for (const [name, address] of Object.entries(PRECOMPILES)) {
    const code = await ethers.provider.getCode(address);
    check(code === "0x", `refusing to benchmark: contract code found at the ${name} precompile address ${address} (mock backend?)`);
  }
}

async function makeQueue(ethers, queue) {
  if (queue) return queue;
  const [signer] = await ethers.getSigners();
  return new TxQueue(signer);
}

const updateRequest = async (contract, commitment, meta = {}) => ({
  tx: await contract.updateCommitment.populateTransaction(commitment),
  gasLimit: GAS_LIMIT.update,
  ...meta,
});

const verifyRequest = async (contract, { w, z, y }, expectedOk, label, meta = {}) => ({
  tx: await contract.verifyNonRevocation.populateTransaction(w, z, y),
  gasLimit: GAS_LIMIT.verify,
  expectedOk,
  label,
  ...meta,
});

/** Assert the logged result and the gas floor of a mined verify transaction. */
function checkedVerify(contract, done) {
  const ok = findEvent(contract, done.receipt, "Verified").args.ok;
  check(ok === done.expectedOk,
    `${done.label}: expected ok = ${done.expectedOk}, the contract logged ok = ${ok} (tx ${done.receipt.hash})`);
  check(done.record.gas_used >= MIN_VERIFY_GAS,
    `${done.label}: ${done.record.gas_used} gas is below the ${MIN_VERIFY_GAS} minimum for a real pairing check (tx ${done.receipt.hash})`);
  return { ...done.record, ok };
}

/**
 * Degree sweep: updateCommitment() and verifyNonRevocation() gas per degree.
 *
 * @param ethers   hardhat ethers
 * @param options  { points, samples, breakProof, log, queue }
 *   points      entries of test/fixtures/kzg_gas_sweep.json
 *   samples     transactions per measurement
 *   breakProof  self-test: swap in a wrong witness for the "valid" case; the
 *               sweep must then throw
 */
async function runKzgGasSweep(ethers, { points, samples = 1, breakProof = false, log = () => {}, queue }) {
  await assertRealPrecompiles(ethers);
  queue = await makeQueue(ethers, queue);
  const Factory = await ethers.getContractFactory("KZGRevocation");
  const results = [];

  for (const point of points) {
    const label = `degree ${point.degree}`;
    for (const key of ["valid", "other_valid", "revoked"]) {
      check(point[key].offchain_verifies, `${label}: the ${key} proof does not verify off-chain`);
    }

    const { contract, record: deployRecord } = await queue.deploy(Factory, [point.commitment], GAS_LIMIT.deploy);
    await readUntil(() => contract.commitment(), point.commitment, `${label}: stored commitment`);

    const valid = breakProof ? { ...point.valid, w: point.other_valid.w } : point.valid;
    const wrongY = { ...point.valid, y: (BigInt(point.valid.y) + 1n).toString() };
    const wrongW = { ...point.valid, w: point.other_valid.w };

    const requests = [];
    for (let i = 0; i < samples; i++) {
      // steady-state update: overwrite one 128-byte commitment with another
      requests.push(await updateRequest(contract, point.next_commitment, { kind: "update" }));
      requests.push(await updateRequest(contract, point.commitment, { kind: "reset" }));
      requests.push(await verifyRequest(contract, valid, true, `${label} non-revoked z=${valid.z}`, { kind: "valid" }));
      requests.push(await verifyRequest(contract, point.revoked, false, `${label} revoked z=${point.revoked.z}`, { kind: "revoked" }));
    }
    // Negative controls: a backend that accepts anything fails here.
    requests.push(await verifyRequest(contract, wrongY, false, `${label} control: wrong y`, { kind: "wrong_y" }));
    requests.push(await verifyRequest(contract, wrongW, false, `${label} control: wrong witness`, { kind: "wrong_witness" }));

    const done = await queue.run(requests);
    const of = (kind) => done.filter((d) => d.kind === kind);
    const update = of("update").map((d) => d.record);
    const verifyValid = of("valid").map((d) => checkedVerify(contract, d));
    const verifyRevoked = of("revoked").map((d) => checkedVerify(contract, d));

    const row = {
      degree: point.degree,
      revoked_ids: point.revoked_ids,
      contract_address: await contract.getAddress(),
      deploy_tx_hash: deployRecord.tx_hash,
      deploy_gas: deployRecord.gas_used,
      commitment_compressed_bytes: 48,
      commitment_stored_bytes: 128,
      witness_calldata_bytes: 128,
      update_commitment_gas_median: median(update.map((r) => r.gas_used)),
      verify_non_revoked_gas_median: median(verifyValid.map((r) => r.gas_used)),
      verify_revoked_gas_median: median(verifyRevoked.map((r) => r.gas_used)),
      offchain_vs_onchain: "match",
      samples: { update_commitment: update, verify_non_revoked: verifyValid, verify_revoked: verifyRevoked },
      negative_controls: {
        wrong_y: checkedVerify(contract, of("wrong_y")[0]),
        wrong_witness: checkedVerify(contract, of("wrong_witness")[0]),
      },
    };
    results.push(row);
    log(row);
  }
  return results;
}

/**
 * Batch sweep: revoke k IDs with k commitment updates (one per ID) or with a
 * single update.
 *
 * @param options { commitments, batchSizes, samples, log, queue }
 *   commitments  test/fixtures/kzg_batch_sweep.json: commitments[i] commits to
 *                the revoked set {1..i}
 *   samples      repetitions of the single batch update
 */
async function runKzgBatchSweep(ethers, { commitments, batchSizes, samples = 1, log = () => {}, queue }) {
  await assertRealPrecompiles(ethers);
  queue = await makeQueue(ethers, queue);
  const Factory = await ethers.getContractFactory("KZGRevocation");
  const { contract, record: deployRecord } = await queue.deploy(Factory, [commitments[0]], GAS_LIMIT.deploy);
  const results = [];

  for (const k of batchSizes) {
    check(k < commitments.length, `batch size ${k} exceeds the ${commitments.length - 1} commitments in the input file`);

    // k updates, one per revoked ID
    const incremental = [await updateRequest(contract, commitments[0], { kind: "reset" })];
    for (let i = 1; i <= k; i++) incremental.push(await updateRequest(contract, commitments[i], { kind: "incremental" }));
    const incrementalRecords = (await queue.run(incremental)).filter((d) => d.kind === "incremental").map((d) => d.record);
    await readUntil(() => contract.commitment(), commitments[k], `batch ${k}: commitment after ${k} incremental updates`);

    // one update for all k
    const batch = [];
    for (let i = 0; i < samples; i++) {
      batch.push(await updateRequest(contract, commitments[0], { kind: "reset" }));
      batch.push(await updateRequest(contract, commitments[k], { kind: "batch" }));
    }
    const batchRecords = (await queue.run(batch)).filter((d) => d.kind === "batch").map((d) => d.record);
    await readUntil(() => contract.commitment(), commitments[k], `batch ${k}: commitment after the batch update`);

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
  return { contract_address: await contract.getAddress(), deploy_tx_hash: deployRecord.tx_hash, deploy_gas: deployRecord.gas_used, results };
}

module.exports = { runKzgGasSweep, runKzgBatchSweep, BenchmarkAssertionError, PAIRING_BACKEND, MIN_VERIFY_GAS, GAS_LIMIT };
