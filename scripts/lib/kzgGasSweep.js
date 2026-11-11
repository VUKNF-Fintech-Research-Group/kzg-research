/**
 * kzgGasSweep.js
 *
 * Core of the KZG gas benchmark. Every measured transaction is checked before
 * its gas is recorded: the `Verified` event must say ok = true for a
 * non-revoked ID and ok = false for a revoked one. Any mismatch throws, so a
 * failed verification can never end up in a results table.
 *
 * Only the real EIP-2537 precompiles are accepted as the pairing backend.
 */

const { BenchmarkAssertionError, check, median, send, findEvent } = require("./benchUtils");

const PAIRING_BACKEND = "eip2537";
const PRECOMPILES = { G1MSM: "0x000000000000000000000000000000000000000c", PAIRING_CHECK: "0x000000000000000000000000000000000000000f" };

// EIP-2537: a 2-pair pairing check costs 32,600 * 2 + 37,700 = 102,900 gas.
// With the 21,000 transaction base cost, a real verification cannot use less.
const MIN_VERIFY_GAS = 21_000 + 102_900;

/**
 * Refuse to run unless the pairing backend is the real precompile set.
 * A precompile address has no bytecode; code there means a mock was planted.
 * The negative controls in `measureVerify` additionally catch any backend
 * that accepts invalid proofs.
 */
async function assertRealPrecompiles(ethers) {
  for (const [name, address] of Object.entries(PRECOMPILES)) {
    const code = await ethers.provider.getCode(address);
    check(code === "0x", `refusing to benchmark: contract code found at the ${name} precompile address ${address} (mock backend?)`);
  }
}

/** Run verifyNonRevocation as a transaction and assert the logged result. */
async function measureVerify(contract, { w, z, y }, expectedOk, label) {
  const { receipt, record } = await send(contract.verifyNonRevocation(w, z, y));
  const ok = findEvent(contract, receipt, "Verified").args.ok;
  check(ok === expectedOk, `${label}: expected ok = ${expectedOk}, the contract logged ok = ${ok} (tx ${receipt.hash})`);
  check(record.gas_used >= MIN_VERIFY_GAS,
    `${label}: ${record.gas_used} gas is below the ${MIN_VERIFY_GAS} minimum for a real pairing check (tx ${receipt.hash})`);
  return { ...record, ok };
}

/**
 * @param ethers   hardhat ethers
 * @param options  { points, samples, breakProof, log }
 *   points      entries of test/fixtures/kzg_gas_sweep.json
 *   samples     transactions per measurement
 *   breakProof  self-test: swap in a wrong witness for the "valid" case; the
 *               sweep must then throw
 */
async function runKzgGasSweep(ethers, { points, samples = 1, breakProof = false, log = () => {} }) {
  await assertRealPrecompiles(ethers);
  const Factory = await ethers.getContractFactory("KZGRevocation");
  const results = [];

  for (const point of points) {
    const label = `degree ${point.degree}`;
    for (const key of ["valid", "other_valid", "revoked"]) {
      check(point[key].offchain_verifies, `${label}: the ${key} proof does not verify off-chain`);
    }

    const contract = await Factory.deploy(point.commitment);
    const deployReceipt = await contract.deploymentTransaction().wait();
    check((await contract.commitment()) === point.commitment, `${label}: stored commitment differs from the input`);

    const valid = breakProof ? { ...point.valid, w: point.other_valid.w } : point.valid;

    const update = [];
    const verifyValid = [];
    const verifyRevoked = [];
    for (let i = 0; i < samples; i++) {
      // steady-state update: overwrite one 128-byte commitment with another
      update.push((await send(contract.updateCommitment(point.next_commitment))).record);
      await send(contract.updateCommitment(point.commitment));

      verifyValid.push(await measureVerify(contract, valid, true, `${label} non-revoked z=${valid.z}`));
      verifyRevoked.push(await measureVerify(contract, point.revoked, false, `${label} revoked z=${point.revoked.z}`));
    }

    // Negative controls: a backend that accepts anything fails here.
    const wrongY = { ...point.valid, y: (BigInt(point.valid.y) + 1n).toString() };
    const wrongW = { ...point.valid, w: point.other_valid.w };
    const controls = {
      wrong_y: await measureVerify(contract, wrongY, false, `${label} control: wrong y`),
      wrong_witness: await measureVerify(contract, wrongW, false, `${label} control: wrong witness`),
    };

    const row = {
      degree: point.degree,
      revoked_ids: point.revoked_ids,
      contract_address: await contract.getAddress(),
      deploy_tx_hash: deployReceipt.hash,
      deploy_gas: Number(deployReceipt.gasUsed),
      commitment_compressed_bytes: 48,
      commitment_stored_bytes: 128,
      witness_calldata_bytes: 128,
      update_commitment_gas_median: median(update.map((r) => r.gas_used)),
      verify_non_revoked_gas_median: median(verifyValid.map((r) => r.gas_used)),
      verify_revoked_gas_median: median(verifyRevoked.map((r) => r.gas_used)),
      offchain_vs_onchain: "match",
      samples: { update_commitment: update, verify_non_revoked: verifyValid, verify_revoked: verifyRevoked },
      negative_controls: controls,
    };
    results.push(row);
    log(row);
  }
  return results;
}

module.exports = { runKzgGasSweep, BenchmarkAssertionError, PAIRING_BACKEND, MIN_VERIFY_GAS };
