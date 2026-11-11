/**
 * MerkleSweep.test.js
 *
 * The Merkle benchmark must refuse to record a wrong verification result.
 *
 * Run: npx hardhat test test/MerkleSweep.test.js
 */

const { expect } = require("chai");
const { ethers } = require("hardhat");
const { runDepthSweep, runBatchSweep } = require("../scripts/lib/merkleSweep");
const { BenchmarkAssertionError } = require("../scripts/lib/benchUtils");
const { buildRevocationTree } = require("../scripts/merkleHelper");

describe("Merkle benchmark assertions", function () {
  let contract;

  beforeEach(async function () {
    contract = await (await ethers.getContractFactory("MerkleRevocation")).deploy(buildRevocationTree([]).root);
    await contract.waitForDeployment();
  });

  it("passes with real proofs and records the result of every verification", async function () {
    const rows = await runDepthSweep(contract, { depths: [2, 4], samples: 2 });
    for (const row of rows) {
      expect(row.proof_elements).to.equal(row.depth);
      for (const s of row.samples.verify_non_revoked) expect(s.ok).to.equal(true);
      for (const s of row.samples.verify_revoked) expect(s.ok).to.equal(false);
      expect(row.negative_controls.revoked_with_dummy_proof.ok).to.equal(false);
    }
    expect(rows[1].verify_non_revoked_gas_median).to.be.greaterThan(rows[0].verify_non_revoked_gas_median);
  });

  it("fails when the non-revoked ID is sent with a dummy proof", async function () {
    let error;
    try { await runDepthSweep(contract, { depths: [2], breakProof: true }); } catch (e) { error = e; }
    expect(error).to.be.instanceOf(BenchmarkAssertionError);
    expect(error.message).to.match(/expected notRevoked = true/);
  });

  it("batch sweep: one update costs the same as each incremental update", async function () {
    const [row] = await runBatchSweep(contract, { batchSizes: [10] });
    expect(row.incremental_tx_count).to.equal(10);
    expect(row.batch_tx_count).to.equal(1);
    expect(row.batch_gain_pct).to.be.closeTo(90, 0.5);
  });
});
