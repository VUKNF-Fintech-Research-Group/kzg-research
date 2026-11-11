/**
 * KZGGasSweep.test.js
 *
 * The gas benchmark must refuse to record a failed verification.
 *
 * Run: npx hardhat test test/KZGGasSweep.test.js
 */

const { expect } = require("chai");
const { ethers, network } = require("hardhat");
const { runKzgGasSweep, BenchmarkAssertionError, MIN_VERIFY_GAS } = require("../scripts/lib/kzgGasSweep");
const { points } = require("./fixtures/kzg_gas_sweep.json");

const smallPoints = points.filter((p) => p.degree <= 16);

async function expectBenchmarkFailure(promise, pattern) {
  let error;
  try { await promise; } catch (e) { error = e; }
  expect(error, "the sweep should have thrown").to.be.instanceOf(BenchmarkAssertionError);
  expect(error.message).to.match(pattern);
}

describe("KZG gas benchmark assertions", function () {
  it("passes with real proofs and records ok for every transaction", async function () {
    const rows = await runKzgGasSweep(ethers, { points: smallPoints, samples: 2 });
    expect(rows).to.have.length(smallPoints.length);
    for (const row of rows) {
      for (const s of row.samples.verify_non_revoked) {
        expect(s.ok).to.equal(true);
        expect(s.gas_used).to.be.at.least(MIN_VERIFY_GAS);
        expect(s.tx_hash).to.match(/^0x[0-9a-f]{64}$/);
      }
      for (const s of row.samples.verify_revoked) expect(s.ok).to.equal(false);
      expect(row.negative_controls.wrong_y.ok).to.equal(false);
      expect(row.negative_controls.wrong_witness.ok).to.equal(false);
    }
  });

  it("fails when a proof is deliberately broken", async function () {
    await expectBenchmarkFailure(
      runKzgGasSweep(ethers, { points: smallPoints, breakProof: true }),
      /expected ok = true, the contract logged ok = false/
    );
  });

  it("fails when a revoked ID is presented as non-revoked", async function () {
    const p = smallPoints[0];
    const swapped = [{ ...p, valid: p.revoked }];
    await expectBenchmarkFailure(runKzgGasSweep(ethers, { points: swapped }), /expected ok = true/);
  });

  it("fails when an input proof did not verify off-chain", async function () {
    const p = smallPoints[0];
    const bad = [{ ...p, valid: { ...p.valid, offchain_verifies: false } }];
    await expectBenchmarkFailure(runKzgGasSweep(ethers, { points: bad }), /does not verify off-chain/);
  });

  it("refuses to run when code is planted at a precompile address", async function () {
    const pairing = "0x000000000000000000000000000000000000000f";
    const snapshot = await network.provider.send("evm_snapshot");
    try {
      // returns 32 bytes of 0x..01 for any input: an "always true" pairing
      await network.provider.send("hardhat_setCode", [pairing, "0x600160005260206000f3"]);
      await expectBenchmarkFailure(runKzgGasSweep(ethers, { points: smallPoints }), /refusing to benchmark/);
    } finally {
      await network.provider.send("evm_revert", [snapshot]);
    }
  });
});
