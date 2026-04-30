/**
 * benchmarkBaseline.js
 *
 * Merkle-tree revocation baseline benchmark – mirrors benchmarkUpdateCommitmentGas.js
 * so results are directly comparable (identical degree / leaf-count mapping, same
 * measurement approach).
 *
 * Run on Hardhat in-process network (fast, no real chain needed):
 *   npx hardhat run scripts/benchmarkBaseline.js --network hardhat
 *
 * Run on Hoodi for paper results (requires PRIVATE_KEY + HOODI_RPC_URL env vars):
 *   npx hardhat run scripts/benchmarkBaseline.js --network hoodi
 *
 * Outputs:  results/baseline_merkle.json
 */

const { ethers } = require("hardhat");
const fs   = require("fs");
const path = require("path");
const { buildTree, getProof, getRevocationProof } = require("./merkleHelper");

// ---------------------------------------------------------------------------
// Experiment parameters
// ---------------------------------------------------------------------------

// Depths match KZG degree sweep: depth d → 2^d leaves → comparable to KZGdegree
// degree 2→depth 2 (4), degree 16→depth 4 (16), degree 256→depth 8 (256),
// degree 1024→depth 10 (1024), degree 4096→depth 12 (4096)
const SCENARIO_A_DEPTHS = [2, 4, 8, 10, 12];
const SCENARIO_B_BATCH_SIZES = [10, 25, 50, 75, 100];
const ITERATIONS = 5; // median over this many repetitions

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function median(arr) {
  const s = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 !== 0 ? s[mid] : Math.round((s[mid - 1] + s[mid]) / 2);
}

/** Generate `count` deterministic bytes32 credential IDs. */
function makeLeaves(count) {
  return Array.from({ length: count }, (_, i) => ethers.toBeHex(i + 1, 32));
}

/**
 * Send a transaction and return { gasUsed, elapsedMs }.
 */
async function sendAndMeasure(txPromise) {
  const t0 = Date.now();
  const tx = await txPromise;
  const receipt = await tx.wait();
  const elapsedMs = Date.now() - t0;
  return { gasUsed: Number(receipt.gasUsed), elapsedMs };
}

// ---------------------------------------------------------------------------
// Scenario A – non-revocation verification gas sweep across depths
// ---------------------------------------------------------------------------

async function runScenarioA(merkle) {
  const results = [];

  console.log("\n=== Scenario A: depth sweep ===");
  console.log(
    `${"Depth".padStart(5)} | ${"Leaves".padStart(6)} | ${"updateRoot gas".padStart(14)} | ` +
    `${"updateRoot ms".padStart(13)} | ${"verify gas".padStart(10)} | ` +
    `${"verify ms".padStart(9)} | ${"proof depth".padStart(11)}`
  );
  console.log("-".repeat(90));

  for (const depth of SCENARIO_A_DEPTHS) {
    const leafCount = 2 ** depth;
    const leaves    = makeLeaves(leafCount);
    const { root, tree } = buildTree(leaves);

    // ---- measure updateRoot() ----
    const updateGasArr = [];
    const updateMsArr  = [];
    for (let i = 0; i < ITERATIONS; i++) {
      // Alternate between two roots to force a real SSTORE each time.
      const alternateLeaves = makeLeaves(leafCount).map((l, idx) =>
        idx === 0 ? ethers.toBeHex(leafCount + i + 1, 32) : l
      );
      const { root: altRoot } = buildTree(alternateLeaves);
      const useRoot = i % 2 === 0 ? root : altRoot;
      const { gasUsed, elapsedMs } = await sendAndMeasure(merkle.updateRoot(useRoot));
      updateGasArr.push(gasUsed);
      updateMsArr.push(elapsedMs);
    }
    // reset to the canonical root for verification
    await (await merkle.updateRoot(root)).wait();

    // ---- measure verifyNonRevocation() for a leaf NOT in the revocation set ----
    // queryLeaf is beyond the leaf index range of the revocation tree.
    const queryLeaf = ethers.toBeHex(leafCount + 9999, 32);
    // Dummy proof of correct depth – exercises O(depth) hashing but fails inclusion check.
    const proof = getRevocationProof(tree, leaves, queryLeaf);

    const verifyGasArr = [];
    const verifyMsArr  = [];
    for (let i = 0; i < ITERATIONS; i++) {
      const { gasUsed, elapsedMs } = await sendAndMeasure(
        merkle.verifyNonRevocation(queryLeaf, proof)
      );
      verifyGasArr.push(gasUsed);
      verifyMsArr.push(elapsedMs);
    }

    const row = {
      depth,
      leaf_count:        leafCount,
      updateRoot_gas:    median(updateGasArr),
      updateRoot_time_ms: median(updateMsArr),
      verify_gas:        median(verifyGasArr),
      verify_time_ms:    median(verifyMsArr),
      proof_size_bytes32: proof.length,
    };
    results.push(row);

    console.log(
      `${String(depth).padStart(5)} | ${String(leafCount).padStart(6)} | ` +
      `${row.updateRoot_gas.toLocaleString().padStart(14)} | ` +
      `${row.updateRoot_time_ms.toFixed(0).padStart(13)} | ` +
      `${row.verify_gas.toLocaleString().padStart(10)} | ` +
      `${row.verify_time_ms.toFixed(0).padStart(9)} | ` +
      `${String(proof.length).padStart(11)}`
    );
  }

  return results;
}

// ---------------------------------------------------------------------------
// Scenario B – batch vs incremental revocation efficiency
// ---------------------------------------------------------------------------

async function runScenarioB(merkle) {
  const results = [];

  console.log("\n=== Scenario B: batch revocation efficiency ===");
  console.log(
    `${"Batch".padStart(5)} | ${"Inc gas".padStart(12)} | ${"Inc txs".padStart(7)} | ` +
    `${"Batch gas".padStart(10)} | ${"Batch txs".padStart(9)} | ` +
    `${"Gas/rev (inc)".padStart(13)} | ${"Gas/rev (batch)".padStart(15)} | ${"Efficiency".padStart(10)}`
  );
  console.log("-".repeat(100));

  // Base set: credentials 1–100 all considered initially valid (empty revocation list).
  // We then revoke `batchSize` credentials and measure the gas cost of two strategies.
  const BASE_COUNT = 200; // initial credential universe (none revoked)

  for (const batchSize of SCENARIO_B_BATCH_SIZES) {
    const toRevoke = makeLeaves(batchSize); // credentials 1..batchSize

    // ---- Incremental: one updateRoot() per revoked credential ----
    let incPoly = [];
    let incTotalGas = 0;
    let incTxCount  = 0;
    // Start from an empty revocation set.
    const { root: emptyRoot } = buildTree([ethers.ZeroHash]); // sentinel
    await (await merkle.updateRoot(emptyRoot)).wait();

    for (const leaf of toRevoke) {
      incPoly.push(leaf);
      const { root: incRoot } = buildTree(incPoly);
      const { gasUsed } = await sendAndMeasure(merkle.updateRoot(incRoot));
      incTotalGas += gasUsed;
      incTxCount++;
    }

    // ---- Batch: one updateRoot() for all revocations at once ----
    // Reset to empty revocation set.
    await (await merkle.updateRoot(emptyRoot)).wait();
    const { root: batchRoot } = buildTree(toRevoke);
    const { gasUsed: batchGas } = await sendAndMeasure(merkle.updateRoot(batchRoot));
    const batchTxCount = 1;

    const gasPerIncremental = Math.round(incTotalGas / batchSize);
    const gasPerBatch       = Math.round(batchGas / batchSize);
    const efficiencyPct     = Math.round((1 - batchGas / incTotalGas) * 100);

    const row = {
      batch_size:                    batchSize,
      incremental_total_gas:         incTotalGas,
      incremental_tx_count:          incTxCount,
      batch_total_gas:               batchGas,
      batch_tx_count:                batchTxCount,
      gas_per_revocation_incremental: gasPerIncremental,
      gas_per_revocation_batch:       gasPerBatch,
      efficiency_gain_pct:           efficiencyPct,
    };
    results.push(row);

    console.log(
      `${String(batchSize).padStart(5)} | ` +
      `${incTotalGas.toLocaleString().padStart(12)} | ` +
      `${String(incTxCount).padStart(7)} | ` +
      `${batchGas.toLocaleString().padStart(10)} | ` +
      `${String(batchTxCount).padStart(9)} | ` +
      `${gasPerIncremental.toLocaleString().padStart(13)} | ` +
      `${gasPerBatch.toLocaleString().padStart(15)} | ` +
      `${String(efficiencyPct).padStart(9)}%`
    );
  }

  return results;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const [owner] = await ethers.getSigners();

  console.log("=== Merkle Revocation Baseline Benchmark ===");
  console.log(`Network : ${network.name}`);
  console.log(`Account : ${owner.address}`);

  // Deploy with an empty sentinel root.
  const Factory = await ethers.getContractFactory("MerkleRevocation");
  const merkle  = await Factory.deploy(ethers.ZeroHash);
  await merkle.waitForDeployment();
  console.log(`Contract: ${await merkle.getAddress()}\n`);

  const scenarioA = await runScenarioA(merkle);
  const scenarioB = await runScenarioB(merkle);

  // ---- save ----
  const output = {
    scenario_a: scenarioA,
    scenario_b: scenarioB,
    metadata: {
      timestamp: new Date().toISOString(),
      network:   network.name,
      contract:  await merkle.getAddress(),
      iterations: ITERATIONS,
      note:
        "verifyNonRevocation() called with dummy proof of correct depth for a " +
        "non-revoked leaf.  Gas is O(depth) because keccak256 is computed once " +
        "per proof element regardless of proof validity.",
    },
  };

  const outPath = path.join(__dirname, "..", "results", "baseline_merkle.json");
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(output, null, 2));
  console.log(`\nResults saved to: ${outPath}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
