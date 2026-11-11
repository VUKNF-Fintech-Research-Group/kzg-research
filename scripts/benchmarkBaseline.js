/**
 * benchmarkBaseline.js
 *
 * Merkle-tree revocation baseline, measured the same way as the KZG sweep
 * (scripts/benchmarkUpdateCommitmentGas.js).
 *
 * Run (in-process Hardhat network):
 *   npx hardhat run scripts/benchmarkBaseline.js --network hardhat
 * Run on Hoodi (needs PRIVATE_KEY in contracts/.env):
 *   npx hardhat run scripts/benchmarkBaseline.js --network hoodi
 *
 * Output: results/merkle_baseline_<network>.json
 *
 * Environment:
 *   SAMPLES=<n>                 transactions per measurement (default 5)
 *   MERKLE_BENCH_BREAK_PROOF=1  self-test: send a dummy proof for the
 *                               non-revoked ID; the script must exit non-zero
 *
 * Scenario A: tree depth {2, 4, 8, 10, 12}, i.e. 2^d - 1 revoked IDs. The
 *   non-revoked ID is verified with a real non-membership proof and must log
 *   notRevoked = true; a revoked ID must log notRevoked = false.
 * Scenario B: revoking k IDs with k root updates or with a single update.
 */

const { ethers, network } = require("hardhat");
const fs = require("fs");
const path = require("path");
const { runDepthSweep, runBatchSweep } = require("./lib/merkleSweep");
const { REPO_ROOT, gitCommit } = require("./lib/benchUtils");
const { buildRevocationTree } = require("./merkleHelper");

const DEPTHS = [2, 4, 8, 10, 12];
const BATCH_SIZES = [1, 10, 25, 50, 75, 100];

const pad = (v, width) => String(v).padStart(width);

async function main() {
  const samples = Number(process.env.SAMPLES || 5);
  const breakProof = process.env.MERKLE_BENCH_BREAK_PROOF === "1";
  const [owner] = await ethers.getSigners();
  const { chainId } = await ethers.provider.getNetwork();

  console.log("=== Merkle revocation baseline ===");
  console.log(`Network : ${network.name} (chain ${chainId})`);
  console.log(`Account : ${owner.address}`);
  console.log(`Samples : ${samples} per measurement, median reported`);
  if (breakProof) console.log("Self-test: MERKLE_BENCH_BREAK_PROOF=1, this run must fail");

  const contract = await (await ethers.getContractFactory("MerkleRevocation")).deploy(buildRevocationTree([]).root);
  const deployReceipt = await contract.deploymentTransaction().wait();
  console.log(`Contract: ${await contract.getAddress()}`);

  console.log("\n--- Scenario A: depth sweep ---");
  console.log(`${pad("Depth", 5)} | ${pad("Revoked", 7)} | ${pad("updateRoot", 10)} | ${pad("verify non-revoked", 18)} | ${pad("verify revoked", 14)} | ${pad("proof bytes", 11)}`);
  const scenarioA = await runDepthSweep(contract, {
    depths: DEPTHS,
    samples,
    breakProof,
    log: (r) => console.log(
      `${pad(r.depth, 5)} | ${pad(r.revoked_count, 7)} | ${pad(r.update_root_gas_median.toLocaleString(), 10)} | ` +
      `${pad(r.verify_non_revoked_gas_median.toLocaleString(), 18)} | ${pad(r.verify_revoked_gas_median.toLocaleString(), 14)} | ${pad(r.proof_size_bytes, 11)}`
    ),
  });

  console.log("\n--- Scenario B: batch revocation ---");
  console.log(`${pad("k", 4)} | ${pad("k updates, total gas", 20)} | ${pad("1 update, gas", 13)} | ${pad("gas/revocation", 14)} | ${pad("gain", 7)}`);
  const scenarioB = await runBatchSweep(contract, {
    batchSizes: BATCH_SIZES,
    log: (r) => console.log(
      `${pad(r.batch_size, 4)} | ${pad(r.incremental_total_gas.toLocaleString(), 20)} | ${pad(r.batch_total_gas.toLocaleString(), 13)} | ` +
      `${pad(r.gas_per_revocation_batch.toLocaleString(), 14)} | ${pad(r.batch_gain_pct + "%", 7)}`
    ),
  });

  const output = {
    experiment: "merkle_baseline",
    scheme: "sorted range-leaf Merkle tree, keccak256, real non-membership proofs",
    network: network.name,
    chain_id: Number(chainId),
    commit: gitCommit(),
    date: new Date().toISOString(),
    contract_address: await contract.getAddress(),
    deploy_tx_hash: deployReceipt.hash,
    deploy_gas: Number(deployReceipt.gasUsed),
    samples_per_measurement: samples,
    checks: {
      verified_event: "notRevoked = true asserted for every non-revoked verify, false for every revoked verify",
      fee_reconciliation: "gasUsed == fee / effective gas price, asserted for every transaction",
      negative_controls: "a revoked ID with a dummy proof must give notRevoked = false",
    },
    scenario_a: scenarioA,
    scenario_b: scenarioB,
  };

  const outPath = path.join(REPO_ROOT, "results", `merkle_baseline_${network.name}.json`);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(output, null, 2) + "\n");
  console.log(`\nAll checks passed. Results saved to ${path.relative(REPO_ROOT, outPath)}`);
}

main().catch((err) => {
  console.error(`\nBENCHMARK FAILED: ${err.message}`);
  process.exit(1);
});
