/**
 * benchmarkUpdateCommitmentGas.js
 *
 * KZG gas benchmark against the real EIP-2537 precompiles. No pairing mock.
 *
 * Degree sweep: updateCommitment() and verifyNonRevocation() for revocation
 *   polynomials of degree {2, 16, 256, 1024, 4095}.
 * Batch sweep: revoking k IDs with k commitment updates or with a single
 *   update, k in {1, 10, 25, 50, 75, 100}.
 *
 * Run (in-process Hardhat network, hardfork prague):
 *   npx hardhat run scripts/benchmarkUpdateCommitmentGas.js --network hardhat
 * Run on Hoodi (needs PRIVATE_KEY in contracts/.env):
 *   npx hardhat run scripts/benchmarkUpdateCommitmentGas.js --network hoodi
 *
 * Inputs:  test/fixtures/kzg_gas_sweep.json and kzg_batch_sweep.json (real
 *          commitments and proofs from c-kzg; regenerate with
 *          `python3 scripts/gen_kzg_fixtures.py`)
 * Output:  results/kzg_gas_sweep_<network>.json
 *
 * Environment:
 *   SAMPLES=<n>              transactions per measurement (default 5)
 *   KZG_BENCH_BREAK_PROOF=1  self-test: use a wrong witness; the script must
 *                            exit non-zero and write nothing
 *
 * Every transaction's Verified event is checked before its gas is recorded
 * (ok = true for non-revoked IDs, false for revoked IDs). Any mismatch aborts
 * the run with a non-zero exit code.
 */

const { ethers, network } = require("hardhat");
const fs = require("fs");
const path = require("path");
const { runKzgGasSweep, runKzgBatchSweep, PAIRING_BACKEND, MIN_VERIFY_GAS } = require("./lib/kzgGasSweep");
const { REPO_ROOT, TxQueue, gitCommit } = require("./lib/benchUtils");

const INPUT_PATH = path.join(REPO_ROOT, "test", "fixtures", "kzg_gas_sweep.json");
const BATCH_INPUT_PATH = path.join(REPO_ROOT, "test", "fixtures", "kzg_batch_sweep.json");
const BATCH_SIZES = [1, 10, 25, 50, 75, 100];

const pad = (v, width) => String(v).padStart(width);

async function main() {
  const samples = Number(process.env.SAMPLES || 5);
  const breakProof = process.env.KZG_BENCH_BREAK_PROOF === "1";
  const { points } = JSON.parse(fs.readFileSync(INPUT_PATH, "utf8"));
  const { commitments } = JSON.parse(fs.readFileSync(BATCH_INPUT_PATH, "utf8"));
  const { chainId } = await ethers.provider.getNetwork();
  const [signer] = await ethers.getSigners();
  const queue = new TxQueue(signer);

  console.log("=== KZG gas benchmark: updateCommitment() and verifyNonRevocation() ===");
  console.log(`Network         : ${network.name} (chain ${chainId})`);
  console.log(`Account         : ${signer.address}`);
  console.log(`Pairing backend : ${PAIRING_BACKEND} (real precompiles)`);
  console.log(`Samples         : ${samples} per measurement, median reported`);
  if (breakProof) console.log("Self-test       : KZG_BENCH_BREAK_PROOF=1, this run must fail");
  console.log();

  const header = `${pad("Degree", 6)} | ${pad("updateCommitment", 16)} | ${pad("verify non-revoked", 18)} | ${pad("verify revoked", 14)} | ok (non-revoked / revoked)`;
  console.log(header);
  console.log("-".repeat(header.length));

  const results = await runKzgGasSweep(ethers, {
    points,
    samples,
    breakProof,
    queue,
    log: (row) => console.log(
      `${pad(row.degree, 6)} | ${pad(row.update_commitment_gas_median.toLocaleString(), 16)} | ` +
      `${pad(row.verify_non_revoked_gas_median.toLocaleString(), 18)} | ` +
      `${pad(row.verify_revoked_gas_median.toLocaleString(), 14)} | true / false`
    ),
  });

  console.log("\n--- Batch revocation ---");
  console.log(`${pad("k", 4)} | ${pad("k updates, total gas", 20)} | ${pad("1 update, gas", 13)} | ${pad("gas/revocation", 14)} | ${pad("gain", 7)}`);
  const batch = await runKzgBatchSweep(ethers, {
    commitments,
    batchSizes: BATCH_SIZES,
    samples,
    queue,
    log: (r) => console.log(
      `${pad(r.batch_size, 4)} | ${pad(r.incremental_total_gas.toLocaleString(), 20)} | ${pad(r.batch_total_gas_median.toLocaleString(), 13)} | ` +
      `${pad(r.gas_per_revocation_batch.toLocaleString(), 14)} | ${pad(r.batch_gain_pct + "%", 7)}`
    ),
  });

  const output = {
    experiment: "kzg_gas_sweep",
    account: signer.address,
    pairing_backend: PAIRING_BACKEND,
    network: network.name,
    chain_id: Number(chainId),
    hardfork: network.name === "hardhat" ? network.config.hardfork : "live network",
    commit: gitCommit(),
    date: new Date().toISOString(),
    samples_per_measurement: samples,
    checks: {
      verified_event: "ok = true asserted for every non-revoked verify, ok = false for every revoked verify",
      min_verify_gas: MIN_VERIFY_GAS,
      fee_reconciliation: "gasUsed == fee / effective gas price, asserted for every transaction",
      negative_controls: "wrong y and wrong witness must give ok = false",
      offchain_cross_check: "every proof also verified off-chain with c-kzg (see input file)",
    },
    input_files: [path.relative(REPO_ROOT, INPUT_PATH), path.relative(REPO_ROOT, BATCH_INPUT_PATH)],
    results,
    batch,
  };

  const outPath = path.join(REPO_ROOT, "results", `kzg_gas_sweep_${network.name}.json`);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(output, null, 2) + "\n");
  console.log(`\nAll checks passed. Results saved to ${path.relative(REPO_ROOT, outPath)}`);
}

main().catch((err) => {
  console.error(`\nBENCHMARK FAILED: ${err.message}`);
  process.exit(1);
});
