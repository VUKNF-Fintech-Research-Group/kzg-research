/**
 * compareResults.js
 *
 * Side-by-side KZG vs Merkle gas table from the benchmark result files.
 *
 * Usage (plain Node, no Hardhat):
 *   node scripts/compareResults.js [network]      network defaults to "hardhat"
 *
 * Reads:
 *   results/kzg_gas_sweep_<network>.json      from benchmarkUpdateCommitmentGas.js
 *   results/merkle_baseline_<network>.json    from benchmarkBaseline.js
 *
 * Rows pair a KZG polynomial of degree d with the Merkle tree of the nearest
 * size: depth 2/4/8/10/12 holds 3/15/255/1023/4095 revoked IDs.
 * Exits non-zero if a file is missing or was not produced with the real
 * EIP-2537 precompiles.
 */

const fs = require("fs");
const path = require("path");

const RESULTS_DIR = path.join(__dirname, "..", "results");
const PAIRS = [
  { degree: 2, depth: 2 },
  { degree: 16, depth: 4 },
  { degree: 256, depth: 8 },
  { degree: 1024, depth: 10 },
  { degree: 4095, depth: 12 },
];

function load(file) {
  const full = path.join(RESULTS_DIR, file);
  if (!fs.existsSync(full)) {
    console.error(`Missing results/${file}. Run the benchmark for this network first.`);
    process.exit(1);
  }
  return JSON.parse(fs.readFileSync(full, "utf8"));
}

const fmt = (n) => n.toLocaleString("en-US");
const pad = (v, w) => String(v).padStart(w);

function main() {
  const networkName = process.argv[2] || "hardhat";
  const kzg = load(`kzg_gas_sweep_${networkName}.json`);
  const merkle = load(`merkle_baseline_${networkName}.json`);

  if (kzg.pairing_backend !== "eip2537") {
    console.error(`KZG results use pairing backend "${kzg.pairing_backend}", not the real precompiles. Refusing to compare.`);
    process.exit(1);
  }

  console.log(`KZG vs Merkle gas on ${networkName} (medians)`);
  console.log(`  KZG    : commit ${kzg.commit}, ${kzg.date}, backend ${kzg.pairing_backend}`);
  console.log(`  Merkle : commit ${merkle.commit}, ${merkle.date}\n`);

  const header = `${pad("KZG degree", 10)} | ${pad("Merkle depth", 12)} | ${pad("KZG update", 10)} | ${pad("Merkle update", 13)} | ` +
    `${pad("KZG verify", 10)} | ${pad("Merkle verify", 13)} | ${pad("KZG proof", 9)} | ${pad("Merkle proof", 12)} | cheaper verify`;
  console.log(header);
  console.log("-".repeat(header.length));

  for (const { degree, depth } of PAIRS) {
    const k = kzg.results.find((r) => r.degree === degree);
    const m = merkle.scenario_a.find((r) => r.depth === depth);
    if (!k || !m) {
      console.log(`${pad(degree, 10)} | ${pad(depth, 12)} | (missing in results)`);
      continue;
    }
    const kv = k.verify_non_revoked_gas_median;
    const mv = m.verify_non_revoked_gas_median;
    const winner = kv < mv ? "KZG" : mv < kv ? "Merkle" : "tie";
    console.log(
      `${pad(degree, 10)} | ${pad(`${depth} (${m.revoked_count})`, 12)} | ${pad(fmt(k.update_commitment_gas_median), 10)} | ` +
      `${pad(fmt(m.update_root_gas_median), 13)} | ${pad(fmt(kv), 10)} | ${pad(fmt(mv), 13)} | ` +
      `${pad(k.witness_calldata_bytes + " B", 9)} | ${pad(m.proof_size_bytes + " B", 12)} | ${winner}`
    );
  }

  console.log("\nKZG proof = 128-byte uncompressed witness (48 bytes compressed), plus z and y (32 bytes each).");
  console.log("Merkle proof = 32 bytes per tree level, plus the (lo, hi) pair (64 bytes).");
}

main();
