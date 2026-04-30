/**
 * compareResults.js
 *
 * Side-by-side comparison of KZG vs Merkle gas costs across the degree sweep.
 *
 * Usage (no Hardhat required – pure Node.js):
 *   node scripts/compareResults.js
 *
 * Reads:
 *   results/gas_sweep_update_commitment.json  – KZG benchmark output
 *   results/baseline_merkle.json              – Merkle benchmark output
 *
 * Falls back to paper Table 2 values if the KZG file is missing, and to
 * placeholder zeros if the Merkle file is missing (run benchmarkBaseline.js first).
 */

const fs   = require("fs");
const path = require("path");

const RESULTS_DIR = path.join(__dirname, "..", "results");

// ---------------------------------------------------------------------------
// Degree → depth mapping (matches benchmarkBaseline.js SCENARIO_A_DEPTHS)
// ---------------------------------------------------------------------------
const ROWS = [
  { degree: 2,    depth: 2,  leafCount: 4    },
  { degree: 16,   depth: 4,  leafCount: 16   },
  { degree: 256,  depth: 8,  leafCount: 256  },
  { degree: 1024, depth: 10, leafCount: 1024 },
  { degree: 4096, depth: 12, leafCount: 4096 },
];

// Paper Table 2 fallback values (Hoodi network measurements)
const KZG_FALLBACK = {
  2:    { update: 41041, verify: 44891 },
  16:   { update: 41041, verify: 44879 },
  256:  { update: 41053, verify: 44903 },
  1024: { update: 41053, verify: 44903 },
  4096: { update: 41053, verify: 44903 },
};

// ---------------------------------------------------------------------------
// Load helpers
// ---------------------------------------------------------------------------

function loadJson(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return null;
  }
}

function loadKzgResults() {
  const data = loadJson(path.join(RESULTS_DIR, "gas_sweep_update_commitment.json"));
  if (!data) return null;
  const byDegree = {};
  for (const r of data.results) {
    byDegree[r.degree] = {
      update: r.update_commitment_gas,
      verify: r.verify_non_revocation_gas,
    };
  }
  return byDegree;
}

function loadMerkleResults() {
  const data = loadJson(path.join(RESULTS_DIR, "baseline_merkle.json"));
  if (!data) return null;
  const byDepth = {};
  for (const r of data.scenario_a) {
    byDepth[r.depth] = {
      update:    r.updateRoot_gas,
      verify:    r.verify_gas,
      proofSize: r.proof_size_bytes32,
    };
  }
  return byDepth;
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

function fmt(n) {
  if (n === null || n === undefined) return "      ???";
  return n.toLocaleString("en-US").padStart(9);
}

function fmtProof(n) {
  if (n === null || n === undefined) return "       ???";
  return `${n} × bytes32`.padStart(10);
}

function label(kzgVerify, merkleVerify) {
  if (merkleVerify === null || kzgVerify === null) return "";
  if (kzgVerify < merkleVerify) return " [KZG wins]";
  if (merkleVerify < kzgVerify) return " [Merkle wins]";
  return " [tie]";
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

function main() {
  const kzgData    = loadKzgResults();
  const merkleData = loadMerkleResults();

  const kzgSource = kzgData
    ? "results/gas_sweep_update_commitment.json"
    : "paper Table 2 (fallback)";
  const merkleSource = merkleData
    ? "results/baseline_merkle.json"
    : "NOT FOUND – run: npx hardhat run scripts/benchmarkBaseline.js --network hardhat";

  console.log("=== KZG vs Merkle Gas Comparison ===");
  console.log(`KZG source    : ${kzgSource}`);
  console.log(`Merkle source : ${merkleSource}`);
  console.log();

  // Header
  const COL = {
    label:        "Degree / Depth",
    kzgUpdate:    "KZG updateCommitment",
    mUpdate:      "Merkle updateRoot",
    kzgVerify:    "KZG verify",
    mVerify:      "Merkle verify",
    proof:        "Proof size",
    winner:       "",
  };
  const SEP = "-".repeat(110);

  console.log(
    `${COL.label.padEnd(15)} | ${COL.kzgUpdate.padStart(21)} | ${COL.mUpdate.padStart(18)} | ` +
    `${COL.kzgVerify.padStart(11)} | ${COL.mVerify.padStart(13)} | ${COL.proof.padStart(14)}`
  );
  console.log(SEP);

  for (const { degree, depth, leafCount } of ROWS) {
    const kzg    = (kzgData && kzgData[degree]) || KZG_FALLBACK[degree];
    const merkle = merkleData ? merkleData[depth] : null;

    const kzgUpdate    = kzg?.update    ?? null;
    const kzgVerify    = kzg?.verify    ?? null;
    const mUpdate      = merkle?.update    ?? null;
    const mVerify      = merkle?.verify    ?? null;
    const proofSize    = merkle?.proofSize ?? depth; // depth = expected proof length

    const rowLabel = `${degree} / ${depth} (${leafCount} leaves)`;
    const winner   = label(kzgVerify, mVerify);

    console.log(
      `${rowLabel.padEnd(15)} | ${fmt(kzgUpdate).padStart(21)} | ${fmt(mUpdate).padStart(18)} | ` +
      `${fmt(kzgVerify).padStart(11)} | ${fmt(mVerify).padStart(13)} | ${fmtProof(proofSize).padStart(14)}` +
      `${winner}`
    );
  }

  console.log(SEP);
  console.log();
  console.log("Notes:");
  console.log("  KZG verify gas includes contract overhead only (AlwaysTruePairing mock on Hardhat).");
  console.log("  On a live network with the BLS12-381 pairing precompile, add ~43,000 gas to KZG verify.");
  console.log("  Merkle verify gas grows ~200–300 gas per additional tree depth level.");
  console.log("  KZG proof size is constant: 48 bytes (G1 compressed point), independent of degree.");
  console.log("  Merkle proof size grows: depth × 32 bytes per level.");

  // If Merkle data available, summarise scaling
  if (merkleData) {
    const depths       = ROWS.map((r) => r.depth);
    const verifyGases  = depths.map((d) => merkleData[d]?.verify).filter(Boolean);
    if (verifyGases.length >= 2) {
      const minVerify = Math.min(...verifyGases);
      const maxVerify = Math.max(...verifyGases);
      console.log();
      console.log(
        `  Merkle verify gas range: ${minVerify.toLocaleString()} – ${maxVerify.toLocaleString()} ` +
        `(+${(maxVerify - minVerify).toLocaleString()} over depth 2→12)`
      );
    }

    const kzgVerifyBase = kzgData
      ? kzgData[4096]?.verify
      : KZG_FALLBACK[4096].verify;
    const mVerify4096   = merkleData[12]?.verify;
    if (kzgVerifyBase && mVerify4096) {
      const diff = kzgVerifyBase - mVerify4096;
      if (diff > 0) {
        console.log(
          `  At depth 12 (4096 leaves): KZG verify is ${diff.toLocaleString()} gas higher ` +
          "than Merkle (but constant regardless of registry growth)."
        );
      } else {
        console.log(
          `  At depth 12 (4096 leaves): Merkle verify is ${(-diff).toLocaleString()} gas higher ` +
          "than KZG and will continue to grow."
        );
      }
    }
  }
}

main();
