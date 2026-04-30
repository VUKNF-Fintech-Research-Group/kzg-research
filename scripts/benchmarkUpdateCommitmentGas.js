/**
 * benchmarkUpdateCommitmentGas.js
 *
 * Dedicated experiment: measure updateCommitment() and verifyNonRevocation()
 * gas across polynomial degree sweep {2, 16, 256, 1024, 4096}.
 *
 * Run:
 *   npm install
 *   npx hardhat run scripts/benchmarkUpdateCommitmentGas.js --network hardhat
 *
 * No external node required – Hardhat spins up an in-process EVM.
 *
 * Commitment / payload sizing:
 *   - A KZG commitment is always a 48-byte BLS12-381 G1 compressed point,
 *     independent of polynomial degree.
 *   - verifyNonRevocation() expects commit(48) || proof(48) || z(32) || y(32)
 *     = 160 bytes, also independent of degree.
 *   - Both gas figures are therefore expected to be identical for all degrees,
 *     empirically confirming O(1) on-chain cost.
 *
 * Pairing mock:
 *   AlwaysTruePairing returns abi.encode(true) for any calldata, so the
 *   pairing check succeeds without the BLS12-381 precompile.  The precompile
 *   cost on a live network (~43 k gas) is reported separately in hoodi results.
 */

const { ethers } = require("hardhat");
const fs = require("fs");
const path = require("path");

// ---------------------------------------------------------------------------
// Degree sweep configuration
// ---------------------------------------------------------------------------
const DEGREES = [2, 16, 256, 1024, 4096];

// ---------------------------------------------------------------------------
// Synthetic payload helpers
// ---------------------------------------------------------------------------
// Because a KZG commitment is always 48 bytes regardless of degree, we build
// a deterministic synthetic commitment per degree (byte pattern = degree % 256)
// to make each measurement visually distinct while keeping size fixed.
// AlwaysTruePairing accepts any bytes, so cryptographic validity is not needed.

function makeCommitment(degree) {
  // 48-byte G1-sized buffer with a recognisable per-degree pattern.
  // Use (degree % 254) + 1 so the fill byte is always in [1, 255] – never
  // zero.  Real KZG commitments are BLS12-381 G1 points whose bytes are
  // never all-zero; all-zero fill would hit the EVM zero-byte calldata
  // discount (4 gas vs 16 gas per byte) and the SSTORE_SET path
  // (zero→nonzero, 20 k gas) rather than the SSTORE_RESET path
  // (nonzero→nonzero, 2.9 k gas), producing spurious gas variation.
  return ethers.hexlify(Buffer.alloc(48, (degree % 254) + 1));
}

function makePayload(commitHex) {
  // payload = commit(48) || proof(48) || z(32) || y(32)  = 160 bytes
  const commit = Buffer.from(commitHex.slice(2), "hex"); // 48 bytes
  const proof  = Buffer.alloc(48, 0xaa);                 // dummy proof
  const z      = Buffer.alloc(32, 0); z[31] = 5;         // z = 5
  const y      = Buffer.alloc(32, 0); y[31] = 1;         // y = 1 (≠ 0 → not revoked)
  return ethers.hexlify(Buffer.concat([commit, proof, z, y]));
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------
function pad(str, width) {
  return String(str).padStart(width);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function main() {
  const [owner] = await ethers.getSigners();

  // ---- deploy AlwaysTruePairing (one instance, shared across degrees) ----
  const ATP  = await ethers.getContractFactory("AlwaysTruePairing");
  const atp  = await ATP.deploy();
  await atp.waitForDeployment();

  const RevFactory = await ethers.getContractFactory("KZGRevocationFixed");

  console.log("=== KZG Gas Sweep: updateCommitment() vs verifyNonRevocation() ===");
  console.log(`Pairing mock : AlwaysTruePairing @ ${await atp.getAddress()}`);
  console.log(`Degrees      : ${DEGREES.join(", ")}`);
  console.log(`Commitment   : always 48 bytes (G1 compressed point)`);
  console.log(`Payload      : always 160 bytes (commit||proof||z||y)`);
  console.log();

  const header =
    `${pad("Degree", 7)} | ${pad("updateCommitment gas", 21)} | ${pad("verifyNonRevocation gas", 24)} | commit | payload`;
  const sep = "-".repeat(header.length);
  console.log(header);
  console.log(sep);

  const results = [];

  for (const degree of DEGREES) {
    const commitHex  = makeCommitment(degree);
    const payloadHex = makePayload(commitHex);

    // Deploy a fresh contract per degree with the initial commitment.
    // Constructor writes the storage slot (cold); updateCommitment() then
    // overwrites it (warm) – reflecting steady-state operational cost.
    const rev = await RevFactory.deploy(await atp.getAddress(), commitHex);
    await rev.waitForDeployment();

    // ---- updateCommitment() ----
    // Write a different commitment (same size) to trigger a real SSTORE.
    // Add 1 to the degree so makeCommitment() produces a different fill byte.
    const commitHex2 = makeCommitment(degree + 1);
    const txUpdate   = await rev.updateCommitment(commitHex2);
    const rcptUpdate = await txUpdate.wait();
    const gasUpdate  = Number(rcptUpdate.gasUsed);

    // Reset to the original commitment so the payload's security check passes.
    const txReset = await rev.updateCommitment(commitHex);
    await txReset.wait();

    // ---- verifyNonRevocation() ----
    const txVerify   = await rev.verifyNonRevocation(payloadHex);
    const rcptVerify = await txVerify.wait();
    const gasVerify  = Number(rcptVerify.gasUsed);

    results.push({ degree, gasUpdate, gasVerify });

    console.log(
      `${pad(degree, 7)} | ${pad(gasUpdate.toLocaleString(), 21)} | ${pad(gasVerify.toLocaleString(), 24)} |   48 B |    160 B`
    );
  }

  console.log(sep);
  console.log();

  // ---- summary ----
  const updateGasValues = results.map((r) => r.gasUpdate);
  const verifyGasValues = results.map((r) => r.gasVerify);

  const minU = Math.min(...updateGasValues);
  const maxU = Math.max(...updateGasValues);
  const minV = Math.min(...verifyGasValues);
  const maxV = Math.max(...verifyGasValues);

  console.log("=== Summary ===");
  console.log(`  updateCommitment()    gas range : ${minU.toLocaleString()} – ${maxU.toLocaleString()}`);
  console.log(`  verifyNonRevocation() gas range : ${minV.toLocaleString()} – ${maxV.toLocaleString()}`);
  console.log();

  const O1update = minU === maxU ? "✓ O(1) – identical across all degrees" : `~ varies by ${maxU - minU} gas`;
  const O1verify = minV === maxV ? "✓ O(1) – identical across all degrees" : `~ varies by ${maxV - minV} gas`;
  console.log(`  updateCommitment()    : ${O1update}`);
  console.log(`  verifyNonRevocation() : ${O1verify}`);
  console.log();
  console.log("  Note: AlwaysTruePairing mock used; BLS12-381 precompile gas (~43 k)");
  console.log("  is excluded here and measured separately on Hoodi (see hoodi results).");

  // ---- persist results ----
  const output = {
    experiment: "update_commitment_gas_sweep",
    network: "hardhat",
    degrees: DEGREES,
    evaluation_point: 5,
    results: results.map((r) => ({
      degree:                    r.degree,
      update_commitment_gas:     r.gasUpdate,
      verify_non_revocation_gas: r.gasVerify,
      commitment_size_bytes:     48,
      payload_size_bytes:        160,
    })),
    metadata: {
      timestamp: new Date().toISOString(),
      pairing_mock: "AlwaysTruePairing (always returns true)",
      note:
        "Commitment is always 48 bytes (G1 point); payload is always 160 bytes. " +
        "Both gas figures are O(1) w.r.t. polynomial degree.",
    },
  };

  const outPath = path.join(__dirname, "..", "results", "gas_sweep_update_commitment.json");
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(output, null, 2));
  console.log(`\n  Results saved to: ${outPath}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
