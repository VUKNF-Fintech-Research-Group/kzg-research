/**
 * sweep_verify.js — EXP-001 E1 (verify gas vs N), E7 (negative tests), Q7 (determinism),
 * Q11 (seeded state = real-path state) for S1 (Merkle, revealed ID) and S2 (KZG, revealed ID).
 *
 * Run: npx hardhat run eval/scripts/sweep_verify.js --network hardhat
 * Inputs: eval/data/inputs/ (eval/scripts/gen_inputs.py). Output: eval/data/raw/sweep_verify-*.jsonl
 *
 * Rules (evaluation plan): one verification per transaction, real transactions only,
 * decoded Verified event asserted before any gas is recorded, negatives recorded as
 * kind = verify_reject and never mixed into accept statistics.
 */
const hre = require("hardhat");
const { ethers } = hre;
const { INPUTS, readJson, RawLog, send, tracePrecompiles, tryCall, assertNoMocks, runtimeHash, check } = require("./lib/evalUtils");
const { findEvent } = require("../../scripts/lib/benchUtils");
const { MAX_ID, buildRevocationTree, getNonRevocationProof, proofForLeaf } = require("../../scripts/merkleHelper");

const SIZES = readJson(require("path").join(__dirname, "..", "config", "sizes.json"));
const HANDLES = readJson(INPUTS, "handles.json").handles.map(BigInt);
const GAS = { deploy: 2_000_000, update: 200_000, verify: 400_000 };
const IS_HARDHAT = hre.network.name === "hardhat";

// EIP-2537 prices of the calls S2 makes: one 3-point G1MSM + one 2-pair pairing check.
const S2_PRECOMPILE_FORMULA = 30_528 + 102_900;

let signer;
let log;

async function measuredVerify({ sut, contract, N, state, kind, rep, tx, expectedOk, okField, extra = {} }) {
  const { receipt, record } = await send(signer, tx, GAS.verify);
  const ev = findEvent(contract, receipt, "Verified");
  const ok = ev.args[okField];
  check(ok === expectedOk, `${sut} N=${N} ${kind} rep ${rep}: expected ${okField}=${expectedOk}, logged ${ok} (tx ${receipt.hash})`);
  const row = { sut, N, state, kind, rep, ok, expected: expectedOk ? "ok=true" : "ok=false", ...record, ...extra };
  if (IS_HARDHAT) {
    const t = await tracePrecompiles(ethers.provider, receipt.hash);
    row.precompile_gas_traced = t.precompile_gas;
    row.precompile_calls = t.calls;
    row.exec_gas_traced = t.exec_gas;
    row.standard_gas = 21_000 + row.calldata_gas + t.exec_gas; // gas before the EIP-7623 floor
    row.floor_binds = row.floor_gas > row.standard_gas;
    check(row.gas_used === Math.max(row.standard_gas, row.floor_gas),
      `${sut} N=${N} rep ${rep}: gasUsed ${row.gas_used} != max(standard ${row.standard_gas}, floor ${row.floor_gas}) (tx ${receipt.hash})`);
  }
  row.precompile_gas_formula = sut === "S2" ? S2_PRECOMPILE_FORMULA : 0;
  row.pairing_backend = sut === "S2" ? "eip2537" : "none (keccak256 only)";
  row.scope = "revocation only";
  return log.add(row);
}

/** A negative case that may revert: try eth_call first, then send only if it does not revert. */
async function negative({ sut, contract, N, caseName, populate, call, okField, expect, extra = {} }) {
  const sim = await tryCall(call);
  if (sim.reverted) {
    check(expect.startsWith("revert"), `${sut} N=${N} ${caseName}: reverted (${sim.reason}) but expected ${expect}`);
    return log.add({ sut, N, kind: "verify_reject", case: caseName, outcome: "revert", revert_reason: sim.reason, expected: expect, pass: true, ...extra });
  }
  check(sim.value === false, `${sut} N=${N} ${caseName}: view call returned ${sim.value}, expected false`);
  const { receipt, record } = await send(signer, await populate(), GAS.verify);
  const ok = findEvent(contract, receipt, "Verified").args[okField];
  check(ok === false, `${sut} N=${N} ${caseName}: logged ${okField}=${ok}`);
  return log.add({ sut, N, kind: "verify_reject", case: caseName, outcome: "ok=false", ok, expected: expect, pass: true, ...record, ...extra });
}

// ---------------------------------------------------------------- S2

async function s2Sweep(kzgFactory) {
  const first = readJson(INPUTS, `s2_N${SIZES.hardhat_sizes[0]}.json`);
  const deployTx = await kzgFactory.getDeployTransaction(first.commitment);
  const { receipt } = await send(signer, deployTx, GAS.deploy);
  const kzg = kzgFactory.attach(receipt.contractAddress);
  log.add({ sut: "S2", kind: "deploy", address: receipt.contractAddress, runtime_sha256: await runtimeHash(ethers.provider, receipt.contractAddress) });

  for (const N of SIZES.hardhat_sizes) {
    const inp = readJson(INPUTS, `s2_N${N}.json`);
    await send(signer, await kzg.updateCommitment.populateTransaction(inp.commitment), GAS.update);
    check((await kzg.commitment()) === inp.commitment, `S2 N=${N}: stored C != seeded C`);

    for (const [rep, v] of inp.valid.entries()) {
      await measuredVerify({ sut: "S2", contract: kzg, N, state: "seeded", kind: "verify_accept", rep, expectedOk: true, okField: "ok",
        tx: await kzg.verifyNonRevocation.populateTransaction(v.w, v.z, v.y), extra: { z: v.z, proof_bytes: 128 + 32 } });
    }
    // Q7: same calldata, same state -> identical gasUsed.
    const v0 = inp.valid[0];
    await measuredVerify({ sut: "S2", contract: kzg, N, state: "seeded", kind: "determinism_rerun", rep: 0, expectedOk: true, okField: "ok",
      tx: await kzg.verifyNonRevocation.populateTransaction(v0.w, v0.z, v0.y), extra: { z: v0.z } });

    for (const neg of inp.negatives) {
      if (neg.case === "stale_commitment") continue;
      await negative({ sut: "S2", contract: kzg, N, caseName: neg.case, okField: "ok", expect: neg.expect,
        call: () => kzg.checkNonRevocation(neg.w, neg.z, neg.y),
        populate: () => kzg.verifyNonRevocation.populateTransaction(neg.w, neg.z, neg.y) });
    }
    // Wrong registry: a valid proof of size N checked against another size's commitment.
    const otherN = SIZES.hardhat_sizes.find((n) => n !== N);
    const other = readJson(INPUTS, `s2_N${otherN}.json`);
    await send(signer, await kzg.updateCommitment.populateTransaction(other.commitment), GAS.update);
    await negative({ sut: "S2", contract: kzg, N, caseName: "wrong_commitment", okField: "ok", expect: "ok=false",
      call: () => kzg.checkNonRevocation(v0.w, v0.z, v0.y), populate: () => kzg.verifyNonRevocation.populateTransaction(v0.w, v0.z, v0.y),
      extra: { registry_state: `C of N=${otherN}` } });
    // Stale: proof made against C_N after the registry moved on to C_N + one revocation.
    const stale = inp.negatives.find((n) => n.case === "stale_commitment");
    await send(signer, await kzg.updateCommitment.populateTransaction(inp.next_commitment), GAS.update);
    await negative({ sut: "S2", contract: kzg, N, caseName: "stale_commitment", okField: "ok", expect: "ok=false",
      call: () => kzg.checkNonRevocation(stale.w, stale.z, stale.y), populate: () => kzg.verifyNonRevocation.populateTransaction(stale.w, stale.z, stale.y) });
    console.log(`S2 N=${N}: ${inp.valid.length} accepts, ${inp.negatives.length + 1} negatives`);
  }

  // Q11 + real-path rows: revoke one handle at a time through updateCommitment, then verify.
  for (const N of SIZES.real_path_sizes) {
    const inp = readJson(INPUTS, `s2_N${N}.json`);
    const { receipt: dr } = await send(signer, await kzgFactory.getDeployTransaction(inp.real_path.initial_commitment), GAS.deploy);
    const fresh = kzgFactory.attach(dr.contractAddress);
    for (const c of inp.real_path.commitments) await send(signer, await fresh.updateCommitment.populateTransaction(c), GAS.update);
    const stored = await fresh.commitment();
    const equal = stored === inp.commitment;
    log.add({ sut: "S2", N, kind: "q11_cross_check", real_path_updates: inp.real_path.commitments.length, real_path_c: stored, seeded_c: inp.commitment, equal });
    check(equal, `Q11 S2 N=${N}: real-path C != seeded C`);
    for (const [rep, v] of inp.valid.entries()) {
      await measuredVerify({ sut: "S2", contract: fresh, N, state: "real", kind: "verify_accept", rep, expectedOk: true, okField: "ok",
        tx: await fresh.verifyNonRevocation.populateTransaction(v.w, v.z, v.y), extra: { z: v.z, proof_bytes: 160 } });
    }
    console.log(`S2 real path N=${N}: C matches seeded state`);
  }
}

// ---------------------------------------------------------------- S1

function flipByte(hex32) {
  const b = Buffer.from(hex32.slice(2), "hex");
  b[31] ^= 0x01;
  return "0x" + b.toString("hex");
}

async function s1Sweep(merkleFactory) {
  const empty = buildRevocationTree([]);
  const { receipt } = await send(signer, await merkleFactory.getDeployTransaction(empty.root), GAS.deploy);
  const mk = merkleFactory.attach(receipt.contractAddress);
  log.add({ sut: "S1", kind: "deploy", address: receipt.contractAddress, runtime_sha256: await runtimeHash(ethers.provider, receipt.contractAddress) });

  for (const N of SIZES.hardhat_sizes) {
    const revoked = HANDLES.slice(0, N);
    const tree = buildRevocationTree(revoked);
    await send(signer, await mk.updateRoot.populateTransaction(tree.root), GAS.update);
    check((await mk.root()) === tree.root, `S1 N=${N}: stored root mismatch`);
    // Same query handles as S2 (aligned inputs).
    const queries = readJson(INPUTS, `s2_N${N}.json`).valid.map((v) => BigInt(v.z));

    for (const [rep, id] of queries.entries()) {
      const p = getNonRevocationProof(tree, id);
      await measuredVerify({ sut: "S1", contract: mk, N, state: "seeded", kind: "verify_accept", rep, expectedOk: true, okField: "notRevoked",
        tx: await mk.verifyNonRevocation.populateTransaction(id, p.lo, p.hi, p.proof),
        extra: { z: id.toString(), proof_len: p.proof.length, tree_depth: tree.depth, proof_bytes: 64 + 32 * p.proof.length } });
    }
    const id0 = queries[0];
    const p0 = getNonRevocationProof(tree, id0);
    await measuredVerify({ sut: "S1", contract: mk, N, state: "seeded", kind: "determinism_rerun", rep: 0, expectedOk: true, okField: "notRevoked",
      tx: await mk.verifyNonRevocation.populateTransaction(id0, p0.lo, p0.hi, p0.proof), extra: { z: id0.toString(), proof_len: p0.proof.length } });

    const rid = revoked[Math.floor(revoked.length / 2)];
    const ridx = tree.bounds.indexOf(rid);
    const attempt = proofForLeaf(tree, ridx - 1); // leaf (prev, rid): rid is its upper bound, not inside
    const cases = [
      { name: "revoked_handle_neighbour_leaf", args: [rid, attempt.lo, attempt.hi, attempt.proof] },
      { name: "revoked_handle_dummy_proof", args: [rid, 0n, MAX_ID, p0.proof.map(() => "0x" + "00".repeat(32))] },
      { name: "id_outside_claimed_gap", args: [id0, p0.hi, p0.hi + 1n, p0.proof] },
      { name: "tampered_sibling", args: [id0, p0.lo, p0.hi, p0.proof.length ? [flipByte(p0.proof[0]), ...p0.proof.slice(1)] : ["0x" + "11".repeat(32)]] },
      { name: "id_out_of_domain", args: [MAX_ID, p0.lo, MAX_ID, p0.proof] },
    ];
    for (const c of cases) {
      await negative({ sut: "S1", contract: mk, N, caseName: c.name, okField: "notRevoked", expect: "ok=false",
        call: () => mk.checkNonRevocation(...c.args), populate: () => mk.verifyNonRevocation.populateTransaction(...c.args) });
    }
    // Wrong registry: proof from this tree against another size's root.
    const otherN = SIZES.hardhat_sizes.find((n) => n !== N);
    const otherTree = buildRevocationTree(HANDLES.slice(0, otherN));
    await send(signer, await mk.updateRoot.populateTransaction(otherTree.root), GAS.update);
    await negative({ sut: "S1", contract: mk, N, caseName: "wrong_root", okField: "notRevoked", expect: "ok=false",
      call: () => mk.checkNonRevocation(id0, p0.lo, p0.hi, p0.proof), populate: () => mk.verifyNonRevocation.populateTransaction(id0, p0.lo, p0.hi, p0.proof),
      extra: { registry_state: `root of N=${otherN}` } });
    // Stale: proof for R_N after the registry moved to R_N + one revocation.
    const nextTree = buildRevocationTree([...revoked, HANDLES[N]]);
    await send(signer, await mk.updateRoot.populateTransaction(nextTree.root), GAS.update);
    const sid = queries[queries.length - 1];
    const sp = getNonRevocationProof(tree, sid);
    await negative({ sut: "S1", contract: mk, N, caseName: "stale_root", okField: "notRevoked", expect: "ok=false",
      call: () => mk.checkNonRevocation(sid, sp.lo, sp.hi, sp.proof), populate: () => mk.verifyNonRevocation.populateTransaction(sid, sp.lo, sp.hi, sp.proof) });
    console.log(`S1 N=${N}: depth ${tree.depth}, ${queries.length} accepts, ${cases.length + 2} negatives`);
  }

  for (const N of SIZES.real_path_sizes) {
    const revoked = HANDLES.slice(0, N);
    const { receipt: dr } = await send(signer, await merkleFactory.getDeployTransaction(empty.root), GAS.deploy);
    const fresh = merkleFactory.attach(dr.contractAddress);
    for (let i = 1; i <= N; i++) await send(signer, await fresh.updateRoot.populateTransaction(buildRevocationTree(revoked.slice(0, i)).root), GAS.update);
    const seeded = buildRevocationTree(revoked);
    const stored = await fresh.root();
    log.add({ sut: "S1", N, kind: "q11_cross_check", real_path_updates: N, real_path_root: stored, seeded_root: seeded.root, equal: stored === seeded.root });
    check(stored === seeded.root, `Q11 S1 N=${N}: real-path root != seeded root`);
    const queries = readJson(INPUTS, `s2_N${N}.json`).valid.map((v) => BigInt(v.z));
    for (const [rep, id] of queries.entries()) {
      const p = getNonRevocationProof(seeded, id);
      await measuredVerify({ sut: "S1", contract: fresh, N, state: "real", kind: "verify_accept", rep, expectedOk: true, okField: "notRevoked",
        tx: await fresh.verifyNonRevocation.populateTransaction(id, p.lo, p.hi, p.proof),
        extra: { z: id.toString(), proof_len: p.proof.length, tree_depth: seeded.depth, proof_bytes: 64 + 32 * p.proof.length } });
    }
    console.log(`S1 real path N=${N}: root matches seeded state`);
  }
}

async function main() {
  [signer] = await ethers.getSigners();
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  log = new RawLog("sweep_verify", hre.network.name, chainId);
  await assertNoMocks(ethers.provider);
  try {
    await s2Sweep(await ethers.getContractFactory("KZGRevocation"));
    await s1Sweep(await ethers.getContractFactory("MerkleRevocation"));
  } finally {
    console.log(`wrote ${log.close({ sizes: SIZES.hardhat_sizes })}`);
  }
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
