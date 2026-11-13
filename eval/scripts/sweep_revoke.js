/**
 * sweep_revoke.js — EXP-001 E3: revocation-update gas for S1 and S2, plus the S2 batch sweep.
 *
 * Run: npx hardhat run eval/scripts/sweep_revoke.js --network hardhat
 * Output: eval/data/raw/sweep_revoke-*.jsonl
 *
 * Both designs update through their production entry point (updateRoot /
 * updateCommitment), which replaces the whole state computed off-chain. At each
 * N the registry is set to R_N, then one revocation ("first") and a second one
 * ("later") are applied; repeated `update_repetitions` times from a reset.
 * Batch (S2 only, as in the plan): revoking k handles in k updates or in one,
 * reported as transaction amortisation.
 *
 * Note: only the new root / commitment goes on-chain. Holders also need the revoked
 * handles to rebuild proofs; publishing them is not part of these figures.
 */
const path = require("path");
const hre = require("hardhat");
const { ethers } = hre;
const { INPUTS, readJson, RawLog, send, assertNoMocks, check } = require("./lib/evalUtils");
const { batchGainPct, median } = require("../../scripts/lib/benchUtils");
const { buildRevocationTree } = require("../../scripts/merkleHelper");

const SIZES = readJson(path.join(__dirname, "..", "config", "sizes.json"));
const HANDLES = readJson(INPUTS, "handles.json").handles.map(BigInt);
const GAS = { deploy: 2_000_000, update: 200_000 };

let signer;
let log;

async function measure(row, tx) {
  const { record } = await send(signer, tx, GAS.update);
  return log.add({ ...row, ...record, scope: "revocation only" });
}

async function s2(factory) {
  const first = readJson(INPUTS, `s2_N${SIZES.hardhat_sizes[0]}.json`);
  const { receipt } = await send(signer, await factory.getDeployTransaction(first.commitment), GAS.deploy);
  const kzg = factory.attach(receipt.contractAddress);
  for (const N of SIZES.hardhat_sizes) {
    const inp = readJson(INPUTS, `s2_N${N}.json`);
    for (let rep = 0; rep < SIZES.update_repetitions; rep++) {
      await send(signer, await kzg.updateCommitment.populateTransaction(inp.commitment), GAS.update); // reset, not measured
      await measure({ sut: "S2", N, kind: "update_first", rep, state: "seeded" }, await kzg.updateCommitment.populateTransaction(inp.next_commitment));
      await measure({ sut: "S2", N, kind: "update_later", rep, state: "seeded" }, await kzg.updateCommitment.populateTransaction(inp.next2_commitment));
    }
    check((await kzg.commitment()) === inp.next2_commitment, `S2 N=${N}: final commitment mismatch`);
    console.log(`S2 N=${N}: updates measured`);
  }

  const batch = readJson(INPUTS, "s2_batch.json").commitments;
  for (const k of SIZES.batch_sizes) {
    await send(signer, await kzg.updateCommitment.populateTransaction(batch[0]), GAS.update);
    const inc = [];
    for (let i = 1; i <= k; i++) {
      inc.push(await measure({ sut: "S2", N: SIZES.batch_base_size, kind: "batch_incremental", k, step: i }, await kzg.updateCommitment.populateTransaction(batch[i])));
    }
    check((await kzg.commitment()) === batch[k], `batch ${k}: incremental end state mismatch`);
    const one = [];
    for (let rep = 0; rep < SIZES.update_repetitions; rep++) {
      await send(signer, await kzg.updateCommitment.populateTransaction(batch[0]), GAS.update);
      one.push(await measure({ sut: "S2", N: SIZES.batch_base_size, kind: "batch_single", k, rep }, await kzg.updateCommitment.populateTransaction(batch[k])));
    }
    check((await kzg.commitment()) === batch[k], `batch ${k}: single-update end state mismatch`);
    const single = median(inc.map((r) => r.gas_used));
    const batchGas = median(one.map((r) => r.gas_used));
    log.add({ sut: "S2", kind: "batch_summary", k, base_N: SIZES.batch_base_size, incremental_total_gas: inc.reduce((s, r) => s + r.gas_used, 0),
      single_update_gas_median: single, batch_gas_median: batchGas, gain_formula: "1 - (batch_gas_median / k) / single_update_gas_median",
      gain_pct: batchGainPct(batchGas, k, single), label: "transaction amortisation, not a property of KZG" });
    console.log(`S2 batch k=${k}: done`);
  }
}

async function s1(factory) {
  const { receipt } = await send(signer, await factory.getDeployTransaction(buildRevocationTree([]).root), GAS.deploy);
  const mk = factory.attach(receipt.contractAddress);
  for (const N of SIZES.hardhat_sizes) {
    const t0 = buildRevocationTree(HANDLES.slice(0, N));
    const t1 = buildRevocationTree(HANDLES.slice(0, N + 1));
    const t2 = buildRevocationTree(HANDLES.slice(0, N + 2));
    for (let rep = 0; rep < SIZES.update_repetitions; rep++) {
      await send(signer, await mk.updateRoot.populateTransaction(t0.root), GAS.update);
      await measure({ sut: "S1", N, kind: "update_first", rep, state: "seeded" }, await mk.updateRoot.populateTransaction(t1.root));
      await measure({ sut: "S1", N, kind: "update_later", rep, state: "seeded" }, await mk.updateRoot.populateTransaction(t2.root));
    }
    check((await mk.root()) === t2.root, `S1 N=${N}: final root mismatch`);
    console.log(`S1 N=${N}: updates measured`);
  }
}

async function main() {
  [signer] = await ethers.getSigners();
  log = new RawLog("sweep_revoke", hre.network.name, Number((await ethers.provider.getNetwork()).chainId));
  await assertNoMocks(ethers.provider);
  try {
    await s2(await ethers.getContractFactory("KZGRevocation"));
    await s1(await ethers.getContractFactory("MerkleRevocation"));
  } finally {
    console.log(`wrote ${log.close({ sizes: SIZES.hardhat_sizes, batch_sizes: SIZES.batch_sizes })}`);
  }
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
