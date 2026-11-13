/**
 * smoke.js — EXP-001 Hardhat step 2: precompile smoke test.
 *
 * Run: npx hardhat run eval/scripts/smoke.js --network hardhat
 *
 * For each vector in eval/data/inputs/smoke_vectors.json, calls the precompile
 * through PrecompileProbe with exactly its EIP-2537 price (must succeed with the
 * expected output) and with the price minus one (must fail). That measures the
 * price exactly. Writes eval/data/raw/smoke-<network>-<time>.jsonl and exits
 * non-zero on any failure.
 */
const hre = require("hardhat");
const { ethers } = hre;
const { INPUTS, readJson, RawLog, assertNoMocks, runtimeHash, check } = require("./lib/evalUtils");

const ADDR = { g1msm: "0x000000000000000000000000000000000000000c", pairing: "0x000000000000000000000000000000000000000f" };

async function main() {
  const chainId = Number((await ethers.provider.getNetwork()).chainId);
  const log = new RawLog("smoke", hre.network.name, chainId);
  await assertNoMocks(ethers.provider);
  const probe = await (await ethers.getContractFactory("PrecompileProbe")).deploy();
  await probe.waitForDeployment();
  const vectors = readJson(INPUTS, "smoke_vectors.json");
  let failures = 0;

  for (const [kind, list] of Object.entries({ g1msm: vectors.g1msm, pairing: vectors.pairing })) {
    for (const v of list) {
      const [okAt, outAt] = await probe.probe(ADDR[kind], v.input, v.price);
      const [okBelow] = await probe.probe(ADDR[kind], v.input, v.price - 1);
      const pass = okAt && outAt === v.expected_output && !okBelow;
      if (!pass) failures += 1;
      log.add({
        type: "smoke", precompile: kind, k: v.k, name: v.name || null, formula_price: v.price,
        succeeds_at_price: okAt, fails_below_price: !okBelow, output_matches: outAt === v.expected_output, pass,
      });
      console.log(`${kind} k=${v.k}${v.name ? " " + v.name : ""}: price ${v.price} ${pass ? "PASS" : "FAIL"}`);
    }
  }
  const file = log.close({ probe_address: await probe.getAddress(), probe_runtime_sha256: await runtimeHash(ethers.provider, await probe.getAddress()), failures });
  console.log(`wrote ${file}`);
  check(failures === 0, `${failures} smoke-test vector(s) failed: switch to the anvil fallback and record it in the manifest`);
}

main().catch((e) => { console.error(e); process.exitCode = 1; });
