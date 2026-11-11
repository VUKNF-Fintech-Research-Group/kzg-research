/**
 * deploy.js
 *
 * Deploy KZGRevocation and MerkleRevocation, verify their source on the block
 * explorer, and write a deployment record.
 *
 * Usage:
 *   npx hardhat run scripts/deploy.js --network hoodi
 *
 * Needs PRIVATE_KEY (and ETHERSCAN_API_KEY for verification) in contracts/.env.
 * Output: deployments/<network>.json (addresses and transaction hashes only).
 *
 * Both contracts start from the empty revoked set: the KZG commitment to
 * f = 1 (the G1 generator) and the Merkle root of the single leaf (0, MAX_ID).
 */

const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
const { REPO_ROOT, TxQueue, gitCommit, readUntil } = require("./lib/benchUtils");
const { GAS_LIMIT: KZG_GAS } = require("./lib/kzgGasSweep");
const { GAS_LIMIT: MERKLE_GAS } = require("./lib/merkleSweep");
const { buildRevocationTree } = require("./merkleHelper");
const { commitments } = require("../test/fixtures/kzg_batch_sweep.json");

const { ethers, network } = hre;

async function verifySource(address, constructorArguments) {
  if (network.name === "hardhat") return "skipped (local network)";
  if (!process.env.ETHERSCAN_API_KEY) return "skipped (no ETHERSCAN_API_KEY)";
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      await hre.run("verify:verify", { address, constructorArguments });
      return "verified";
    } catch (err) {
      if (/already verified/i.test(err.message)) return "verified";
      console.log(`  verification attempt ${attempt} failed: ${err.message.split("\n")[0]}`);
      await new Promise((resolve) => setTimeout(resolve, 20000)); // explorer may not have indexed it yet
    }
  }
  return "failed";
}

async function main() {
  const [deployer] = await ethers.getSigners();
  if (!deployer) throw new Error("no deployer account: set PRIVATE_KEY in contracts/.env");
  const { chainId } = await ethers.provider.getNetwork();
  console.log(`Network  : ${network.name} (chain ${chainId})`);
  console.log(`Deployer : ${deployer.address}`);
  console.log(`Balance  : ${ethers.formatEther(await ethers.provider.getBalance(deployer.address))} ETH\n`);

  const queue = new TxQueue(deployer);
  const emptyCommitment = commitments[0];
  const emptyRoot = buildRevocationTree([]).root;

  const kzg = await queue.deploy(await ethers.getContractFactory("KZGRevocation"), [emptyCommitment], KZG_GAS.deploy);
  const kzgAddress = await kzg.contract.getAddress();
  console.log(`KZGRevocation    : ${kzgAddress} (${kzg.record.gas_used.toLocaleString()} gas)`);

  const merkle = await queue.deploy(await ethers.getContractFactory("MerkleRevocation"), [emptyRoot], MERKLE_GAS.deploy);
  const merkleAddress = await merkle.contract.getAddress();
  console.log(`MerkleRevocation : ${merkleAddress} (${merkle.record.gas_used.toLocaleString()} gas)`);

  await readUntil(() => kzg.contract.commitment(), emptyCommitment, "KZGRevocation commitment");
  await readUntil(() => merkle.contract.root(), emptyRoot, "MerkleRevocation root");

  console.log("\nVerifying source...");
  const kzgVerified = await verifySource(kzgAddress, [emptyCommitment]);
  const merkleVerified = await verifySource(merkleAddress, [emptyRoot]);
  console.log(`KZGRevocation    : ${kzgVerified}`);
  console.log(`MerkleRevocation : ${merkleVerified}`);

  const record = {
    network: network.name,
    chain_id: Number(chainId),
    deployer: deployer.address,
    commit: gitCommit(),
    date: new Date().toISOString(),
    pairing_backend: "eip2537",
    contracts: {
      KZGRevocation: {
        address: kzgAddress,
        deploy_tx_hash: kzg.record.tx_hash,
        block_number: kzg.record.block_number,
        deploy_gas: kzg.record.gas_used,
        constructor_args: { initialCommitment: emptyCommitment },
        source_verification: kzgVerified,
      },
      MerkleRevocation: {
        address: merkleAddress,
        deploy_tx_hash: merkle.record.tx_hash,
        block_number: merkle.record.block_number,
        deploy_gas: merkle.record.gas_used,
        constructor_args: { initialRoot: emptyRoot },
        source_verification: merkleVerified,
      },
    },
  };
  const outPath = path.join(REPO_ROOT, "deployments", `${network.name}.json`);
  fs.mkdirSync(path.dirname(outPath), { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(record, null, 2) + "\n");
  console.log(`\nDeployment record written to ${path.relative(REPO_ROOT, outPath)}`);
}

main().catch((err) => {
  console.error(`\nDEPLOY FAILED: ${err.message}`);
  process.exit(1);
});
