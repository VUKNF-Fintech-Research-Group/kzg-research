/**
 * deployMerkle.js
 *
 * Deploy MerkleRevocation.sol to the configured network and write the
 * deployment record to deployments/merkle_<network>.json.
 *
 * Usage:
 *   npx hardhat run scripts/deployMerkle.js --network hardhat
 *   npx hardhat run scripts/deployMerkle.js --network hoodi
 *
 * Requires PRIVATE_KEY env var for live networks (set in .env or shell).
 */

const { ethers } = require("hardhat");
const fs   = require("fs");
const path = require("path");

async function main() {
  console.log(`Deploying MerkleRevocation.sol`);
  console.log(`Network  : ${network.name}`);

  const signers = await ethers.getSigners();
  if (signers.length === 0) {
    console.error(
      "\nError: no deployer account configured.\n" +
      "Set your private key and RPC URL before running:\n\n" +
      "  export PRIVATE_KEY=<your_hex_private_key_without_0x>\n" +
      "  export HOODI_RPC_URL=https://rpc.hoodi.ethpandaops.io\n\n" +
      "Then re-run:\n" +
      "  npx hardhat run scripts/deployMerkle.js --network hoodi"
    );
    process.exit(1);
  }
  const [deployer] = signers;
  console.log(`Deployer : ${deployer.address}`);

  const balance = await ethers.provider.getBalance(deployer.address);
  console.log(`Balance  : ${ethers.formatEther(balance)} ETH\n`);

  // Deploy with a zero root; the owner will call updateRoot() to set the
  // first revocation-set root after deployment.
  const Factory = await ethers.getContractFactory("MerkleRevocation");
  const merkle  = await Factory.deploy(ethers.ZeroHash);
  await merkle.waitForDeployment();

  const address     = await merkle.getAddress();
  const deployedAt  = new Date().toISOString();
  const deployBlock = merkle.deploymentTransaction()?.blockNumber ?? null;

  console.log(`Contract : ${address}`);
  console.log(`Block    : ${deployBlock ?? "pending"}`);
  console.log(`Time     : ${deployedAt}`);

  // Persist deployment record
  const record = {
    network:    network.name,
    contract:   "MerkleRevocation",
    address,
    deployer:   deployer.address,
    deployedAt,
    blockNumber: deployBlock,
  };

  const outDir  = path.join(__dirname, "..", "deployments");
  const outPath = path.join(outDir, `merkle_${network.name}.json`);
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(outPath, JSON.stringify(record, null, 2));
  console.log(`\nDeployment record written to: ${outPath}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
