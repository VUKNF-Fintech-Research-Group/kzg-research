require("@nomicfoundation/hardhat-chai-matchers");
require("@nomicfoundation/hardhat-ethers");
require("dotenv").config({ path: "./contracts/.env" });

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    compilers: [
      {
        version: "0.8.20",
        settings: { optimizer: { enabled: true, runs: 200 } },
      },
      {
        // KZGVerifier_flattened.sol pins to exact 0.8.19
        version: "0.8.19",
        settings: { optimizer: { enabled: true, runs: 200 } },
      },
    ],
  },
  networks: {
    hardhat: {
      // In-process Hardhat Network – no external node required
    },
    hoodi: {
      url:      process.env.HOODI_RPC || "https://rpc.hoodi.ethpandaops.io",
      chainId:  560048,
      accounts: process.env.PRIVATE_KEY ? [`0x${process.env.PRIVATE_KEY.replace(/^0x/, "")}`] : [],
    },
  },
  paths: {
    sources:   "./contracts",
    artifacts: "./artifacts",
    cache:     "./cache",
  },
};
