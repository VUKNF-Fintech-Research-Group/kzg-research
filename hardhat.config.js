require("@nomicfoundation/hardhat-chai-matchers");
require("@nomicfoundation/hardhat-ethers");
require("@nomicfoundation/hardhat-verify");
require("dotenv").config({ path: "./contracts/.env" });

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    compilers: [
      {
        version: "0.8.20",
        settings: { optimizer: { enabled: true, runs: 200 } },
      },
    ],
  },
  networks: {
    hardhat: {
      // In-process Hardhat Network – no external node required.
      // Prague enables the EIP-2537 BLS12-381 precompiles (0x0b–0x11).
      hardfork: "prague",
    },
    hoodi: {
      url:      process.env.HOODI_RPC || "https://rpc.hoodi.ethpandaops.io",
      chainId:  560048,
      accounts: process.env.PRIVATE_KEY ? [`0x${process.env.PRIVATE_KEY.replace(/^0x/, "")}`] : [],
    },
  },
  // Source verification. The key comes from contracts/.env and is never committed.
  etherscan: {
    apiKey: process.env.ETHERSCAN_API_KEY || "",
    customChains: [
      {
        network: "hoodi",
        chainId: 560048,
        urls: {
          apiURL: "https://api.etherscan.io/v2/api?chainid=560048",
          browserURL: "https://hoodi.etherscan.io",
        },
      },
    ],
  },
  sourcify: { enabled: false },
  paths: {
    sources:   "./contracts",
    artifacts: "./artifacts",
    cache:     "./cache",
  },
};
