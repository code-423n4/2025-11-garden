/** @type import('hardhat/config').HardhatUserConfig */
require("@nomicfoundation/hardhat-toolbox");
require("@nomicfoundation/hardhat-foundry");
import "@nomicfoundation/hardhat-ethers";
import { config } from "dotenv";
config();

module.exports = {
  solidity: {
    version: "0.8.28",
    settings: {
      optimizer: {
        enabled: true,
        runs: 10,
      },
      // viaIR: true,
    },
  },
  networks: {
    hardhat: {
      chainId: process.env.CHAIN_ID ? parseInt(process.env.CHAIN_ID) : 31337,
    },
    docker: {
      url: "http://0.0.0.0:8545",
      chainId: process.env.CHAIN_ID ? parseInt(process.env.CHAIN_ID) : 31337,
    },
    ETHsepolia: {
      url: process.env.SEPOLIA_RPC_URL || "",
      accounts: process.env.SEPOLIA_PRIVATE_KEY ? [process.env.SEPOLIA_PRIVATE_KEY] : [],
      chainId: 11155111,
    },
    ETHmainnet: {
      url: process.env.ETH_RPC_URL || "",
      accounts: process.env.ETH_PRIVATE_KEY ? [process.env.ETH_PRIVATE_KEY] : [],
      chainId: 1,
    },
    ARBsepolia: {
      url: process.env.ARB_SEPOLIA_RPC_URL || "",
      accounts: process.env.ARB_SEPOLIA_PRIVATE_KEY ? [process.env.ARB_SEPOLIA_PRIVATE_KEY] : [],
      chainId: 421614,
    },
    ARBmainnet: {
      url: process.env.ARB_RPC_URL || "",
      accounts: process.env.ARB_PRIVATE_KEY ? [process.env.ARB_PRIVATE_KEY] : [],
      chainId: 42161,
    }
  },
  etherscan: {
    apiKey: {
      docker: "garden",
      sepolia: process.env.ETHERSCAN_API_KEY || "",
      ETHmainnet: process.env.ETHERSCAN_API_KEY || "",
    },
    customChains: [
      {
        network: "docker",
        chainId: process.env.CHAIN_ID ? parseInt(process.env.CHAIN_ID) : 31337,
        urls: {
          apiURL: process.env.BLOCKSCOUT_URL
            ? process.env.BLOCKSCOUT_URL + "/api"
            : "http://localhost",
          browserURL: process.env.BLOCKSCOUT_URL
            ? process.env.BLOCKSCOUT_URL
            : "http://localhost",
        },
      },
    ],
  },
};
