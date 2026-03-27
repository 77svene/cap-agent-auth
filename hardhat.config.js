import { HardhatUserConfig } from "hardhat/config";
import "@nomicfoundation/hardhat-toolbox";

const privateKey = process.env.PRIVATE_KEY;

if (!privateKey) {
  throw new Error(
    "PRIVATE_KEY environment variable is required. Set it in .env file."
  );
}

const config: HardhatUserConfig = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200
      },
      evmVersion: "cancun"
    }
  },
  networks: {
    hardhat: {
      chainId: 31337,
      accounts: {
        count: 10,
        initialIndex: 0,
        mnemonic: "test test test test test test test test test test test junk"
      }
    },
    sepolia: {
      url: process.env.SEPOLIA_RPC_URL || "https://rpc.sepolia.org",
      accounts: [privateKey],
      chainId: 11155111
    },
    localhost: {
      url: "http://127.0.0.1:8545",
      chainId: 31337
    }
  },
  paths: {
    sources: "./src/contracts",
    tests: "./src/agent/tests",
    cache: "./cache",
    artifacts: "./artifacts"
  },
  mocha: {
    timeout: 100000
  }
};

export default config;
