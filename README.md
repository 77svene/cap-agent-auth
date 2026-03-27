# CapAgent: Capability-Based Agent Authorization

## Overview

CapAgent implements a novel **Capability Token Protocol (CTP)** — a permission system where execution rights are encoded as on-chain NFTs with verifiable scope constraints. Unlike traditional CBAC or ERC-721 approval patterns, CapAgent introduces **Capability Scope Verification (CSV)**: a primitive that cryptographically binds action permissions to NFT ownership without requiring off-chain trust assumptions.

## Novelty Statement

This implementation introduces **Capability Scope Verification (CSV)** — a primitive where capability NFTs encode not just ownership but verifiable execution scope through on-chain state transitions. The CSV primitive enables:

1. **Dynamic Capability Revocation** — Revoke agent permissions without key rotation by burning capability NFTs
2. **Capability Inheritance Chains** — Sub-agents inherit parent capabilities through on-chain verification (not off-chain delegation)
3. **Scope-Bound Execution** — Each NFT encodes allowed action types and limits as immutable state
4. **Zero-Trust Capability Verification** — All capability checks happen on-chain; no off-chain manager required

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                              CapAgent System Architecture                        │
├─────────────────────────────────────────────────────────────────────────────────┤
│                                                                                  │
│  ┌─────────────────┐    ┌─────────────────────────────────────────────────┐    │
│  │   User Wallet   │    │              On-Chain Layer                      │    │
│  │   (EOA)         │    │  ┌─────────────────────────────────────────┐    │    │
│  └────────┬────────┘    │  │           CapabilityNFT.sol             │    │    │
│           │            │  │  - ERC-721 with scope encoding          │    │    │
│           │            │  │  - Dynamic capability minting           │    │    │
│           │            │  │  - Revocation without key rotation      │    │    │
│           │            │  └─────────────────────────────────────────┘    │    │
│           │            │  ┌─────────────────────────────────────────┐    │    │
│           │            │  │           AgentAuth.sol                 │    │    │
│           │            │  │  - Capability scope verification        │    │    │
│           │            │  │  - CSV primitive implementation         │    │    │
│           │            │  │  - Action type validation               │    │    │
│           │            │  └─────────────────────────────────────────┘    │    │
│           │            │  ┌─────────────────────────────────────────┐    │    │
│           │            │  │      CapabilityInheritance.sol          │    │    │
│           │            │  │  - Parent-child capability chains       │    │    │
│           │            │  │  - On-chain inheritance verification    │    │    │
│           │            │  └─────────────────────────────────────────┘    │    │
│           │            │                                                  │    │
│           │            │  ┌─────────────────────────────────────────┐    │    │
│           │            │  │           ExecutionEngine.sol           │    │    │
│           │            │  │  - Capability-bound execution           │    │    │
│           │            │  │  - Limit enforcement                    │    │    │
│           │            │  └─────────────────────────────────────────┘    │    │
│           │            │                                                  │    │
│           │            └──────────────────────────────────────────────────┘    │
│           │                                                                  │
│           ▼                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                        Node.js Agent Layer                               ││
│  │  ┌─────────────────────────────────────────────────────────────────┐    ││
│  │  │                    ExecutionEngine.js                            │    ││
│  │  │  - On-chain capability verification                              │    ││
│  │  │  - No private key exposure                                       │    ││
│  │  │  - Capability scope enforcement                                  │    ││
│  │  └─────────────────────────────────────────────────────────────────┘    ││
│  │  ┌─────────────────────────────────────────────────────────────────┐    ││
│  │  │                    CapabilityManager.js                          │    ││
│  │  │  - Capability minting/burning orchestration                      │    ││
│  │  │  - Inheritance chain management                                  │    ││
│  │  │  - NO on-chain trust assumption                                  │    ││
│  │  └─────────────────────────────────────────────────────────────────┘    ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│           │                                                                  │
│           ▼                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────────┐│
│  │                        Frontend Dashboard                                ││
│  │  ┌─────────────────────────────────────────────────────────────────┐    ││
│  │  │                         Dashboard.jsx                            │    ││
│  │  │  - Real-time capability visualization                            │    ││
│  │  │  - Mint/burn capability NFTs                                     │    ││
│  │  │  - Agent hierarchy management                                    │    ││
│  │  └─────────────────────────────────────────────────────────────────┘    ││
│  └─────────────────────────────────────────────────────────────────────────┘│
│                                                                                  │
└─────────────────────────────────────────────────────────────────────────────────┘

KEY SECURITY PRIMITIVES:
├── Capability Scope Verification (CSV) — On-chain capability validation
├── Dynamic Capability Revocation — Burn NFTs to revoke without key rotation
├── Capability Inheritance Chains — Parent-child capability verification
└── Zero-Trust Execution — All capability checks on-chain
```

## API Endpoints

### Smart Contract Functions

| Contract | Function | Parameters | Returns | Description |
|----------|----------|------------|---------|-------------|
| CapabilityNFT | `mintCapability` | `address agent, bytes32 actionType, uint256 limit` | `uint256 tokenId` | Mint capability NFT for agent |
| CapabilityNFT | `burnCapability` | `uint256 tokenId` | `void` | Revoke capability by burning NFT |
| CapabilityNFT | `getCapabilityScope` | `uint256 tokenId` | `tuple(actionType, limit, owner)` | Get capability scope |
| AgentAuth | `verifyCapability` | `address agent, bytes32 actionType` | `bool` | Verify agent has capability for action |
| AgentAuth | `executeWithCapability` | `bytes32 actionType, bytes data` | `bool success` | Execute with capability verification |
| CapabilityInheritance | `createInheritanceChain` | `address parent, address child` | `uint256 chainId` | Create parent-child capability chain |
| CapabilityInheritance | `inheritCapability` | `uint256 chainId, uint256 capabilityId` | `bool` | Inherit capability from parent |

### Node.js Agent API

| Method | Parameters | Returns | Description |
|--------|------------|---------|-------------|
| `verifyCapability(agent, actionType)` | `string agent, string actionType` | `Promise<boolean>` | Verify capability on-chain |
| `mintCapability(agent, actionType, limit)` | `string agent, string actionType, uint256 limit` | `Promise<string>` | Mint capability NFT |
| `burnCapability(tokenId)` | `string tokenId` | `Promise<void>` | Revoke capability |
| `getAgentCapabilities(agent)` | `string agent` | `Promise<Array>` | Get all agent capabilities |
| `createInheritanceChain(parent, child)` | `string parent, string child` | `Promise<string>` | Create inheritance chain |

## Deployment Instructions

### Prerequisites

```bash
node >= 18.0.0
npm >= 9.0.0
hardhat >= 2.19.0
```n
### Local Development

```bash
# Install dependencies
npm install

# Compile contracts
npx hardhat compile

# Run local testnet
npx hardhat node

# Deploy to local network
npx hardhat run scripts/deploy.js --network localhost

# Run tests
npx hardhat test
```

### Production Deployment

```bash
# Set environment variables
export PRIVATE_KEY=<your_private_key>
export RPC_URL=<your_rpc_url>
export CONTRACT_ADDRESS=<deployed_contract_address>

# Deploy to mainnet/testnet
npx hardhat run scripts/deploy.js --network <network_name>

# Verify contracts
npx hardhat verify --network <network_name> <contract_address>
```

### Network Configuration

```javascript
// hardhat.config.js
module.exports = {
  networks: {
    hardhat: { chainId: 31337 },
    sepolia: { url: process.env.SEPOLIA_RPC_URL, accounts: [process.env.PRIVATE_KEY] },
    polygon: { url: process.env.POLYGON_RPC_URL, accounts: [process.env.PRIVATE_KEY] },
    arbitrum: { url: process.env.ARBITRUM_RPC_URL, accounts: [process.env.PRIVATE_KEY] }
  }
};
```

## Usage Examples

### Mint Capability NFT

```javascript
const { ethers } = require("hardhat");

async function main() {
  const CapabilityNFT = await ethers.getContractFactory("CapabilityNFT");
  const capabilityNFT = await CapabilityNFT.deploy();
  await capabilityNFT.waitForDeployment();

  const agent = "0xAgentAddress";
  const actionType = ethers.id("TRADE");
  const limit = ethers.parseEther("1000");

  const tx = await capabilityNFT.mintCapability(agent, actionType, limit);
  const receipt = await tx.wait();
  const tokenId = receipt.events[0].args.tokenId;

  console.log("Capability NFT minted:", tokenId.toString());
}

main();
```

### Verify Capability

```javascript
const { ethers } = require("hardhat");

async function main() {
  const AgentAuth = await ethers.getContractFactory("AgentAuth");
  const agentAuth = await AgentAuth.deploy();
  await agentAuth.waitForDeployment();

  const agent = "0xAgentAddress";
  const actionType = ethers.id("TRANSFER");

  const hasCapability = await agentAuth.verifyCapability(agent, actionType);
  console.log("Agent has capability:", hasCapability);
}

main();
```

### Execute with Capability

```javascript
const { ethers } = require("hardhat");

async function main() {
  const ExecutionEngine = await ethers.getContractFactory("ExecutionEngine");
  const executionEngine = await ExecutionEngine.deploy();
  await executionEngine.waitForDeployment();

  const actionType = ethers.id("TRADE");
  const data = ethers.encodeFunctionData("trade", ["token", "amount"]);

  const success = await executionEngine.executeWithCapability(actionType, data);
  console.log("Execution successful:", success);
}

main();
```

## Security Considerations

### Capability Scope Verification (CSV)

The CSV primitive ensures that:

1. **No Off-Chain Trust** — All capability verification happens on-chain
2. **Immutable Scope** — Capability limits cannot be exceeded
3. **Revocable Permissions** — Capabilities can be burned without key rotation
4. **Inheritance Verification** — Parent-child capability chains verified on-chain

### Attack Vectors Mitigated

| Attack Vector | Mitigation |
|---------------|------------|
| Private Key Exposure | Capabilities verified on-chain, keys never exposed |
| Capability Forgery | NFT ownership required for capability verification |
| Scope Exceeding | On-chain limit enforcement |
| Unauthorized Delegation | Inheritance chains verified on-chain |
| Reentrancy | ReentrancyGuard on all capability modifications |

## Testing

```bash
# Run all tests
npx hardhat test

# Run specific test file
npx hardhat test test/CapAgent.test.js

# Run with gas reporting
npx hardhat test --gas-reporter

# Run with coverage
npx hardhat coverage
```

## Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open Pull Request

## License

MIT License - See LICENSE file for details

## Acknowledgments

- Auth0 for AI Agents Hackathon
- Solidity community for ERC-721 standards
- Hardhat for development tooling

## Contact

For questions or issues, please open an issue on GitHub.

---

**Capability Token Protocol v1.0** — Built for the future of agent authorization.
