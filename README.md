# 🛡️ CapAgent: Capability-Based Agent Authorization

> **Revolutionizing AI security by treating permissions as tradable, revocable NFT assets.**

[![Hackathon](https://img.shields.io/badge/Hackathon-Authorized%20Act-blue)](https://github.com/77svene/cap-agent-auth)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Solidity](https://img.shields.io/badge/Smart%20Contracts-Solidity-orange)](https://soliditylang.org/)
[![Node.js](https://img.shields.io/badge/Agent-Node.js-blue)](https://nodejs.org/)
[![Hardhat](https://img.shields.io/badge/Testing-Hardhat-purple)](https://hardhat.org/)

---

## 🚀 One-Line Pitch
CapAgent introduces the first **NFT-based Capability Tokens** that dynamically grant execution rights to AI agents without exposing private keys, shifting Web3 security from identity-based auth to granular, on-chain capability verification.

---

## 🧩 Problem & Solution

### ❌ The Problem
Traditional AI agent authorization in Web3 relies on static wallet signatures or identity-based authentication. This creates critical vulnerabilities:
*   **Privilege Creep:** Agents often hold full wallet access, risking total asset loss if compromised.
*   **Inflexible Revocation:** Revoking access requires burning keys or complex multisig changes.
*   **Lack of Granularity:** Hard to define specific action scopes (e.g., "Trade ETH" vs. "Transfer USDC") without separate keys.
*   **Identity Leakage:** Execution often reveals the underlying owner's identity rather than just the permission scope.

### ✅ The Solution
**CapAgent** implements a **Capability-Based Access Control (CBAC)** primitive.
*   **Permission as Assets:** Execution rights are minted as **ERC-721 Capability NFTs**.
*   **Dynamic Limits:** **ERC-20** tokens define spending limits attached to the capability.
*   **On-Chain Verification:** The `ExecutionEngine` verifies NFT ownership and action type before execution.
*   **Decoupled Identity:** The agent proves *permission*, not *ownership*.
*   **Inheritance:** Sub-agents can inherit capabilities from parent agents via `CapabilityInheritance.sol`.

---

## 🏗️ Architecture

```text
+----------------+       +---------------------+       +-------------------+
|   User Wallet  |       |   CapAgent Contract |       |   AI Agent Node   |
| (Owner)        |<----->| (Solidity)          |<----->| (Node.js)         |
+-------+--------+       +----------+----------+       +--------+----------+
        |                           |                          |
        | 1. Mint Capability NFT    |                          |
        |    (ERC-721 + ERC-20)     |                          |
        v                           v                          v
+-------+--------+       +----------+----------+       +--------+----------+
|   Dashboard    |       |   Execution Engine  |       |   CapabilityMgr   |
| (React/HTML)   |       |   (Verify NFT &     |       |   (Logic Layer)   |
+----------------+       |    Action Scope)    |       +-------------------+
                         +----------+----------+
                                    |
                                    v
                         +----------+----------+
                         |   Blockchain (EVM)  |
                         |   (Gas & State)     |
                         +---------------------+
```

---

## 🛠️ Tech Stack

| Component | Technology |
| :--- | :--- |
| **Smart Contracts** | Solidity 0.8.19, Hardhat |
| **Agent Logic** | Node.js 18+, Ethers.js |
| **Frontend** | React, HTML5, CSS3 |
| **Security** | ERC-721, ERC-20, Access Control |
| **Testing** | Mocha, Chai, Hardhat Network |

---

## 📸 Demo

### Dashboard Visualization
![CapAgent Dashboard](https://via.placeholder.com/800x400/000000/FFFFFF?text=CapAgent+Dashboard:+Active+Capabilities+&+Limits)

### Agent Execution Flow
![Execution Flow](https://via.placeholder.com/800x400/1a1a1a/00ff00?text=On-Chain+Verification+Log:+Action+Approved)

---

## ⚙️ Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/77svene/cap-agent-auth
cd cap-agent-auth
```

### 2. Install Dependencies
```bash
npm install
```

### 3. Configure Environment
Create a `.env` file in the root directory with your private key and RPC URL:
```env
PRIVATE_KEY=your_private_key_here
RPC_URL=https://sepolia.infura.io/v3/your_project_id
CONTRACT_ADDRESS=0x...
```

### 4. Deploy Contracts
```bash
npx hardhat run scripts/deploy.js --network sepolia
```

### 5. Run the Agent & Dashboard
```bash
# Terminal 1: Start Node.js Agent
npm start

# Terminal 2: Start Frontend (if applicable)
npm run dev
```

---

## 🔌 API Endpoints

| Method | Endpoint | Description | Payload |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/mint-capability` | Mint a new Capability NFT for an agent | `{ agentId, actionType, limit }` |
| `POST` | `/api/execute` | Request execution of an action | `{ agentId, action, params }` |
| `GET` | `/api/capabilities/:agentId` | Retrieve active capabilities for an agent | `N/A` |
| `POST` | `/api/revoke` | Burn a specific capability NFT | `{ agentId, tokenId }` |
| `GET` | `/api/inheritance` | Check capability inheritance tree | `{ parentId }` |

---

## 👥 Team

**Built by VARAKH BUILDER — autonomous AI agent**

*   **Core Logic:** VARAKH BUILDER (Autonomous)
*   **Smart Contracts:** Solidity Engine
*   **Frontend:** UI Module

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

> **Note:** This project was built for the **Authorized Act: Auth0 for AI Agents** hackathon. It demonstrates a composable authorization model for autonomous agents, distinct from standard wallet signatures or ZK proofs. By treating permissions as assets, we enable complex agent hierarchies where sub-agents inherit capabilities from parent agents, setting a new standard for agent security in Web3.