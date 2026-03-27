import { ethers } from 'ethers';
import { CapabilityManager } from './CapabilityManager.js';

export class ExecutionEngine {
  #provider;
  #wallet;
  #authContract;
  #capabilityManager;
  #agentAddress;
  #capabilityCache = new Map();
  #actionQueue = [];
  #isExecuting = false;
  #maxGasLimit = 3000000;
  #signatureCache = new Map();
  #cacheTTL = 300000;

  constructor(providerUrl, privateKey, authContractAddress, capabilityManagerAddress) {
    if (!providerUrl || typeof providerUrl !== 'string') {
      throw new Error('Invalid provider URL');
    }
    if (!privateKey || typeof privateKey !== 'string' || privateKey.length < 64) {
      throw new Error('Invalid private key format');
    }
    if (!authContractAddress || !ethers.isAddress(authContractAddress)) {
      throw new Error('Invalid AgentAuth contract address');
    }
    if (!capabilityManagerAddress || !ethers.isAddress(capabilityManagerAddress)) {
      throw new Error('Invalid CapabilityManager contract address');
    }

    this.#provider = new ethers.JsonRpcProvider(providerUrl);
    this.#wallet = new ethers.Wallet(privateKey, this.#provider);
    this.#agentAddress = this.#wallet.address;
    
    const authABI = [
      'function executeAction(address agent, bytes32 actionHash, bytes signature) external returns (bool)',
      'function verifyCapability(address agent, uint256 tokenId, bytes32 actionType) external view returns (bool)',
      'function getAgentCapabilities(address agent) external view returns (uint256[] memory)',
      'function getCapabilityLimits(uint256 tokenId) external view returns (uint256, uint256, uint256)',
      'function isCapabilityActive(uint256 tokenId) external view returns (bool)',
      'function getInheritanceChain(address agent) external view returns (address[] memory)',
      'event CapabilityGranted(address indexed agent, uint256 indexed tokenId, bytes32 actionType)',
      'event CapabilityRevoked(address indexed agent, uint256 indexed tokenId)',
      'event ActionExecuted(address indexed agent, bytes32 indexed actionHash, uint256 timestamp)'
    ];
    
    this.#authContract = new ethers.Contract(authContractAddress, authABI, this.#wallet);
    this.#capabilityManager = new CapabilityManager(capabilityManagerAddress, this.#wallet);
  }

  async #loadCapabilitiesFromContract() {
    try {
      const capabilities = await this.#authContract.getAgentCapabilities(this.#agentAddress);
      const capabilityData = await Promise.all(
        capabilities.map(async (tokenId) => {
          const isActive = await this.#authContract.isCapabilityActive(tokenId);
          const limits = await this.#authContract.getCapabilityLimits(tokenId);
          return { tokenId, isActive, limits };
        })
      );
      
      capabilityData.forEach(cap => {
        this.#capabilityCache.set(cap.tokenId.toString(), cap);
      });
      
      return capabilityData;
    } catch (error) {
      console.error('Failed to load capabilities:', error.message);
      return [];
    }
  }

  async #loadInheritanceChain() {
    try {
      const chain = await this.#authContract.getInheritanceChain(this.#agentAddress);
      const parentCapabilities = new Map();
      
      for (const parentAddress of chain) {
        if (parentAddress === ethers.ZeroAddress) continue;
        
        const parentCaps = await this.#authContract.getAgentCapabilities(parentAddress);
        for (const tokenId of parentCaps) {
          const isActive = await this.#authContract.isCapabilityActive(tokenId);
          if (isActive) {
            parentCapabilities.set(tokenId.toString(), true);
          }
        }
      }
      
      return parentCapabilities;
    } catch (error) {
      console.error('Failed to load inheritance chain:', error.message);
      return new Map();
    }
  }

  async #validateSignature(actionHash, signature) {
    const cacheKey = `${actionHash}-${signature}`;
    const cached = this.#signatureCache.get(cacheKey);
    
    if (cached && Date.now() - cached.timestamp < this.#cacheTTL) {
      return cached.valid;
    }
    
    try {
      const recoveredAddress = ethers.verifyMessage(
        ethers.getBytes(actionHash),
        signature
      );
      
      const isValid = recoveredAddress === this.#agentAddress;
      this.#signatureCache.set(cacheKey, { valid: isValid, timestamp: Date.now() });
      
      return isValid;
    } catch (error) {
      return false;
    }
  }

  async #checkCapabilityLimits(tokenId, actionType) {
    const cap = this.#capabilityCache.get(tokenId.toString());
    if (!cap || !cap.isActive) return false;
    
    const [dailyLimit, actionLimit, timestamp] = cap.limits;
    const now = Math.floor(Date.now() / 1000);
    
    if (now - timestamp > 86400) {
      return true;
    }
    
    return actionLimit > 0;
  }

  async #executeWithRetry(action, maxRetries = 3) {
    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const tx = await action();
        const receipt = await tx.wait();
        return { success: true, receipt, attempt };
      } catch (error) {
        if (attempt === maxRetries - 1) {
          return { success: false, error: error.message, attempt };
        }
        await new Promise(resolve => setTimeout(resolve, 1000 * (attempt + 1)));
      }
    }
    return { success: false, error: 'Max retries exceeded', attempt: maxRetries };
  }

  async executeAction(actionType, actionData, signature) {
    const actionHash = ethers.keccak256(ethers.toUtf8Bytes(JSON.stringify({
      type: actionType,
      data: actionData,
      timestamp: Date.now()
    })));
    
    const isValidSignature = await this.#validateSignature(actionHash, signature);
    if (!isValidSignature) {
      throw new Error('Invalid signature for action');
    }
    
    const capabilities = await this.#loadCapabilitiesFromContract();
    const inheritanceChain = await this.#loadInheritanceChain();
    
    const hasCapability = capabilities.some(cap => {
      if (!cap.isActive) return false;
      return inheritanceChain.has(cap.tokenId.toString()) || 
             this.#capabilityCache.get(cap.tokenId.toString())?.isActive;
    });
    
    if (!hasCapability) {
      throw new Error('No valid capability for action type');
    }
    
    const action = async () => {
      return await this.#authContract.executeAction(
        this.#agentAddress,
        actionHash,
        signature
      );
    };
    
    const result = await this.#executeWithRetry(action);
    
    if (result.success) {
      console.log(`Action ${actionType} executed successfully`);
      return { success: true, actionHash, receipt: result.receipt };
    }
    
    throw new Error(`Action execution failed: ${result.error}`);
  }

  async executeBatch(actions) {
    const results = [];
    
    for (const action of actions) {
      try {
        const result = await this.executeAction(action.type, action.data, action.signature);
        results.push({ action: action.type, ...result });
      } catch (error) {
        results.push({ action: action.type, success: false, error: error.message });
      }
    }
    
    return results;
  }

  async getAgentStatus() {
    const capabilities = await this.#loadCapabilitiesFromContract();
    const inheritanceChain = await this.#loadInheritanceChain();
    
    return {
      agentAddress: this.#agentAddress,
      capabilities: capabilities.map(cap => ({
        tokenId: cap.tokenId.toString(),
        isActive: cap.isActive,
        limits: cap.limits
      })),
      inheritedCapabilities: Array.from(inheritanceChain.keys()),
      totalCapabilities: capabilities.length,
      activeCapabilities: capabilities.filter(c => c.isActive).length
    };
  }

  async refreshCapabilities() {
    await this.#loadCapabilitiesFromContract();
    await this.#loadInheritanceChain();
    return await this.getAgentStatus();
  }

  async revokeCapability(tokenId) {
    try {
      const tx = await this.#capabilityManager.revokeCapability(this.#agentAddress, tokenId);
      const receipt = await tx.wait();
      this.#capabilityCache.delete(tokenId.toString());
      return { success: true, receipt };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  async grantCapability(actionType, limits) {
    try {
      const tx = await this.#capabilityManager.grantCapability(
        this.#agentAddress,
        actionType,
        limits
      );
      const receipt = await tx.wait();
      await this.refreshCapabilities();
      return { success: true, receipt };
    } catch (error) {
      return { success: false, error: error.message };
    }
  }

  async verifyCapability(tokenId, actionType) {
    try {
      const isValid = await this.#authContract.verifyCapability(
        this.#agentAddress,
        tokenId,
        ethers.keccak256(ethers.toUtf8Bytes(actionType))
      );
      return isValid;
    } catch (error) {
      return false;
    }
  }

  async getBalance() {
    return await this.#provider.getBalance(this.#agentAddress);
  }

  async getNonce() {
    return await this.#provider.getTransactionCount(this.#agentAddress);
  }

  async signMessage(message) {
    return await this.#wallet.signMessage(ethers.toUtf8Bytes(message));
  }

  async signTypedData(domain, types, value) {
    return await this.#wallet.signTypedData(domain, types, value);
  }

  async getGasPrice() {
    return await this.#provider.getGasPrice();
  }

  async estimateGas(action) {
    try {
      return await this.#provider.estimateGas(action);
    } catch (error) {
      return null;
    }
  }

  async #processQueue() {
    if (this.#isExecuting || this.#actionQueue.length === 0) return;
    
    this.#isExecuting = true;
    
    while (this.#actionQueue.length > 0) {
      const action = this.#actionQueue.shift();
      try {
        await this.executeAction(action.type, action.data, action.signature);
      } catch (error) {
        console.error('Queue action failed:', error.message);
      }
    }
    
    this.#isExecuting = false;
  }

  queueAction(type, data, signature) {
    this.#actionQueue.push({ type, data, signature });
    this.#processQueue();
  }

  clearQueue() {
    this.#actionQueue = [];
  }

  getQueueLength() {
    return this.#actionQueue.length;
  }

  async destroy() {
    this.#actionQueue = [];
    this.#capabilityCache.clear();
    this.#signatureCache.clear();
  }
}

export default ExecutionEngine;
