const { ethers } = require('ethers');

class CapabilityManager {
  constructor(provider, walletAddress, contractAddress, agentId) {
    if (!provider) throw new Error('Provider is required');
    if (!walletAddress || !ethers.isAddress(walletAddress)) {
      throw new Error('Valid wallet address is required');
    }
    if (!contractAddress || !ethers.isAddress(contractAddress)) {
      throw new Error('Valid contract address is required');
    }
    if (!agentId || typeof agentId !== 'string' || agentId.length < 1) {
      throw new Error('Valid agent ID is required');
    }

    this.provider = provider;
    this.walletAddress = walletAddress.toLowerCase();
    this.contractAddress = contractAddress.toLowerCase();
    this.agentId = agentId;
    this.capabilities = new Map();
    this.actionLimits = new Map();
    this.authorizationCache = new Map();
    this.cacheTTL = 30000;
    this.maxGasPrice = 100000000000;
    this.minGasLimit = 50000;
    this.maxGasLimit = 5000000;
    this.nonce = 0;
    this.pendingAuthorizations = new Map();
    this.revocationEvents = [];
    this.capabilityRegistry = new Set();
  }

  async initialize() {
    const blockNumber = await this.provider.getBlockNumber();
    const chainId = await this.provider.getChainId();
    const networkName = chainId === 1 ? 'mainnet' : chainId === 5 ? 'goerli' : chainId === 137 ? 'polygon' : 'unknown';
    
    this.chainId = Number(chainId);
    this.networkName = networkName;
    this.initializedAt = blockNumber;
    
    await this.loadAllCapabilities();
    await this.verifyCapabilityIntegrity();
    
    return {
      chainId: this.chainId,
      networkName: this.networkName,
      initializedAt: this.initializedAt,
      capabilityCount: this.capabilities.size,
      agentId: this.agentId,
      walletAddress: this.walletAddress
    };
  }

  async loadAllCapabilities() {
    const contractInterface = new ethers.utils.Interface([
      'function ownerOf(uint256 tokenId) view returns (address)',
      'function capabilityType(uint256 tokenId) view returns (uint8)',
      'function capabilityLimit(uint256 tokenId) view returns (uint256)',
      'function capabilityExpiry(uint256 tokenId) view returns (uint256)',
      'function getAgentCapabilities(address agent) view returns (uint256[] memory)',
      'function isCapabilityActive(uint256 tokenId) view returns (bool)',
      'event CapabilityMinted(uint256 indexed tokenId, address indexed owner, uint8 indexed capabilityType, uint256 limit)',
      'event CapabilityRevoked(uint256 indexed tokenId, address indexed agent)',
      'event CapabilityTransferred(uint256 indexed tokenId, address indexed from, address indexed to)'
    ]);

    const contract = new ethers.Contract(this.contractAddress, contractInterface, this.provider);
    const agentCapabilities = await contract.getAgentCapabilities(this.walletAddress);
    
    for (const tokenId of agentCapabilities) {
      try {
        const owner = await contract.ownerOf(tokenId);
        if (owner.toLowerCase() !== this.walletAddress) continue;
        
        const capabilityType = await contract.capabilityType(tokenId);
        const capabilityLimit = await contract.capabilityLimit(tokenId);
        const capabilityExpiry = await contract.capabilityExpiry(tokenId);
        const isActive = await contract.isCapabilityActive(tokenId);
        
        if (!isActive) continue;
        
        const now = Math.floor(Date.now() / 1000);
        if (capabilityExpiry > 0 && now > capabilityExpiry) continue;
        
        const actionType = this.parseCapabilityType(capabilityType);
        const limit = Number(capabilityLimit);
        
        this.capabilities.set(Number(tokenId), {
          tokenId: Number(tokenId),
          actionType,
          limit,
          expiry: capabilityExpiry,
          mintedAt: now - 3600,
          verified: true
        });
        
        this.actionLimits.set(actionType, Math.max(
          this.actionLimits.get(actionType) || 0,
          limit
        ));
        
        this.capabilityRegistry.add(Number(tokenId));
      } catch (error) {
        if (error.code !== 'CALL_EXCEPTION') throw error;
      }
    }
    
    return this.capabilities.size;
  }

  parseCapabilityType(type) {
    const typeMap = {
      0: 'READ',
      1: 'WRITE',
      2: 'TRANSFER',
      3: 'EXECUTE',
      4: 'DEPLOY',
      5: 'ADMIN',
      6: 'MINT',
      7: 'BURN',
      8: 'PAUSE',
      9: 'UNPAUSE',
      10: 'UPGRADE',
      11: 'CONFIGURE',
      12: 'AUTHENTICATE',
      13: 'VERIFY',
      14: 'SIGN',
      15: 'ENCRYPT',
      16: 'DECRYPT',
      17: 'COMPUTE',
      18: 'STORE',
      19: 'RETRIEVE'
    };
    return typeMap[type] || 'UNKNOWN';
  }

  async verifyCapabilityIntegrity() {
    const contractInterface = new ethers.utils.Interface([
      'function verifyCapabilityProof(uint256 tokenId, address agent, bytes32 actionHash) view returns (bool)'
    ]);
    
    const contract = new ethers.Contract(this.contractAddress, contractInterface, this.provider);
    
    for (const [tokenId, capability] of this.capabilities) {
      const actionHash = ethers.keccak256(
        ethers.utils.defaultAbiCoder.encode(
          ['address', 'string', 'uint256'],
          [this.walletAddress, capability.actionType, capability.limit]
        )
      );
      
      try {
        const isValid = await contract.verifyCapabilityProof(tokenId, this.walletAddress, actionHash);
        capability.verified = isValid;
        
        if (!isValid) {
          this.capabilities.delete(tokenId);
          this.actionLimits.delete(capability.actionType);
          this.capabilityRegistry.delete(tokenId);
        }
      } catch (error) {
        capability.verified = false;
      }
    }
    
    return Array.from(this.capabilities.values()).filter(c => c.verified).length;
  }

  async requestAuthorization(actionType, targetAddress, parameters, gasLimit = 100000) {
    if (!this.capabilities.size) {
      throw new Error('No capabilities loaded for agent');
    }
    
    const now = Math.floor(Date.now() / 1000);
    const nonce = this.nonce++;
    const actionHash = ethers.keccak256(
      ethers.utils.defaultAbiCoder.encode(
        ['address', 'string', 'address', 'bytes', 'uint256', 'uint256'],
        [this.walletAddress, actionType, targetAddress, ethers.utils.defaultAbiCoder.encode(['bytes'], [parameters]), nonce, now]
      )
    );
    
    const cachedAuth = this.authorizationCache.get(actionHash);
    if (cachedAuth && now - cachedAuth.timestamp < this.cacheTTL / 1000) {
      return cachedAuth.result;
    }
    
    if (gasLimit < this.minGasLimit || gasLimit > this.maxGasLimit) {
      throw new Error(`Gas limit must be between ${this.minGasLimit} and ${this.maxGasLimit}`);
    }
    
    const contractInterface = new ethers.utils.Interface([
      'function executeWithCapability(address agent, uint256 tokenId, string action, address target, bytes data, uint256 gasLimit) returns (bool)'
    ]);
    
    const contract = new ethers.Contract(this.contractAddress, contractInterface, this.provider);
    
    const capability = this.findValidCapability(actionType);
    if (!capability) {
      throw new Error(`No valid capability found for action: ${actionType}`);
    }
    
    if (capability.limit > 0 && this.actionLimits.get(actionType) >= capability.limit) {
      throw new Error(`Action limit exceeded for ${actionType}`);
    }
    
    const gasPrice = await this.provider.getGasPrice();
    if (gasPrice > this.maxGasPrice) {
      throw new Error('Gas price too high');
    }
    
    const tx = {
      to: this.contractAddress,
      data: contractInterface.encodeFunctionData('executeWithCapability', [
        this.walletAddress,
        capability.tokenId,
        actionType,
        targetAddress,
        parameters,
        gasLimit
      ]),
      gasLimit: gasLimit,
      gasPrice: gasPrice
    };
    
    const pendingId = `${actionHash}-${nonce}`;
    this.pendingAuthorizations.set(pendingId, {
      actionHash,
      actionType,
      tokenId: capability.tokenId,
      timestamp: now,
      status: 'pending'
    });
    
    try {
      const receipt = await this.provider.sendTransaction(tx);
      const txResult = await receipt.wait();
      
      const success = txResult.status === 1;
      
      this.authorizationCache.set(actionHash, {
        result: success,
        txHash: receipt.hash,
        timestamp: now
      });
      
      if (success) {
        this.pendingAuthorizations.delete(pendingId);
        this.revocationEvents.push({
          actionHash,
          tokenId: capability.tokenId,
          timestamp: now,
          status: 'executed'
        });
      }
      
      return { success, txHash: receipt.hash, gasUsed: txResult.gasUsed };
    } catch (error) {
      this.pendingAuthorizations.delete(pendingId);
      throw new Error(`Authorization failed: ${error.message}`);
    }
  }

  findValidCapability(actionType) {
    const now = Math.floor(Date.now() / 1000);
    
    for (const [tokenId, capability] of this.capabilities) {
      if (capability.actionType === actionType && 
          capability.verified && 
          (capability.expiry === 0 || now < capability.expiry)) {
        return capability;
      }
    }
    
    return null;
  }

  async getAgentStatus() {
    const contractInterface = new ethers.utils.Interface([
      'function getAgentStatus(address agent) view returns (uint256 capabilityCount, uint256 activeCapabilities, uint256 totalLimit, bool isAuthorized)'
    ]);
    
    const contract = new ethers.Contract(this.contractAddress, contractInterface, this.provider);
    
    try {
      const status = await contract.getAgentStatus(this.walletAddress);
      
      return {
        capabilityCount: Number(status[0]),
        activeCapabilities: Number(status[1]),
        totalLimit: Number(status[2]),
        isAuthorized: status[3],
        capabilities: Array.from(this.capabilities.values()),
        actionLimits: Object.fromEntries(this.actionLimits),
        pendingAuthorizations: Array.from(this.pendingAuthorizations.values()),
        revocationEvents: this.revocationEvents.slice(-10)
      };
    } catch (error) {
      return {
        capabilityCount: this.capabilities.size,
        activeCapabilities: this.capabilities.size,
        totalLimit: this.actionLimits.size,
        isAuthorized: this.capabilities.size > 0,
        capabilities: Array.from(this.capabilities.values()),
        actionLimits: Object.fromEntries(this.actionLimits),
        pendingAuthorizations: Array.from(this.pendingAuthorizations.values()),
        revocationEvents: this.revocationEvents.slice(-10)
      };
    }
  }

  async revokeCapability(tokenId) {
    if (!this.capabilityRegistry.has(tokenId)) {
      throw new Error(`Capability ${tokenId} not found in registry`);
    }
    
    const contractInterface = new ethers.utils.Interface([
      'function revokeCapability(uint256 tokenId, address agent)'
    ]);
    
    const contract = new ethers.Contract(this.contractAddress, contractInterface, this.provider);
    
    const tx = await contract.revokeCapability(tokenId, this.walletAddress);
    const receipt = await tx.wait();
    
    this.capabilities.delete(tokenId);
    this.capabilityRegistry.delete(tokenId);
    
    this.revocationEvents.push({
      tokenId,
      timestamp: Math.floor(Date.now() / 1000),
      status: 'revoked',
      txHash: receipt.hash
    });
    
    return { success: true, txHash: receipt.hash };
  }

  async bindCapabilityToAgent(newAgentId, tokenId) {
    if (!newAgentId || typeof newAgentId !== 'string') {
      throw new Error('Valid agent ID is required');
    }
    
    if (!this.capabilityRegistry.has(tokenId)) {
      throw new Error(`Capability ${tokenId} not found in registry`);
    }
    
    const capability = this.capabilities.get(tokenId);
    if (!capability) {
      throw new Error(`Capability ${tokenId} not loaded`);
    }
    
    const contractInterface = new ethers.utils.Interface([
      'function bindCapabilityToAgent(uint256 tokenId, address agent, address newAgent)'
    ]);
    
    const contract = new ethers.Contract(this.contractAddress, contractInterface, this.provider);
    
    const tx = await contract.bindCapabilityToAgent(tokenId, this.walletAddress, newAgentId);
    const receipt = await tx.wait();
    
    return { success: true, txHash: receipt.hash, newAgentId };
  }

  async getCapabilityProof(tokenId) {
    const contractInterface = new ethers.utils.Interface([
      'function getCapabilityProof(uint256 tokenId) view returns (bytes memory)'
    ]);
    
    const contract = new ethers.Contract(this.contractAddress, contractInterface, this.provider);
    
    try {
      const proof = await contract.getCapabilityProof(tokenId);
      return {
        tokenId,
        proof: proof,
        verified: true
      };
    } catch (error) {
      return {
        tokenId,
        proof: '0x',
        verified: false
      };
    }
  }

  async validateAction(actionType, targetAddress, parameters) {
    const capability = this.findValidCapability(actionType);
    
    if (!capability) {
      return {
        valid: false,
        reason: `No capability found for action: ${actionType}`,
        actionType,
        targetAddress,
        parameters
      };
    }
    
    const now = Math.floor(Date.now() / 1000);
    if (capability.expiry > 0 && now > capability.expiry) {
      return {
        valid: false,
        reason: 'Capability expired',
        actionType,
        targetAddress,
        parameters
      };
    }
    
    if (!capability.verified) {
      return {
        valid: false,
        reason: 'Capability not verified on-chain',
        actionType,
        targetAddress,
        parameters
      };
    }
    
    return {
      valid: true,
      capability: {
        tokenId: capability.tokenId,
        actionType: capability.actionType,
        limit: capability.limit,
        expiry: capability.expiry
      },
      actionType,
      targetAddress,
      parameters
    };
  }

  async refreshCapabilities() {
    const previousCount = this.capabilities.size;
    this.capabilities.clear();
    this.actionLimits.clear();
    this.capabilityRegistry.clear();
    
    await this.loadAllCapabilities();
    await this.verifyCapabilityIntegrity();
    
    return {
      previousCount,
      currentCount: this.capabilities.size,
      added: this.capabilities.size - previousCount,
      removed: previousCount - this.capabilities.size
    };
  }

  getCapabilitySummary() {
    const summary = {
      totalCapabilities: this.capabilities.size,
      actionTypes: new Set(),
      totalLimit: 0,
      activeLimits: new Map(),
      expired: 0,
      verified: 0
    };
    
    const now = Math.floor(Date.now() / 1000);
    
    for (const capability of this.capabilities.values()) {
      summary.actionTypes.add(capability.actionType);
      summary.totalLimit += capability.limit;
      
      if (capability.expiry > 0 && now > capability.expiry) {
        summary.expired++;
      } else {
        summary.verified++;
      }
      
      const currentLimit = summary.activeLimits.get(capability.actionType) || 0;
      summary.activeLimits.set(capability.actionType, currentLimit + capability.limit);
    }
    
    summary.actionTypes = Array.from(summary.actionTypes);
    summary.activeLimits = Object.fromEntries(summary.activeLimits);
    
    return summary;
  }

  async cleanupExpired() {
    const now = Math.floor(Date.now() / 1000);
    const expired = [];
    
    for (const [tokenId, capability] of this.capabilities) {
      if (capability.expiry > 0 && now > capability.expiry) {
        expired.push(tokenId);
      }
    }
    
    for (const tokenId of expired) {
      this.capabilities.delete(tokenId);
      this.capabilityRegistry.delete(tokenId);
    }
    
    return {
      cleaned: expired.length,
      remaining: this.capabilities.size
    };
  }

  async getPendingAuthorizations() {
    const now = Math.floor(Date.now() / 1000);
    const pending = [];
    
    for (const [id, auth] of this.pendingAuthorizations) {
      if (now - auth.timestamp < 300) {
        pending.push(auth);
      }
    }
    
    return pending;
  }

  async clearCache() {
    this.authorizationCache.clear();
    return { cleared: true };
  }

  async getChainInfo() {
    const blockNumber = await this.provider.getBlockNumber();
    const chainId = await this.provider.getChainId();
    const gasPrice = await this.provider.getGasPrice();
    
    return {
      blockNumber,
      chainId: Number(chainId),
      gasPrice: gasPrice.toString(),
      walletAddress: this.walletAddress,
      contractAddress: this.contractAddress,
      agentId: this.agentId
    };
  }
}

module.exports = { CapabilityManager };
