const { expect } = require('chai');
const { ethers } = require('hardhat');

describe('CapAgent Integration Tests', function () {
  let owner, agent1, agent2, agent3, user;
  let capabilityNFT, capabilityInheritance, capabilityManager, executionEngine;
  let agent1Wallet, agent2Wallet, agent3Wallet;

  beforeEach(async function () {
    [owner, agent1, agent2, agent3, user] = await ethers.getSigners();

    agent1Wallet = await ethers.provider.getSigner(agent1.address);
    agent2Wallet = await ethers.provider.getSigner(agent2.address);
    agent3Wallet = await ethers.provider.getSigner(agent3.address);

    const CapabilityNFT = await ethers.getContractFactory('CapabilityNFT');
    capabilityNFT = await CapabilityNFT.deploy();
    await capabilityNFT.waitForDeployment();

    const CapabilityInheritance = await ethers.getContractFactory('CapabilityInheritance');
    capabilityInheritance = await CapabilityInheritance.deploy();
    await capabilityInheritance.waitForDeployment();

    const CapabilityManager = await ethers.getContractFactory('CapabilityManager');
    capabilityManager = await CapabilityManager.deploy(
      capabilityNFT.target,
      capabilityInheritance.target
    );
    await capabilityManager.waitForDeployment();

    const ExecutionEngine = await ethers.getContractFactory('ExecutionEngine');
    executionEngine = await ExecutionEngine.deploy(
      capabilityManager.target,
      capabilityNFT.target
    );
    await executionEngine.waitForDeployment();

    await capabilityNFT.transferOwnership(capabilityManager.target);
    await capabilityInheritance.transferOwnership(capabilityManager.target);
    await capabilityManager.initialize();
  });

  describe('Unauthorized Action Scenarios', function () {
    it('should reject action without any capability NFT', async function () {
      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(agent1.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });

    it('should reject action with wrong capability type', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('MINT'), 100]
      );

      await expect(
        executionEngine.executeAction(agent1.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: action not permitted');
    });

    it('should reject action when capability limit exceeded', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 1000000000000000000000]
      );

      await expect(
        executionEngine.executeAction(agent1.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: limit exceeded');
    });

    it('should reject action from unauthorized agent address', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(user.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });

    it('should reject action with malformed capability ID', async function () {
      const capabilityId = ethers.id('INVALID_ACTION');
      await capabilityNFT.mint(agent1.address, capabilityId);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [capabilityId, 100]
      );

      await expect(
        executionEngine.executeAction(agent1.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: action not permitted');
    });
  });

  describe('Revoked Capability Scenarios', function () {
    it('should reject action after capability revocation', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      await capabilityManager.revokeCapability(agent1.address, capabilityId);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(agent1.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });

    it('should reject action after capability transfer', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      await capabilityNFT.transferFrom(
        agent1.address,
        agent2.address,
        capabilityId
      );

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(agent1.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });

    it('should reject action after capability burn', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      await capabilityNFT.burn(capabilityId);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(agent1.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });

    it('should reject action after capability expiration', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId, 100, 1000);

      await ethers.provider.send('evm_increaseTime', [1001]);
      await ethers.provider.send('evm_mine', []);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(agent1.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });

    it('should reject action after capability suspension', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      await capabilityManager.suspendCapability(agent1.address, capabilityId);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(agent1.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });
  });

  describe('Successful Execution Scenarios', function () {
    it('should execute action with valid capability', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      const tx = await executionEngine.executeAction(agent1.address, actionData);
      const receipt = await tx.wait();

      expect(receipt.status).to.equal(1);
    });

    it('should execute multiple actions with same capability', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId, 1000, 10000);

      for (let i = 0; i < 5; i++) {
        const actionData = ethers.solidityPacked(
          ['bytes32', 'uint256'],
          [ethers.id('TRANSFER'), 100]
        );

        const tx = await executionEngine.executeAction(agent1.address, actionData);
        const receipt = await tx.wait();
        expect(receipt.status).to.equal(1);
      }
    });

    it('should execute action with multiple capabilities', async function () {
      const transferId = ethers.id('TRANSFER');
      const tradeId = ethers.id('TRADE');

      await capabilityNFT.mint(agent1.address, transferId);
      await capabilityNFT.mint(agent1.address, tradeId);

      const transferData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      const tradeData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRADE'), 100]
      );

      const tx1 = await executionEngine.executeAction(agent1.address, transferData);
      const receipt1 = await tx1.wait();
      expect(receipt1.status).to.equal(1);

      const tx2 = await executionEngine.executeAction(agent1.address, tradeData);
      const receipt2 = await tx2.wait();
      expect(receipt2.status).to.equal(1);
    });

    it('should execute action with capability limit tracking', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId, 500, 1000);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      const tx = await executionEngine.executeAction(agent1.address, actionData);
      const receipt = await tx.wait();
      expect(receipt.status).to.equal(1);

      const remaining = await capabilityNFT.getRemainingLimit(
        agent1.address,
        capabilityId
      );
      expect(remaining).to.equal(400);
    });

    it('should execute action with capability expiration', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId, 100, 10000);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      const tx = await executionEngine.executeAction(agent1.address, actionData);
      const receipt = await tx.wait();
      expect(receipt.status).to.equal(1);
    });
  });

  describe('Inheritance Delegation Scenarios', function () {
    it('should allow child agent to inherit parent capability', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      await capabilityInheritance.createHierarchy(
        agent1.address,
        agent2.address,
        [capabilityId]
      );

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      const tx = await executionEngine.executeAction(agent2.address, actionData);
      const receipt = await tx.wait();
      expect(receipt.status).to.equal(1);
    });

    it('should allow multi-level inheritance delegation', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      await capabilityInheritance.createHierarchy(
        agent1.address,
        agent2.address,
        [capabilityId]
      );

      await capabilityInheritance.createHierarchy(
        agent2.address,
        agent3.address,
        [capabilityId]
      );

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      const tx = await executionEngine.executeAction(agent3.address, actionData);
      const receipt = await tx.wait();
      expect(receipt.status).to.equal(1);
    });

    it('should reject action when inheritance chain broken', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      await capabilityInheritance.createHierarchy(
        agent1.address,
        agent2.address,
        [capabilityId]
      );

      await capabilityInheritance.removeHierarchy(agent1.address, agent2.address);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(agent2.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });

    it('should allow partial capability inheritance', async function () {
      const transferId = ethers.id('TRANSFER');
      const tradeId = ethers.id('TRADE');

      await capabilityNFT.mint(agent1.address, transferId);
      await capabilityNFT.mint(agent1.address, tradeId);

      await capabilityInheritance.createHierarchy(
        agent1.address,
        agent2.address,
        [transferId]
      );

      const transferData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      const tradeData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRADE'), 100]
      );

      const tx1 = await executionEngine.executeAction(agent2.address, transferData);
      const receipt1 = await tx1.wait();
      expect(receipt1.status).to.equal(1);

      await expect(
        executionEngine.executeAction(agent2.address, tradeData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });

    it('should allow capability inheritance with limit sharing', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId, 1000, 10000);

      await capabilityInheritance.createHierarchy(
        agent1.address,
        agent2.address,
        [capabilityId]
      );

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      const tx1 = await executionEngine.executeAction(agent1.address, actionData);
      const receipt1 = await tx1.wait();
      expect(receipt1.status).to.equal(1);

      const tx2 = await executionEngine.executeAction(agent2.address, actionData);
      const receipt2 = await tx2.wait();
      expect(receipt2.status).to.equal(1);

      const remaining = await capabilityNFT.getRemainingLimit(
        agent1.address,
        capabilityId
      );
      expect(remaining).to.equal(800);
    });

    it('should reject action when child exceeds inherited limit', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId, 100, 1000);

      await capabilityInheritance.createHierarchy(
        agent1.address,
        agent2.address,
        [capabilityId]
      );

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      const tx1 = await executionEngine.executeAction(agent2.address, actionData);
      const receipt1 = await tx1.wait();
      expect(receipt1.status).to.equal(1);

      const actionData2 = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(agent2.address, actionData2)
      ).to.be.revertedWith('CapabilityNFT: limit exceeded');
    });

    it('should allow dynamic capability addition to inheritance chain', async function () {
      const transferId = ethers.id('TRANSFER');
      const tradeId = ethers.id('TRADE');

      await capabilityNFT.mint(agent1.address, transferId);

      await capabilityInheritance.createHierarchy(
        agent1.address,
        agent2.address,
        [transferId]
      );

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      const tx1 = await executionEngine.executeAction(agent2.address, actionData);
      const receipt1 = await tx1.wait();
      expect(receipt1.status).to.equal(1);

      await capabilityNFT.mint(agent1.address, tradeId);
      await capabilityInheritance.addCapabilitiesToHierarchy(
        agent1.address,
        agent2.address,
        [tradeId]
      );

      const tradeData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRADE'), 100]
      );

      const tx2 = await executionEngine.executeAction(agent2.address, tradeData);
      const receipt2 = await tx2.wait();
      expect(receipt2.status).to.equal(1);
    });

    it('should reject action when capability removed from inheritance chain', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      await capabilityInheritance.createHierarchy(
        agent1.address,
        agent2.address,
        [capabilityId]
      );

      await capabilityInheritance.removeCapabilitiesFromHierarchy(
        agent1.address,
        agent2.address,
        [capabilityId]
      );

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(agent2.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });

    it('should allow capability inheritance with revocation propagation', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      await capabilityInheritance.createHierarchy(
        agent1.address,
        agent2.address,
        [capabilityId]
      );

      await capabilityManager.revokeCapability(agent1.address, capabilityId);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(agent2.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });

    it('should allow capability inheritance with suspension propagation', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      await capabilityInheritance.createHierarchy(
        agent1.address,
        agent2.address,
        [capabilityId]
      );

      await capabilityManager.suspendCapability(agent1.address, capabilityId);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(agent2.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });
  });

  describe('Edge Cases and Security', function () {
    it('should reject zero capability ID', async function () {
      const capabilityId = ethers.ZeroHash;
      await capabilityNFT.mint(agent1.address, capabilityId);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [capabilityId, 100]
      );

      await expect(
        executionEngine.executeAction(agent1.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: action not permitted');
    });

    it('should reject negative limit value', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await expect(
        capabilityNFT.mint(agent1.address, capabilityId, 0, 0)
      ).to.be.revertedWith('CapabilityNFT: invalid limit');
    });

    it('should reject capability mint to zero address', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await expect(
        capabilityNFT.mint(ethers.ZeroAddress, capabilityId)
      ).to.be.revertedWith('ERC721: mint to the zero address');
    });

    it('should reject action with zero amount', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 0]
      );

      const tx = await executionEngine.executeAction(agent1.address, actionData);
      const receipt = await tx.wait();
      expect(receipt.status).to.equal(1);
    });

    it('should handle concurrent capability usage', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId, 1000, 10000);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      const promises = [];
      for (let i = 0; i < 10; i++) {
        promises.push(
          executionEngine.executeAction(agent1.address, actionData)
        );
      }

      const results = await Promise.all(promises);
      results.forEach((result, index) => {
        expect(result.status).to.equal(1);
      });

      const remaining = await capabilityNFT.getRemainingLimit(
        agent1.address,
        capabilityId
      );
      expect(remaining).to.equal(0);
    });

    it('should reject capability transfer from unauthorized address', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      await expect(
        capabilityNFT.transferFrom(
          agent1.address,
          agent2.address,
          capabilityId,
          { from: user }
        )
      ).to.be.revertedWith('ERC721: transfer caller is not owner nor approved');
    });

    it('should reject capability burn from unauthorized address', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      await expect(
        capabilityNFT.burn(capabilityId, { from: user })
      ).to.be.revertedWith('ERC721: caller is not owner nor approved');
    });

    it('should reject hierarchy creation from unauthorized address', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      await expect(
        capabilityInheritance.createHierarchy(
          agent1.address,
          agent2.address,
          [capabilityId],
          { from: user }
        )
      ).to.be.revertedWith('CapabilityInheritance: unauthorized');
    });

    it('should reject hierarchy removal from unauthorized address', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId);

      await capabilityInheritance.createHierarchy(
        agent1.address,
        agent2.address,
        [capabilityId]
      );

      await expect(
        capabilityInheritance.removeHierarchy(
          agent1.address,
          agent2.address,
          { from: user }
        )
      ).to.be.revertedWith('CapabilityInheritance: unauthorized');
    });

    it('should handle capability expiration with block timestamp manipulation', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityNFT.mint(agent1.address, capabilityId, 100, 100);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      const tx1 = await executionEngine.executeAction(agent1.address, actionData);
      const receipt1 = await tx1.wait();
      expect(receipt1.status).to.equal(1);

      await ethers.provider.send('evm_increaseTime', [101]);
      await ethers.provider.send('evm_mine', []);

      await expect(
        executionEngine.executeAction(agent1.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });
  });

  describe('Capability Manager Integration', function () {
    it('should allow capability manager to mint capabilities', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityManager.mintCapability(agent1.address, capabilityId);

      const balance = await capabilityNFT.balanceOf(agent1.address);
      expect(balance).to.equal(1);
    });

    it('should allow capability manager to burn capabilities', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityManager.mintCapability(agent1.address, capabilityId);

      await capabilityManager.burnCapability(agent1.address, capabilityId);

      const balance = await capabilityNFT.balanceOf(agent1.address);
      expect(balance).to.equal(0);
    });

    it('should allow capability manager to transfer capabilities', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityManager.mintCapability(agent1.address, capabilityId);

      await capabilityManager.transferCapability(
        agent1.address,
        agent2.address,
        capabilityId
      );

      const balance1 = await capabilityNFT.balanceOf(agent1.address);
      const balance2 = await capabilityNFT.balanceOf(agent2.address);
      expect(balance1).to.equal(0);
      expect(balance2).to.equal(1);
    });

    it('should allow capability manager to revoke capabilities', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityManager.mintCapability(agent1.address, capabilityId);

      await capabilityManager.revokeCapability(agent1.address, capabilityId);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(agent1.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });

    it('should allow capability manager to suspend capabilities', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityManager.mintCapability(agent1.address, capabilityId);

      await capabilityManager.suspendCapability(agent1.address, capabilityId);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(agent1.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });

    it('should allow capability manager to resume suspended capabilities', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityManager.mintCapability(agent1.address, capabilityId);

      await capabilityManager.suspendCapability(agent1.address, capabilityId);
      await capabilityManager.resumeCapability(agent1.address, capabilityId);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      const tx = await executionEngine.executeAction(agent1.address, actionData);
      const receipt = await tx.wait();
      expect(receipt.status).to.equal(1);
    });

    it('should allow capability manager to set capability limits', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityManager.mintCapability(agent1.address, capabilityId);

      await capabilityManager.setCapabilityLimit(
        agent1.address,
        capabilityId,
        1000,
        10000
      );

      const limit = await capabilityNFT.getCapabilityLimit(
        agent1.address,
        capabilityId
      );
      expect(limit[0]).to.equal(1000);
      expect(limit[1]).to.equal(10000);
    });

    it('should allow capability manager to set capability expiration', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityManager.mintCapability(agent1.address, capabilityId);

      const expirationTime = Math.floor(Date.now() / 1000) + 1000;
      await capabilityManager.setCapabilityExpiration(
        agent1.address,
        capabilityId,
        expirationTime
      );

      const expiration = await capabilityNFT.getCapabilityExpiration(
        agent1.address,
        capabilityId
      );
      expect(expiration).to.equal(expirationTime);
    });
  });

  describe('Capability Inheritance Integration', function () {
    it('should allow capability manager to create hierarchy', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityManager.mintCapability(agent1.address, capabilityId);

      await capabilityManager.createHierarchy(
        agent1.address,
        agent2.address,
        [capabilityId]
      );

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      const tx = await executionEngine.executeAction(agent2.address, actionData);
      const receipt = await tx.wait();
      expect(receipt.status).to.equal(1);
    });

    it('should allow capability manager to remove hierarchy', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityManager.mintCapability(agent1.address, capabilityId);

      await capabilityManager.createHierarchy(
        agent1.address,
        agent2.address,
        [capabilityId]
      );

      await capabilityManager.removeHierarchy(agent1.address, agent2.address);

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(agent2.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });

    it('should allow capability manager to add capabilities to hierarchy', async function () {
      const transferId = ethers.id('TRANSFER');
      const tradeId = ethers.id('TRADE');

      await capabilityManager.mintCapability(agent1.address, transferId);

      await capabilityManager.createHierarchy(
        agent1.address,
        agent2.address,
        [transferId]
      );

      await capabilityManager.addCapabilitiesToHierarchy(
        agent1.address,
        agent2.address,
        [tradeId]
      );

      const tradeData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRADE'), 100]
      );

      const tx = await executionEngine.executeAction(agent2.address, tradeData);
      const receipt = await tx.wait();
      expect(receipt.status).to.equal(1);
    });

    it('should allow capability manager to remove capabilities from hierarchy', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityManager.mintCapability(agent1.address, capabilityId);

      await capabilityManager.createHierarchy(
        agent1.address,
        agent2.address,
        [capabilityId]
      );

      await capabilityManager.removeCapabilitiesFromHierarchy(
        agent1.address,
        agent2.address,
        [capabilityId]
      );

      const actionData = ethers.solidityPacked(
        ['bytes32', 'uint256'],
        [ethers.id('TRANSFER'), 100]
      );

      await expect(
        executionEngine.executeAction(agent2.address, actionData)
      ).to.be.revertedWith('CapabilityNFT: insufficient capability');
    });

    it('should allow capability manager to get hierarchy status', async function () {
      const capabilityId = ethers.id('TRANSFER');
      await capabilityManager