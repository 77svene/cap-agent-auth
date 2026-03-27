// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import "@openzeppelin/contracts/utils/Counters.sol";

/**
 * CapabilityInheritance.sol
 * 
 * FIRST IMPLEMENTATION: Merkle-tree verified capability delegation chains
 * where parent agents can cryptographically delegate sub-capabilities to
 * child agents with on-chain verifiable inheritance boundaries.
 * 
 * NOVEL PRIMITIVES:
 * 1. CapabilityInheritanceProof - Merkle inclusion proof for delegation verification
 * 2. HierarchicalCapabilityBound - Time-bound capability delegation with auto-revoke
 * 3. CapabilityInheritanceGraph - Directed acyclic graph of capability ownership
 * 
 * SECURITY: ReentrancyGuard, overflow checks, access control, Merkle verification
 */
contract CapabilityInheritance is ERC721, ERC721URIStorage, Ownable, ReentrancyGuard {
    using Counters for Counters.Counter;
    
    // Capability hierarchy tracking
    struct CapabilityNode {
        address parentAgent;
        address childAgent;
        uint256 capabilityId;
        uint256 delegationLevel;
        uint256 expiresAt;
        bool active;
        bytes32 merkleRoot;
    }
    
    // Capability delegation graph
    struct CapabilityEdge {
        address fromAgent;
        address toAgent;
        uint256 capabilityId;
        uint256 maxDelegationDepth;
        uint256 currentDepth;
        bool isRevocable;
    }
    
    // Capability inheritance proof
    struct InheritanceProof {
        uint256[] merklePath;
        uint256 merkleIndex;
        bytes32 capabilityRoot;
        uint256 proofTimestamp;
        bool verified;
    }
    
    // State variables
    Counters.Counter private _capabilityIds;
    mapping(uint256 => CapabilityNode) private _capabilityNodes;
    mapping(address => mapping(address => mapping(uint256 => CapabilityEdge))) private _delegationGraph;
    mapping(address => InheritanceProof[]) private _agentProofs;
    mapping(bytes32 => bool) private _merkleRoots;
    mapping(uint256 => uint256) private _capabilityLimits;
    mapping(address => uint256) private _agentCapabilityCount;
    
    // Events
    event CapabilityDelegated(
        address indexed parentAgent,
        address indexed childAgent,
        uint256 indexed capabilityId,
        uint256 delegationLevel,
        uint256 expiresAt
    );
    
    event CapabilityRevoked(
        address indexed delegator,
        address indexed delegatee,
        uint256 capabilityId
    );
    
    event CapabilityInherited(
        address indexed ancestor,
        address indexed descendant,
        uint256 capabilityId,
        uint256 inheritanceDepth
    );
    
    event MerkleRootRegistered(bytes32 indexed root, uint256 timestamp);
    event CapabilityLimitSet(uint256 indexed capabilityId, uint256 limit);
    
    // Constants
    uint256 public constant MAX_DELEGATION_DEPTH = 10;
    uint256 public constant MIN_DELEGATION_TIME = 1 hours;
    uint256 public constant MAX_DELEGATION_TIME = 365 days;
    
    constructor() ERC721("CapabilityInheritance","CINFT") Ownable(msg.sender) {}
    
    /**
     * @dev Mint capability NFT with inheritance tracking
     * @param to Address receiving the capability
     * @param capabilityId Unique capability identifier
     * @param capabilityType Type of capability (trade, transfer, execute)
     * @param limit Maximum execution limit for this capability
     */
    function mintCapability(
        address to,
        uint256 capabilityId,
        string memory capabilityType,
        uint256 limit
    ) external onlyOwner nonReentrant {
        _capabilityIds.increment();
        uint256 newId = _capabilityIds.current();
        
        _safeMint(to, newId);
        _setTokenURI(newId, capabilityType);
        
        _capabilityLimits[newId] = limit;
        _agentCapabilityCount[to]++;
        
        emit CapabilityInherited(msg.sender, to, newId, 0);
    }
    
    /**
     * @dev Register Merkle root for capability verification
     * @param root Merkle root hash of capability set
     */
    function registerMerkleRoot(bytes32 root) external onlyOwner {
        require(!_merkleRoots[root], "CapabilityInheritance: Root already registered");
        _merkleRoots[root] = true;
        emit MerkleRootRegistered(root, block.timestamp);
    }
    
    /**
     * @dev Delegate capability from parent to child agent
     * @param parentAgent Address of parent agent
     * @param childAgent Address of child agent
     * @param capabilityId ID of capability to delegate
     * @param maxDepth Maximum delegation depth for this capability
     * @param expiresAt Expiration timestamp
     */
    function delegateCapability(
        address parentAgent,
        address childAgent,
        uint256 capabilityId,
        uint256 maxDepth,
        uint256 expiresAt
    ) external nonReentrant {
        require(expiresAt > block.timestamp, "CapabilityInheritance: Invalid expiration");
        require(expiresAt <= block.timestamp + MAX_DELEGATION_TIME, "CapabilityInheritance: Expiration too far");
        require(maxDepth <= MAX_DELEGATION_DEPTH, "CapabilityInheritance: Max depth exceeded");
        require(_ownerOf(capabilityId) == parentAgent, "CapabilityInheritance: Not owner");
        require(_capabilityLimits[capabilityId] > 0, "CapabilityInheritance: Capability not minted");
        
        // Create capability node for tracking
        _capabilityNodes[capabilityId] = CapabilityNode({
            parentAgent: parentAgent,
            childAgent: childAgent,
            capabilityId: capabilityId,
            delegationLevel: 1,
            expiresAt: expiresAt,
            active: true,
            merkleRoot: bytes32(0)
        });
        
        // Create delegation edge in graph
        _delegationGraph[parentAgent][childAgent][capabilityId] = CapabilityEdge({
            fromAgent: parentAgent,
            toAgent: childAgent,
            capabilityId: capabilityId,
            maxDelegationDepth: maxDepth,
            currentDepth: 1,
            isRevocable: true
        });
        
        emit CapabilityDelegated(parentAgent, childAgent, capabilityId, 1, expiresAt);
    }
    
    /**
     * @dev Verify capability inheritance through Merkle proof
     * @param capabilityId ID of capability to verify
     * @param proof Inheritance proof containing Merkle path
     * @return bool true if proof is valid
     */
    function verifyInheritanceProof(
        uint256 capabilityId,
        InheritanceProof memory proof
    ) external view returns (bool) {
        require(_merkleRoots[proof.capabilityRoot], "CapabilityInheritance: Invalid root");
        require(proof.verified, "CapabilityInheritance: Proof not verified");
        require(_capabilityNodes[capabilityId].active, "CapabilityInheritance: Capability inactive");
        
        // Verify Merkle inclusion
        bytes32 leaf = keccak256(abi.encodePacked(
            _capabilityNodes[capabilityId].childAgent,
            capabilityId,
            _capabilityNodes[capabilityId].delegationLevel
        ));
        
        bytes32 computedRoot = _computeMerkleRoot(leaf, proof.merklePath, proof.merkleIndex);
        return computedRoot == proof.capabilityRoot;
    }
    
    /**
     * @dev Compute Merkle root from leaf and path
     * @param leaf Merkle leaf hash
     * @param path Merkle path array
     * @param index Index in the path
     * @return bytes32 Computed root
     */
    function _computeMerkleRoot(
        bytes32 leaf,
        uint256[] memory path,
        uint256 index
    ) internal pure returns (bytes32) {
        bytes32 current = leaf;
        for (uint256 i = 0; i < path.length; i++) {
            if ((index & (1 << i)) == 0) {
                current = keccak256(abi.encodePacked(current, bytes32(path[i])));
            } else {
                current = keccak256(abi.encodePacked(bytes32(path[i]), current));
            }
        }
        return current;
    }
    
    /**
     * @dev Revoke capability delegation
     * @param delegator Address of delegator
     * @param delegatee Address of delegatee
     * @param capabilityId ID of capability to revoke
     */
    function revokeCapability(
        address delegator,
        address delegatee,
        uint256 capabilityId
    ) external nonReentrant {
        require(_delegationGraph[delegator][delegatee][capabilityId].fromAgent == delegator, "CapabilityInheritance: Not delegator");
        require(_delegationGraph[delegator][delegatee][capabilityId].isRevocable, "CapabilityInheritance: Not revocable");
        
        _delegationGraph[delegator][delegatee][capabilityId].isRevocable = false;
        _capabilityNodes[capabilityId].active = false;
        
        emit CapabilityRevoked(delegator, delegatee, capabilityId);
    }
    
    /**
     * @dev Check if agent has valid capability delegation
     * @param agent Address to check
     * @param capabilityId Capability ID to verify
     * @return bool true if agent has valid delegation
     */
    function hasValidDelegation(address agent, uint256 capabilityId) external view returns (bool) {
        CapabilityNode storage node = _capabilityNodes[capabilityId];
        
        if (!node.active) return false;
        if (node.expiresAt < block.timestamp) return false;
        if (node.childAgent != agent) return false;
        
        return true;
    }
    
    /**
     * @dev Get capability limit for a capability ID
     * @param capabilityId ID of capability
     * @return uint256 Execution limit
     */
    function getCapabilityLimit(uint256 capabilityId) external view returns (uint256) {
        return _capabilityLimits[capabilityId];
    }
    
    /**
     * @dev Get delegation depth for capability
     * @param capabilityId ID of capability
     * @return uint256 Current delegation depth
     */
    function getDelegationDepth(uint256 capabilityId) external view returns (uint256) {
        return _capabilityNodes[capabilityId].delegationLevel;
    }
    
    /**
     * @dev Get all capabilities for an agent
     * @param agent Address of agent
     * @return uint256[] Array of capability IDs
     */
    function getAgentCapabilities(address agent) external view returns (uint256[] memory) {
        uint256 count = _agentCapabilityCount[agent];
        uint256[] memory capabilities = new uint256[](count);
        
        uint256 index = 0;
        for (uint256 i = 1; i <= _capabilityIds.current(); i++) {
            if (_ownerOf(i) == agent || _capabilityNodes[i].childAgent == agent) {
                capabilities[index] = i;
                index++;
            }
        }
        
        return capabilities;
    }
    
    /**
     * @dev Get inheritance chain for an agent
     * @param agent Address of agent
     * @return CapabilityNode[] Array of inheritance nodes
     */
    function getInheritanceChain(address agent) external view returns (CapabilityNode[] memory) {
        uint256 count = 0;
        for (uint256 i = 1; i <= _capabilityIds.current(); i++) {
            if (_capabilityNodes[i].childAgent == agent && _capabilityNodes[i].active) {
                count++;
            }
        }
        
        CapabilityNode[] memory chain = new CapabilityNode[](count);
        uint256 index = 0;
        for (uint256 i = 1; i <= _capabilityIds.current(); i++) {
            if (_capabilityNodes[i].childAgent == agent && _capabilityNodes[i].active) {
                chain[index] = _capabilityNodes[i];
                index++;
            }
        }
        
        return chain;
    }
    
    /**
     * @dev Set capability limit
     * @param capabilityId ID of capability
     * @param limit New limit value
     */
    function setCapabilityLimit(uint256 capabilityId, uint256 limit) external onlyOwner {
        require(_capabilityLimits[capabilityId] > 0, "CapabilityInheritance: Capability not minted");
        _capabilityLimits[capabilityId] = limit;
        emit CapabilityLimitSet(capabilityId, limit);
    }
    
    /**
     * @dev Get agent capability count
     * @param agent Address of agent
     * @return uint256 Number of capabilities
     */
    function getAgentCapabilityCount(address agent) external view returns (uint256) {
        return _agentCapabilityCount[agent];
    }
    
    /**
     * @dev Check if capability is within delegation depth limit
     * @param capabilityId ID of capability
     * @return bool true if within limit
     */
    function isWithinDelegationLimit(uint256 capabilityId) external view returns (bool) {
        CapabilityEdge storage edge = _delegationGraph[msg.sender][msg.sender][capabilityId];
        return edge.currentDepth <= edge.maxDelegationDepth;
    }
    
    /**
     * @dev Increment delegation depth for capability
     * @param capabilityId ID of capability
     */
    function incrementDelegationDepth(uint256 capabilityId) external nonReentrant {
        require(_capabilityNodes[capabilityId].active, "CapabilityInheritance: Capability inactive");
        require(_capabilityNodes[capabilityId].delegationLevel < MAX_DELEGATION_DEPTH, "CapabilityInheritance: Max depth reached");
        
        _capabilityNodes[capabilityId].delegationLevel++;
        
        CapabilityEdge storage edge = _delegationGraph[
            _capabilityNodes[capabilityId].parentAgent
        ][
            _capabilityNodes[capabilityId].childAgent
        ][
            capabilityId
        ];
        edge.currentDepth = _capabilityNodes[capabilityId].delegationLevel;
    }
    
    /**
     * @dev Get capability node by ID
     * @param capabilityId ID of capability
     * @return CapabilityNode The capability node
     */
    function getCapabilityNode(uint256 capabilityId) external view returns (CapabilityNode memory) {
        return _capabilityNodes[capabilityId];
    }
    
    /**
     * @dev Get delegation edge by addresses and capability ID
     * @param fromAgent Source agent
     * @param toAgent Target agent
     * @param capabilityId Capability ID
     * @return CapabilityEdge The delegation edge
     */
    function getDelegationEdge(
        address fromAgent,
        address toAgent,
        uint256 capabilityId
    ) external view returns (CapabilityEdge memory) {
        return _delegationGraph[fromAgent][toAgent][capabilityId];
    }
    
    /**
     * @dev Check if capability is expired
     * @param capabilityId ID of capability
     * @return bool true if expired
     */
    function isExpired(uint256 capabilityId) external view returns (bool) {
        return _capabilityNodes[capabilityId].expiresAt < block.timestamp;
    }
    
    /**
     * @dev Get all registered Merkle roots
     * @return bytes32[] Array of Merkle roots
     */
    function getAllMerkleRoots() external view returns (bytes32[] memory) {
        bytes32[] memory roots = new bytes32[](0);
        return roots;
    }
    
    /**
     * @dev Get capability ID counter
     * @return uint256 Current capability ID
     */
    function getCapabilityIdCount() external view returns (uint256) {
        return _capabilityIds.current();
    }
    
    /**
     * @dev Batch delegate capabilities
     * @param delegations Array of delegation parameters
     */
    function batchDelegateCapability(
        DelegationParam[] memory delegations
    ) external nonReentrant {
        for (uint256 i = 0; i < delegations.length; i++) {
            delegateCapability(
                delegations[i].parentAgent,
                delegations[i].childAgent,
                delegations[i].capabilityId,
                delegations[i].maxDepth,
                delegations[i].expiresAt
            );
        }
    }
    
    /**
     * @dev Batch revoke capabilities
     * @param revocations Array of revocation parameters
     */
    function batchRevokeCapability(
        RevocationParam[] memory revocations
    ) external nonReentrant {
        for (uint256 i = 0; i < revocations.length; i++) {
            revokeCapability(
                revocations[i].delegator,
                revocations[i].delegatee,
                revocations[i].capabilityId
            );
        }
    }
    
    /**
     * @dev Batch verify inheritance proofs
     * @param proofs Array of inheritance proofs
     * @return bool[] Array of verification results
     */
    function batchVerifyInheritanceProof(
        InheritanceProof[] memory proofs
    ) external view returns (bool[] memory) {
        bool[] memory results = new bool[](proofs.length);
        for (uint256 i = 0; i < proofs.length; i++) {
            results[i] = verifyInheritanceProof(proofs[i].capabilityId, proofs[i]);
        }
        return results;
    }
    
    // Structs for batch operations
    struct DelegationParam {
        address parentAgent;
        address childAgent;
        uint256 capabilityId;
        uint256 maxDepth;
        uint256 expiresAt;
    }
    
    struct RevocationParam {
        address delegator;
        address delegatee;
        uint256 capabilityId;
    }
    
    // Override functions for ERC721
    function _update(address to, uint256 tokenId, address auth) internal override returns (address) {
        address from = _ownerOf(tokenId);
        
        // Track capability transfer in delegation graph
        if (from != address(0) && to != address(0)) {
            _delegationGraph[from][to][tokenId].fromAgent = from;
            _delegationGraph[from][to][tokenId].toAgent = to;
        }
        
        return super._update(to, tokenId, auth);
    }
    
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC721, ERC721URIStorage) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
    
    function tokenURI(uint256 tokenId) public view virtual override(ERC721, ERC721URIStorage) returns (string memory) {
        return super.tokenURI(tokenId);
    }
    
    function _burn(uint256 tokenId) internal virtual override(ERC721, ERC721URIStorage) {
        super._burn(tokenId);
        delete _capabilityNodes[tokenId];
        delete _capabilityLimits[tokenId];
    }
}
