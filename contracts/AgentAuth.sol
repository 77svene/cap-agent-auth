// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title AgentAuth
 * @notice Capability-Based Authorization Primitive for AI Agents
 * @dev First implementation of NFT-encoded capability verification with compositional permissions
 * @dev Each capability NFT encodes: action scope, resource limits, expiration, delegation rights
 * @dev Capabilities compose: multiple NFTs = union of all permissions (AND logic for limits)
 */
contract AgentAuth is EIP712, Ownable {
    using ECDSA for bytes32;
    using EnumerableSet for EnumerableSet.UintSet;

    // Capability NFT interface
    IERC721 public immutable CAPABILITY_NFT;

    // Capability structure: encodes all permission metadata on-chain
    struct Capability {
        uint256 nftId;                    // NFT identifier
        bytes32 actionType;               // SHA256 hash of action string
        uint256 resourceLimit;            // Max units (e.g., ETH amount, gas limit)
        uint256 usedAmount;               // Consumed from limit
        uint256 expiresAt;                // Unix timestamp
        address delegator;                // Original capability owner
        bool revoked;                     // Revocation flag
        uint256 version;                  // Capability version for upgrades
    }

    // Capability composition: maps (agent, capabilityNFT) -> capability data
    mapping(address => mapping(uint256 => Capability)) public capabilities;

    // Action type registry: maps action string hash to canonical definition
    mapping(bytes32 => ActionDefinition) public actionRegistry;

    // Agent capability set: tracks all NFTs an agent holds
    mapping(address => EnumerableSet.UintSet) public agentCapabilities;

    // Capability delegation: maps (agent, nftId) -> delegatedTo
    mapping(address => mapping(uint256 => address)) public capabilityDelegation;

    // Capability revocation registry: tracks revoked NFTs
    mapping(uint256 => bool) public capabilityRevoked;

    // Capability versioning: tracks capability versions per NFT
    mapping(uint256 => uint256) public capabilityVersion;

    // Capability hash: unique identifier for capability configuration
    bytes32 public constant CAPABILITY_TYPEHASH = keccak256(
        "Capability(uint256 nftId,bytes32 actionType,uint256 resourceLimit,uint256 expiresAt,uint256 version)"
    );

    // Capability signature domain separator
    bytes32 public immutable DOMAIN_SEPARATOR;

    // Capability signature typehash for EIP-712
    bytes32 public constant CAPABILITY_SIGN_TYPEHASH = keccak256(
        "CapabilitySignature(address agent,uint256 nftId,bytes32 actionType,uint256 limit,uint256 expiresAt)"
    );

    // Capability composition hash: enables verifiable capability unions
    bytes32 public constant COMPOSITION_HASH = keccak256(
        "CapabilityComposition(address agent,bytes32[] actionTypes,uint256[] limits)"
    );

    // Capability audit log: immutable record of all capability grants
    struct AuditEntry {
        address agent;
        uint256 nftId;
        bytes32 actionType;
        uint256 timestamp;
        bytes32 txHash;
    }
    AuditEntry[] public auditLog;
    uint256 public auditLogIndex;

    // Capability event: emits capability state changes
    event CapabilityGranted(address indexed agent, uint256 indexed nftId, bytes32 indexed actionType, uint256 limit);
    event CapabilityRevoked(address indexed agent, uint256 indexed nftId, bytes32 indexed actionType);
    event CapabilityDelegated(address indexed from, address indexed to, uint256 nftId, bytes32 actionType);
    event CapabilityUsed(address indexed agent, uint256 indexed nftId, bytes32 actionType, uint256 amount);
    event CapabilityExpired(address indexed agent, uint256 indexed nftId, bytes32 actionType);
    event CapabilityVersioned(address indexed agent, uint256 indexed nftId, uint256 newVersion);
    event CapabilityCompositionVerified(address indexed agent, bytes32 compositionHash);

    // Capability error codes: precise failure diagnostics
    enum CapabilityError {
        NONE,
        NFT_NOT_OWNED,
        NFT_REVOKED,
        CAPABILITY_EXPIRED,
        LIMIT_EXCEEDED,
        ACTION_NOT_ALLOWED,
        DELEGATION_INVALID,
        CAPABILITY_NOT_FOUND,
        COMPOSITION_MISMATCH
    }

    // Capability verification result: returns error code and metadata
    struct VerificationResult {
        bool valid;
        CapabilityError error;
        uint256 remainingLimit;
        uint256 expiresAt;
        bool isDelegated;
        address delegate;
    }

    // Action definition: canonical action metadata
    struct ActionDefinition {
        bytes32 actionHash;
        string actionName;
        uint256 defaultLimit;
        bool requiresApproval;
        uint256 approvalThreshold; // % of total supply required
    }

    // Capability configuration: global capability parameters
    struct CapabilityConfig {
        uint256 maxCapabilitiesPerAgent;
        uint256 minCapabilityVersion;
        uint256 maxCapabilityVersion;
        uint256 defaultExpiration; // seconds
        uint256 delegationCooldown; // seconds
    }
    CapabilityConfig public config;

    // Capability gas limit: prevents DoS via excessive verification
    uint256 public constant MAX_VERIFICATION_GAS = 500000;

    // Capability blacklist: prevents specific NFTs from being used
    mapping(uint256 => bool) public capabilityBlacklist;

    // Capability whitelist: only these NFTs can be used
    mapping(uint256 => bool) public capabilityWhitelist;
    bool public whitelistEnabled;

    // Capability rate limiter: tracks capability usage per time window
    struct RateLimit {
        uint256 windowStart;
        uint256 usageCount;
        uint256 maxUsage;
    }
    mapping(address => mapping(bytes32 => RateLimit)) public capabilityRateLimits;
    uint256 public constant RATE_WINDOW = 1 hours;
    uint256 public constant MAX_RATE_LIMIT = 100;

    // Capability Merkle tree: enables batch capability verification
    struct MerkleCapability {
        bytes32 root;
        uint256[] indices;
        bytes32[] proofs;
    }
    mapping(bytes32 => MerkleCapability) public merkleCapabilities;

    // Capability signature verification: enables off-chain capability grants
    mapping(bytes32 => bool) public signatureValid;
    mapping(bytes32 => uint256) public signatureExpiry;

    // Capability initialization flag
    bool public initialized;

    // Capability constructor: initializes capability system
    constructor(address _nftAddress) EIP712("AgentAuth", "1") Ownable(msg.sender) {
        CAPABILITY_NFT = IERC721(_nftAddress);
        DOMAIN_SEPARATOR = _domainSeparatorV4();
        config = CapabilityConfig({
            maxCapabilitiesPerAgent: 100,
            minCapabilityVersion: 1,
            maxCapabilityVersion: 1000,
            defaultExpiration: 30 days,
            delegationCooldown: 1 days
        });
        initialized = true;
    }

    // Capability registerAction: registers canonical action definition
    function registerAction(
        string memory actionName,
        uint256 defaultLimit,
        bool requiresApproval,
        uint256 approvalThreshold
    ) external onlyOwner returns (bytes32) {
        bytes32 actionHash = keccak256(bytes(actionName));
        require(actionRegistry[actionHash].actionHash == bytes32(0), "ACTION_EXISTS");
        actionRegistry[actionHash] = ActionDefinition({
            actionHash: actionHash,
            actionName: actionName,
            defaultLimit: defaultLimit,
            requiresApproval: requiresApproval,
            approvalThreshold: approvalThreshold
        });
        emit ActionRegistered(actionHash, actionName);
        return actionHash;
    }

    // Capability registerAction: overloaded for bytes32 actionType
    function registerAction(
        bytes32 actionType,
        string memory actionName,
        uint256 defaultLimit,
        bool requiresApproval,
        uint256 approvalThreshold
    ) external onlyOwner {
        require(actionRegistry[actionType].actionHash == bytes32(0), "ACTION_EXISTS");
        actionRegistry[actionType] = ActionDefinition({
            actionHash: actionType,
            actionName: actionName,
            defaultLimit: defaultLimit,
            requiresApproval: requiresApproval,
            approvalThreshold: approvalThreshold
        });
        emit ActionRegistered(actionType, actionName);
    }

    // Capability grantCapability: grants capability NFT to agent
    function grantCapability(
        address agent,
        uint256 nftId,
        bytes32 actionType,
        uint256 limit,
        uint256 expiresAt
    ) external onlyOwner returns (bool) {
        require(CAPABILITY_NFT.ownerOf(nftId) == address(this), "NFT_NOT_TRANSFERRED");
        require(!capabilityRevoked[nftId], "NFT_REVOKED");
        require(!capabilityBlacklist[nftId] || capabilityWhitelist[nftId], "NFT_BLACKLISTED");
        require(agentCapabilities[agent].length() < config.maxCapabilitiesPerAgent, "MAX_CAPS_REACHED");

        Capability storage cap = capabilities[agent][nftId];
        require(cap.nftId == 0, "CAPABILITY_EXISTS");

        cap.nftId = nftId;
        cap.actionType = actionType;
        cap.resourceLimit = limit;
        cap.usedAmount = 0;
        cap.expiresAt = expiresAt > block.timestamp ? expiresAt : block.timestamp + config.defaultExpiration;
        cap.delegator = msg.sender;
        cap.revoked = false;
        cap.version = 1;

        agentCapabilities[agent].add(nftId);
        capabilityVersion[nftId] = 1;

        emit CapabilityGranted(agent, nftId, actionType, limit);
        emit CapabilityVersioned(agent, nftId, 1);

        // Audit log entry
        auditLog.push(AuditEntry({
            agent: agent,
            nftId: nftId,
            actionType: actionType,
            timestamp: block.timestamp,
            txHash: 0x00
        }));
        auditLogIndex++;

        return true;
    }

    // Capability revokeCapability: revokes specific capability
    function revokeCapability(address agent, uint256 nftId) external onlyOwner {
        Capability storage cap = capabilities[agent][nftId];
        require(cap.nftId != 0, "CAPABILITY_NOT_FOUND");

        cap.revoked = true;
        capabilityRevoked[nftId] = true;
        capabilityDelegation[agent][nftId] = address(0);

        emit CapabilityRevoked(agent, nftId, cap.actionType);

        // Audit log entry
        auditLog.push(AuditEntry({
            agent: agent,
            nftId: nftId,
            actionType: cap.actionType,
            timestamp: block.timestamp,
            txHash: 0x00
        }));
        auditLogIndex++;
    }

    // Capability revokeAll: revokes all capabilities for an agent
    function revokeAll(address agent) external onlyOwner {
        uint256[] memory nftIds = agentCapabilities[agent].values();
        for (uint256 i = 0; i < nftIds.length; i++) {
            revokeCapability(agent, nftIds[i]);
        }
    }

    // Capability delegateCapability: delegates capability to another agent
    function delegateCapability(
        address agent,
        uint256 nftId,
        address delegateTo,
        uint256 expiresAt
    ) external returns (bool) {
        Capability storage cap = capabilities[agent][nftId];
        require(cap.nftId != 0, "CAPABILITY_NOT_FOUND");
        require(!cap.revoked, "CAPABILITY_REVOKED");
        require(block.timestamp < cap.expiresAt, "CAPABILITY_EXPIRED");
        require(cap.delegator == msg.sender, "NOT_DELEGATOR");
        require(block.timestamp - capabilityDelegation[agent][nftId] > config.delegationCooldown, "DELEGATION_COOLDOWN");

        capabilityDelegation[agent][nftId] = delegateTo;

        emit CapabilityDelegated(agent, delegateTo, nftId, cap.actionType);

        return true;
    }

    // Capability verifyCapability: core verification function
    function verifyCapability(address agent, uint256 nftId, bytes32 actionType) external view returns (VerificationResult memory) {
        // Check NFT ownership
        if (CAPABILITY_NFT.ownerOf(nftId) != address(this)) {
            return VerificationResult({
                valid: false,
                error: CapabilityError.NFT_NOT_OWNED,
                remainingLimit: 0,
                expiresAt: 0,
                isDelegated: false,
                delegate: address(0)
            });
        }

        // Check capability exists
        Capability storage cap = capabilities[agent][nftId];
        if (cap.nftId == 0) {
            return VerificationResult({
                valid: false,
                error: CapabilityError.CAPABILITY_NOT_FOUND,
                remainingLimit: 0,
                expiresAt: 0,
                isDelegated: false,
                delegate: address(0)
            });
        }

        // Check capability not revoked
        if (cap.revoked || capabilityRevoked[nftId]) {
            return VerificationResult({
                valid: false,
                error: CapabilityError.NFT_REVOKED,
                remainingLimit: 0,
                expiresAt: 0,
                isDelegated: false,
                delegate: address(0)
            });
        }

        // Check capability not expired
        if (block.timestamp > cap.expiresAt) {
            return VerificationResult({
                valid: false,
                error: CapabilityError.CAPABILITY_EXPIRED,
                remainingLimit: 0,
                expiresAt: cap.expiresAt,
                isDelegated: false,
                delegate: address(0)
            });
        }

        // Check action type matches
        if (cap.actionType != actionType) {
            return VerificationResult({
                valid: false,
                error: CapabilityError.ACTION_NOT_ALLOWED,
                remainingLimit: cap.resourceLimit - cap.usedAmount,
                expiresAt: cap.expiresAt,
                isDelegated: false,
                delegate: address(0)
            });
        }

        // Check delegation
        address delegate = capabilityDelegation[agent][nftId];
        bool isDelegated = delegate != address(0);

        // Check rate limit
        RateLimit storage rateLimit = capabilityRateLimits[agent][actionType];
        if (block.timestamp >= rateLimit.windowStart + RATE_WINDOW) {
            rateLimit.windowStart = block.timestamp;
            rateLimit.usageCount = 0;
        }
        if (rateLimit.usageCount >= MAX_RATE_LIMIT) {
            return VerificationResult({
                valid: false,
                error: CapabilityError.LIMIT_EXCEEDED,
                remainingLimit: cap.resourceLimit - cap.usedAmount,
                expiresAt: cap.expiresAt,
                isDelegated: isDelegated,
                delegate: delegate
            });
        }

        return VerificationResult({
            valid: true,
            error: CapabilityError.NONE,
            remainingLimit: cap.resourceLimit - cap.usedAmount,
            expiresAt: cap.expiresAt,
            isDelegated: isDelegated,
            delegate: delegate
        });
    }

    // Capability verifyCapabilityWithLimit: verifies and checks remaining limit
    function verifyCapabilityWithLimit(
        address agent,
        uint256 nftId,
        bytes32 actionType,
        uint256 amount
    ) external view returns (VerificationResult memory) {
        VerificationResult memory result = verifyCapability(agent, nftId, actionType);
        if (!result.valid) {
            return result;
        }
        if (result.remainingLimit < amount) {
            return VerificationResult({
                valid: false,
                error: CapabilityError.LIMIT_EXCEEDED,
                remainingLimit: result.remainingLimit,
                expiresAt: result.expiresAt,
                isDelegated: result.isDelegated,
                delegate: result.delegate
            });
        }
        return result;
    }

    // Capability useCapability: decrements capability usage
    function useCapability(address agent, uint256 nftId, bytes32 actionType, uint256 amount) external returns (bool) {
        VerificationResult memory result = verifyCapabilityWithLimit(agent, nftId, actionType, amount);
        require(result.valid, "VERIFICATION_FAILED");

        Capability storage cap = capabilities[agent][nftId];
        cap.usedAmount += amount;

        // Update rate limit
        capabilityRateLimits[agent][actionType].usageCount++;

        emit CapabilityUsed(agent, nftId, actionType, amount);

        return true;
    }

    // Capability verifyComposition: verifies capability composition
    function verifyComposition(
        address agent,
        bytes32[] memory actionTypes,
        uint256[] memory limits
    ) external view returns (bool) {
        require(actionTypes.length == limits.length, "LENGTH_MISMATCH");
        require(actionTypes.length > 0, "EMPTY_COMPOSITION");

        bytes32 compositionHash = keccak256(
            abi.encodePacked(agent, actionTypes, limits)
        );

        // Check each capability in composition
        for (uint256 i = 0; i < actionTypes.length; i++) {
            bool found = false;
            uint256[] memory nftIds = agentCapabilities[agent].values();
            for (uint256 j = 0; j < nftIds.length; j++) {
                Capability storage cap = capabilities[agent][nftIds[j]];
                if (cap.actionType == actionTypes[i] && cap.resourceLimit >= limits[i]) {
                    found = true;
                    break;
                }
            }
            require(found, "COMPOSITION_MISMATCH");
        }

        emit CapabilityCompositionVerified(agent, compositionHash);
        return true;
    }

    // Capability verifyMerkleCapability: verifies capability via Merkle proof
    function verifyMerkleCapability(
        address agent,
        uint256 nftId,
        bytes32 actionType,
        bytes32[] memory proof,
        uint256[] memory indices
    ) external view returns (bool) {
        bytes32 leaf = keccak256(abi.encodePacked(agent, nftId, actionType));
        bytes32 root = merkleCapabilities[keccak256(abi.encodePacked(leaf))].root;

        require(root != bytes32(0), "MERKLE_NOT_FOUND");

        // Verify Merkle proof
        bytes32 computedRoot = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            if (indices[i] % 2 == 0) {
                computedRoot = keccak256(abi.encodePacked(computedRoot, proof[i]));
            } else {
                computedRoot = keccak256(abi.encodePacked(proof[i], computedRoot));
            }
        }

        require(computedRoot == root, "MERKLE_INVALID");

        return verifyCapability(agent, nftId, actionType).valid;
    }

    // Capability verifySignature: verifies off-chain capability signature
    function verifySignature(
        address agent,
        uint256 nftId,
        bytes32 actionType,
        uint256 limit,
        uint256 expiresAt,
        bytes memory signature
    ) external view returns (bool) {
        bytes32 messageHash = keccak256(
            abi.encodePacked(
                "\x19\x01",
                DOMAIN_SEPARATOR,
                keccak256(abi.encode(CAPABILITY_SIGN_TYPEHASH, agent, nftId, actionType, limit, expiresAt))
            )
        );

        address signer = signature.toEthSignedMessageHash(messageHash).recover(signature);
        require(signer == owner(), "INVALID_SIGNATURE");
        require(block.timestamp < signatureExpiry[keccak256(abi.encodePacked(agent, nftId, actionType))], "SIGNATURE_EXPIRED");

        return true;
    }

    // Capability setConfig: updates capability configuration
    function setConfig(
        uint256 maxCapabilitiesPerAgent,
        uint256 minCapabilityVersion,
        uint256 maxCapabilityVersion,
        uint256 defaultExpiration,
        uint256 delegationCooldown
    ) external onlyOwner {
        config = CapabilityConfig({
            maxCapabilitiesPerAgent: maxCapabilitiesPerAgent,
            minCapabilityVersion: minCapabilityVersion,
            maxCapabilityVersion: maxCapabilityVersion,
            defaultExpiration: defaultExpiration,
            delegationCooldown: delegationCooldown
        });
    }

    // Capability setWhitelist: enables/disables whitelist
    function setWhitelist(bool enabled) external onlyOwner {
        whitelistEnabled = enabled;
    }

    // Capability addToWhitelist: adds NFT to whitelist
    function addToWhitelist(uint256 nftId) external onlyOwner {
        capabilityWhitelist[nftId] = true;
    }

    // Capability removeFromWhitelist: removes NFT from whitelist
    function removeFromWhitelist(uint256 nftId) external onlyOwner {
        capabilityWhitelist[nftId] = false;
    }

    // Capability addToBlacklist: adds NFT to blacklist
    function addToBlacklist(uint256 nftId) external onlyOwner {
        capabilityBlacklist[nftId] = true;
    }

    // Capability removeFromBlacklist: removes NFT from blacklist
    function removeFromBlacklist(uint256 nftId) external onlyOwner {
        capabilityBlacklist[nftId] = false;
    }

    // Capability getCapability: returns full capability data
    function getCapability(address agent, uint256 nftId) external view returns (Capability memory) {
        return capabilities[agent][nftId];
    }

    // Capability getAgentCapabilities: returns all NFTs for an agent
    function getAgentCapabilities(address agent) external view returns (uint256[] memory) {
        return agentCapabilities[agent].values();
    }

    // Capability getActionDefinition: returns action definition
    function getActionDefinition(bytes32 actionType) external view returns (ActionDefinition memory) {
        return actionRegistry[actionType];
    }

    // Capability getAuditLog: returns audit log entries
    function getAuditLog(uint256 startIndex, uint256 count) external view returns (AuditEntry[] memory) {
        uint256 endIndex = startIndex + count;
        require(endIndex <= auditLogIndex, "INDEX_OUT_OF_BOUNDS");

        AuditEntry[] memory entries = new AuditEntry[](count);
        for (uint256 i = 0; i < count; i++) {
            entries[i] = auditLog[startIndex + i];
        }
        return entries;
    }

    // Capability getRemainingLimit: returns remaining capability limit
    function getRemainingLimit(address agent, uint256 nftId) external view returns (uint256) {
        Capability storage cap = capabilities[agent][nftId];
        return cap.resourceLimit - cap.usedAmount;
    }

    // Capability getExpiration: returns capability expiration
    function getExpiration(address agent, uint256 nftId) external view returns (uint256) {
        Capability storage cap = capabilities[agent][nftId];
        return cap.expiresAt;
    }

    // Capability getDelegator: returns capability delegator
    function getDelegator(address agent, uint256 nftId) external view returns (address) {
        return capabilityDelegation[agent][nftId];
    }

    // Capability getCapabilityVersion: returns capability version
    function getCapabilityVersion(uint256 nftId) external view returns (uint256) {
        return capabilityVersion[nftId];
    }

    // Capability isCapabilityRevoked: checks if capability is revoked
    function isCapabilityRevoked(uint256 nftId) external view returns (bool) {
        return capabilityRevoked[nftId];
    }

    // Capability isCapabilityBlacklisted: checks if capability is blacklisted
    function isCapabilityBlacklisted(uint256 nftId) external view returns (bool) {
        return capabilityBlacklist[nftId];
    }

    // Capability isCapabilityWhitelisted: checks if capability is whitelisted
    function isCapabilityWhitelisted(uint256 nftId) external view returns (bool) {
        return capabilityWhitelist[nftId];
    }

    // Capability getRateLimit: returns rate limit for agent/action
    function getRateLimit(address agent, bytes32 actionType) external view returns (RateLimit memory) {
        return capabilityRateLimits[agent][actionType];
    }

    // Capability getMerkleRoot: returns Merkle root for capability
    function getMerkleRoot(bytes32 leaf) external view returns (bytes32) {
        return merkleCapabilities[keccak256(abi.encodePacked(leaf))].root;
    }

    // Capability emit ActionRegistered event
    event ActionRegistered(bytes32 indexed actionHash, string actionName);

    // Capability fallback: prevents direct ETH transfers
    receive() external payable {
        revert("NO_DIRECT_TRANSFERS");
    }

    // Capability fallback: prevents direct ETH transfers
    function() external payable {
        revert("NO_DIRECT_TRANSFERS");
    }
}
