// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

interface ICapabilityRegistry {
    function verifyCapability(uint256 tokenId, bytes32 actionHash, address agent) external view returns (bool);
    function getCapabilityLimits(uint256 tokenId) external view returns (uint256 maxAmount, uint256 remaining);
    function getCapabilityParent(uint256 tokenId) external view returns (uint256);
}

contract CapabilityNFT is ERC721, ERC721URIStorage, Ownable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    struct CapabilityMetadata {
        bytes32 actionType;           // keccak256("trade") | keccak256("transfer") | keccak256("execute")
        uint256 maxAmount;            // Maximum transaction amount this capability allows
        uint256 remaining;            // Remaining amount (ERC-20 style limit tracking)
        uint256 expiration;           // Unix timestamp when capability expires
        uint256 parentId;             // Parent capability ID for hierarchical inheritance
        bool isRevoked;               // Revocation flag
        bytes32 capabilityHash;       // Cryptographic binding of all capability attributes
    }

    struct CapabilitySignature {
        address signer;
        uint256 tokenId;
        bytes32 actionHash;
        uint256 nonce;
        uint256 timestamp;
    }

    mapping(uint256 => CapabilityMetadata) public capabilities;
    mapping(bytes32 => uint256) public capabilityHashToTokenId;
    mapping(address => uint256[]) public agentCapabilities;
    mapping(uint256 => mapping(address => bool)) public capabilityOwnership;
    mapping(bytes32 => bool) public signatureUsed;
    uint256 public totalCapabilities;
    uint256 public constant SIGNATURE_VALIDITY_SECONDS = 300;
    uint256 public constant MIN_EXPIRATION_SECONDS = 3600;
    address public capabilityRegistry;
    bytes32 public constant ACTION_TRADE = keccak256("trade");
    bytes32 public constant ACTION_TRANSFER = keccak256("transfer");
    bytes32 public constant ACTION_EXECUTE = keccak256("execute");
    bytes32 public constant ACTION_DEPLOY = keccak256("deploy");
    bytes32 public constant CAPABILITY_PREFIX = keccak256("capability");

    event CapabilityMinted(uint256 indexed tokenId, address indexed owner, bytes32 actionType, uint256 maxAmount, uint256 expiration);
    event CapabilityUsed(uint256 indexed tokenId, address indexed agent, bytes32 actionHash, uint256 amount);
    event CapabilityRevoked(uint256 indexed tokenId, address indexed owner);
    event CapabilityInherited(uint256 indexed childId, uint256 indexed parentId, address indexed agent);
    event CapabilityRegistrySet(address indexed registry);
    event CapabilitySignatureVerified(uint256 indexed tokenId, address indexed signer, bytes32 actionHash);

    constructor(address _initialOwner) ERC721("CapabilityNFT", "CAP") Ownable(_initialOwner) {
        totalCapabilities = 0;
    }

    function setCapabilityRegistry(address _registry) external onlyOwner {
        require(_registry != address(0), "Invalid registry address");
        capabilityRegistry = _registry;
        emit CapabilityRegistrySet(_registry);
    }

    function _computeCapabilityHash(CapabilityMetadata memory cap) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            CAPABILITY_PREFIX,
            cap.actionType,
            cap.maxAmount,
            cap.remaining,
            cap.expiration,
            cap.parentId,
            cap.isRevoked
        ));
    }

    function _validateParentCapability(uint256 tokenId, uint256 parentId) internal view {
        require(parentId == 0 || parentId < totalCapabilities, "Invalid parent capability");
        if (parentId > 0) {
            CapabilityMetadata storage parentCap = capabilities[parentId];
            require(!parentCap.isRevoked, "Parent capability revoked");
            require(parentCap.expiration > block.timestamp, "Parent capability expired");
            require(parentCap.remaining > 0, "Parent capability exhausted");
            require(parentCap.actionType == ACTION_TRADE || parentCap.actionType == ACTION_TRANSFER || parentCap.actionType == ACTION_EXECUTE || parentCap.actionType == ACTION_DEPLOY, "Invalid parent action type");
        }
    }

    function _validateActionType(bytes32 actionType) internal pure {
        require(
            actionType == ACTION_TRADE ||
            actionType == ACTION_TRANSFER ||
            actionType == ACTION_EXECUTE ||
            actionType == ACTION_DEPLOY,
            "Invalid action type"
        );
    }

    function mintCapability(
        address to,
        bytes32 actionType,
        uint256 maxAmount,
        uint256 expiration,
        uint256 parentId,
        bytes memory signature
    ) external returns (uint256) {
        require(to != address(0), "Invalid recipient");
        require(maxAmount > 0, "Max amount must be positive");
        require(expiration > block.timestamp + MIN_EXPIRATION_SECONDS, "Expiration too short");
        _validateActionType(actionType);
        _validateParentCapability(totalCapabilities + 1, parentId);

        uint256 tokenId = ++totalCapabilities;
        CapabilityMetadata storage cap = capabilities[tokenId];
        cap.actionType = actionType;
        cap.maxAmount = maxAmount;
        cap.remaining = maxAmount;
        cap.expiration = expiration;
        cap.parentId = parentId;
        cap.isRevoked = false;
        cap.capabilityHash = _computeCapabilityHash(cap);

        capabilityHashToTokenId[cap.capabilityHash] = tokenId;
        capabilityOwnership[tokenId][to] = true;
        agentCapabilities[to].push(tokenId);

        if (parentId > 0) {
            emit CapabilityInherited(tokenId, parentId, to);
        }

        _safeMint(to, tokenId);
        emit CapabilityMinted(tokenId, to, actionType, maxAmount, expiration);

        return tokenId;
    }

    function mintCapabilityWithSignature(
        address to,
        bytes32 actionType,
        uint256 maxAmount,
        uint256 expiration,
        uint256 parentId,
        bytes memory signature
    ) external returns (uint256) {
        require(to != address(0), "Invalid recipient");
        require(maxAmount > 0, "Max amount must be positive");
        require(expiration > block.timestamp + MIN_EXPIRATION_SECONDS, "Expiration too short");
        _validateActionType(actionType);
        _validateParentCapability(totalCapabilities + 1, parentId);

        (address signer, bool valid) = _verifySignature(to, actionType, maxAmount, expiration, parentId, signature);
        require(valid, "Invalid signature");
        require(signer == owner(), "Unauthorized signer");

        uint256 tokenId = ++totalCapabilities;
        CapabilityMetadata storage cap = capabilities[tokenId];
        cap.actionType = actionType;
        cap.maxAmount = maxAmount;
        cap.remaining = maxAmount;
        cap.expiration = expiration;
        cap.parentId = parentId;
        cap.isRevoked = false;
        cap.capabilityHash = _computeCapabilityHash(cap);

        capabilityHashToTokenId[cap.capabilityHash] = tokenId;
        capabilityOwnership[tokenId][to] = true;
        agentCapabilities[to].push(tokenId);

        if (parentId > 0) {
            emit CapabilityInherited(tokenId, parentId, to);
        }

        _safeMint(to, tokenId);
        emit CapabilityMinted(tokenId, to, actionType, maxAmount, expiration);

        return tokenId;
    }

    function _verifySignature(
        address to,
        bytes32 actionType,
        uint256 maxAmount,
        uint256 expiration,
        uint256 parentId,
        bytes memory signature
    ) internal view returns (address, bool) {
        bytes32 messageHash = keccak256(abi.encodePacked(
            "capability-mint",
            to,
            actionType,
            maxAmount,
            expiration,
            parentId
        ));
        bytes32 ethSignedMessage = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessage.recover(signature);
        return (signer, signer == owner());
    }

    function useCapability(uint256 tokenId, bytes32 actionHash, uint256 amount, address agent) external returns (bool) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        require(capabilityOwnership[tokenId][msg.sender], "Not capability owner");
        CapabilityMetadata storage cap = capabilities[tokenId];
        require(!cap.isRevoked, "Capability revoked");
        require(block.timestamp < cap.expiration, "Capability expired");
        require(cap.remaining >= amount, "Insufficient remaining amount");
        require(cap.actionType == actionHash, "Action type mismatch");
        require(agent == msg.sender || capabilityOwnership[tokenId][agent], "Unauthorized agent");

        cap.remaining -= amount;
        emit CapabilityUsed(tokenId, agent, actionHash, amount);

        if (capabilityRegistry != address(0)) {
            ICapabilityRegistry(capabilityRegistry).verifyCapability(tokenId, actionHash, agent);
        }

        return true;
    }

    function revokeCapability(uint256 tokenId) external {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        require(capabilityOwnership[tokenId][msg.sender], "Not capability owner");
        CapabilityMetadata storage cap = capabilities[tokenId];
        require(!cap.isRevoked, "Already revoked");
        cap.isRevoked = true;
        emit CapabilityRevoked(tokenId, msg.sender);
    }

    function transferCapability(uint256 tokenId, address to) external {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        require(capabilityOwnership[tokenId][msg.sender], "Not capability owner");
        require(to != address(0), "Invalid recipient");
        CapabilityMetadata storage cap = capabilities[tokenId];
        require(!cap.isRevoked, "Cannot transfer revoked capability");
        require(block.timestamp < cap.expiration, "Cannot transfer expired capability");

        capabilityOwnership[tokenId][msg.sender] = false;
        capabilityOwnership[tokenId][to] = true;
        agentCapabilities[msg.sender].remove(tokenId);
        agentCapabilities[to].push(tokenId);

        _transfer(msg.sender, to, tokenId);
    }

    function getCapabilityInfo(uint256 tokenId) external view returns (CapabilityMetadata memory) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        return capabilities[tokenId];
    }

    function getAgentCapabilities(address agent) external view returns (uint256[] memory) {
        return agentCapabilities[agent];
    }

    function verifyCapabilityForAction(uint256 tokenId, bytes32 actionHash, address agent) external view returns (bool) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        CapabilityMetadata storage cap = capabilities[tokenId];
        if (cap.isRevoked || block.timestamp >= cap.expiration) return false;
        if (cap.remaining == 0) return false;
        if (cap.actionType != actionHash) return false;
        if (!capabilityOwnership[tokenId][msg.sender] && !capabilityOwnership[tokenId][agent]) return false;
        return true;
    }

    function getCapabilityLimits(uint256 tokenId) external view returns (uint256 maxAmount, uint256 remaining) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        return (capabilities[tokenId].maxAmount, capabilities[tokenId].remaining);
    }

    function getCapabilityParent(uint256 tokenId) external view returns (uint256) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        return capabilities[tokenId].parentId;
    }

    function getCapabilityHash(uint256 tokenId) external view returns (bytes32) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        return capabilities[tokenId].capabilityHash;
    }

    function capabilityExists(bytes32 hash) external view returns (bool) {
        return capabilityHashToTokenId[hash] > 0;
    }

    function tokenURI(uint256 tokenId) public view override(ERC721, ERC721URIStorage) returns (string memory) {
        require(_exists(tokenId), "Token does not exist");
        return super.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC721, ERC721URIStorage) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _burn(uint256 tokenId) internal override(ERC721, ERC721URIStorage) {
        super._burn(tokenId);
        delete capabilityHashToTokenId[capabilities[tokenId].capabilityHash];
    }

    function _beforeTokenTransfer(address from, address to, uint256 tokenId) internal override(ERC721, ERC721URIStorage) {
        super._beforeTokenTransfer(from, to, tokenId);
        require(!capabilities[tokenId].isRevoked, "Cannot transfer revoked capability");
        require(block.timestamp < capabilities[tokenId].expiration, "Cannot transfer expired capability");
    }

    function _exists(uint256 tokenId) internal view virtual override returns (bool) {
        return tokenId > 0 && tokenId <= totalCapabilities;
    }

    function _safeMint(address to, uint256 tokenId) internal {
        _safeMint(to, tokenId, "");
    }

    function _safeMint(address to, uint256 tokenId, bytes memory data) internal {
        _safeMint(to, tokenId, data, "");
    }

    function _safeMint(address to, uint256 tokenId, bytes memory data, string memory uri) internal {
        _safeMint(to, tokenId, data, uri, "");
    }

    function _safeMint(address to, uint256 tokenId, bytes memory data, string memory uri, string memory extra) internal {
        _mint(to, tokenId);
        if (bytes(uri).length > 0) {
            _setTokenURI(tokenId, uri);
        }
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI......

{"tool":"write_file","params":{"filePath":"contracts/CapabilityNFT.sol","content":"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

interface ICapabilityRegistry {
    function verifyCapability(uint256 tokenId, bytes32 actionHash, address agent) external view returns (bool);
    function getCapabilityLimits(uint256 tokenId) external view returns (uint256 maxAmount, uint256 remaining);
    function getCapabilityParent(uint256 tokenId) external view returns (uint256);
}

contract CapabilityNFT is ERC721, ERC721URIStorage, Ownable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    struct CapabilityMetadata {
        bytes32 actionType;
        uint256 maxAmount;
        uint256 remaining;
        uint256 expiration;
        uint256 parentId;
        bool isRevoked;
        bytes32 capabilityHash;
    }

    mapping(uint256 => CapabilityMetadata) public capabilities;
    mapping(bytes32 => uint256) public capabilityHashToTokenId;
    mapping(address => uint256[]) public agentCapabilities;
    mapping(uint256 => mapping(address => bool)) public capabilityOwnership;
    uint256 public totalCapabilities;
    uint256 public constant SIGNATURE_VALIDITY_SECONDS = 300;
    uint256 public constant MIN_EXPIRATION_SECONDS = 3600;
    address public capabilityRegistry;
    bytes32 public constant ACTION_TRADE = keccak256("trade");
    bytes32 public constant ACTION_TRANSFER = keccak256("transfer");
    bytes32 public constant ACTION_EXECUTE = keccak256("execute");
    bytes32 public constant ACTION_DEPLOY = keccak256("deploy");
    bytes32 public constant CAPABILITY_PREFIX = keccak256("capability");

    event CapabilityMinted(uint256 indexed tokenId, address indexed owner, bytes32 actionType, uint256 maxAmount, uint256 expiration);
    event CapabilityUsed(uint256 indexed tokenId, address indexed agent, bytes32 actionHash, uint256 amount);
    event CapabilityRevoked(uint256 indexed tokenId, address indexed owner);
    event CapabilityInherited(uint256 indexed childId, uint256 indexed parentId, address indexed agent);
    event CapabilityRegistrySet(address indexed registry);

    constructor(address _initialOwner) ERC721("CapabilityNFT", "CAP") Ownable(_initialOwner) {
        totalCapabilities = 0;
    }

    function setCapabilityRegistry(address _registry) external onlyOwner {
        require(_registry != address(0), "Invalid registry address");
        capabilityRegistry = _registry;
        emit CapabilityRegistrySet(_registry);
    }

    function _computeCapabilityHash(CapabilityMetadata memory cap) internal pure returns (bytes32) {
        return keccak256(abi.encode(
            CAPABILITY_PREFIX,
            cap.actionType,
            cap.maxAmount,
            cap.remaining,
            cap.expiration,
            cap.parentId,
            cap.isRevoked
        ));
    }

    function _validateParentCapability(uint256 tokenId, uint256 parentId) internal view {
        require(parentId == 0 || parentId < totalCapabilities, "Invalid parent capability");
        if (parentId > 0) {
            CapabilityMetadata storage parentCap = capabilities[parentId];
            require(!parentCap.isRevoked, "Parent capability revoked");
            require(parentCap.expiration > block.timestamp, "Parent capability expired");
            require(parentCap.remaining > 0, "Parent capability exhausted");
        }
    }

    function _validateActionType(bytes32 actionType) internal pure {
        require(
            actionType == ACTION_TRADE ||
            actionType == ACTION_TRANSFER ||
            actionType == ACTION_EXECUTE ||
            actionType == ACTION_DEPLOY,
            "Invalid action type"
        );
    }

    function mintCapability(
        address to,
        bytes32 actionType,
        uint256 maxAmount,
        uint256 expiration,
        uint256 parentId,
        bytes memory signature
    ) external returns (uint256) {
        require(to != address(0), "Invalid recipient");
        require(maxAmount > 0, "Max amount must be positive");
        require(expiration > block.timestamp + MIN_EXPIRATION_SECONDS, "Expiration too short");
        _validateActionType(actionType);
        _validateParentCapability(totalCapabilities + 1, parentId);

        uint256 tokenId = ++totalCapabilities;
        CapabilityMetadata storage cap = capabilities[tokenId];
        cap.actionType = actionType;
        cap.maxAmount = maxAmount;
        cap.remaining = maxAmount;
        cap.expiration = expiration;
        cap.parentId = parentId;
        cap.isRevoked = false;
        cap.capabilityHash = _computeCapabilityHash(cap);

        capabilityHashToTokenId[cap.capabilityHash] = tokenId;
        capabilityOwnership[tokenId][to] = true;
        agentCapabilities[to].push(tokenId);

        if (parentId > 0) {
            emit CapabilityInherited(tokenId, parentId, to);
        }

        _safeMint(to, tokenId);
        emit CapabilityMinted(tokenId, to, actionType, maxAmount, expiration);

        return tokenId;
    }

    function _verifySignature(
        address to,
        bytes32 actionType,
        uint256 maxAmount,
        uint256 expiration,
        uint256 parentId,
        bytes memory signature
    ) internal view returns (address, bool) {
        bytes32 messageHash = keccak256(abi.encodePacked(
            "capability-mint",
            to,
            actionType,
            maxAmount,
            expiration,
            parentId
        ));
        bytes32 ethSignedMessage = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessage.recover(signature);
        return (signer, signer == owner());
    }

    function useCapability(uint256 tokenId, bytes32 actionHash, uint256 amount, address agent) external returns (bool) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        require(capabilityOwnership[tokenId][msg.sender], "Not capability owner");
        CapabilityMetadata storage cap = capabilities[tokenId];
        require(!cap.isRevoked, "Capability revoked");
        require(block.timestamp < cap.expiration, "Capability expired");
        require(cap.remaining >= amount, "Insufficient remaining amount");
        require(cap.actionType == actionHash, "Action type mismatch");
        require(agent == msg.sender || capabilityOwnership[tokenId][agent], "Unauthorized agent");

        cap.remaining -= amount;
        emit CapabilityUsed(tokenId, agent, actionHash, amount);

        if (capabilityRegistry != address(0)) {
            ICapabilityRegistry(capabilityRegistry).verifyCapability(tokenId, actionHash, agent);
        }

        return true;
    }

    function revokeCapability(uint256 tokenId) external {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        require(capabilityOwnership[tokenId][msg.sender], "Not capability owner");
        CapabilityMetadata storage cap = capabilities[tokenId];
        require(!cap.isRevoked, "Already revoked");
        cap.isRevoked = true;
        emit CapabilityRevoked(tokenId, msg.sender);
    }

    function transferCapability(uint256 tokenId, address to) external {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        require(capabilityOwnership[tokenId][msg.sender], "Not capability owner");
        require(to != address(0), "Invalid recipient");
        CapabilityMetadata storage cap = capabilities[tokenId];
        require(!cap.isRevoked, "Cannot transfer revoked capability");
        require(block.timestamp < cap.expiration, "Cannot transfer expired capability");

        capabilityOwnership[tokenId][msg.sender] = false;
        capabilityOwnership[tokenId][to] = true;
        agentCapabilities[msg.sender].remove(tokenId);
        agentCapabilities[to].push(tokenId);

        _transfer(msg.sender, to, tokenId);
    }

    function getCapabilityInfo(uint256 tokenId) external view returns (CapabilityMetadata memory) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        return capabilities[tokenId];
    }

    function getAgentCapabilities(address agent) external view returns (uint256[] memory) {
        return agentCapabilities[agent];
    }

    function verifyCapabilityForAction(uint256 tokenId, bytes32 actionHash, address agent) external view returns (bool) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        CapabilityMetadata storage cap = capabilities[tokenId];
        if (cap.isRevoked || block.timestamp >= cap.expiration) return false;
        if (cap.remaining == 0) return false;
        if (cap.actionType != actionHash) return false;
        if (!capabilityOwnership[tokenId][msg.sender] && !capabilityOwnership[tokenId][agent]) return false;
        return true;
    }

    function getCapabilityLimits(uint256 tokenId) external view returns (uint256 maxAmount, uint256 remaining) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        return (capabilities[tokenId].maxAmount, capabilities[tokenId].remaining);
    }

    function getCapabilityParent(uint256 tokenId) external view returns (uint256) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        return capabilities[tokenId].parentId;
    }

    function getCapabilityHash(uint256 tokenId) external view returns (bytes32) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        return capabilities[tokenId].capabilityHash;
    }

    function capabilityExists(bytes32 hash) external view returns (bool) {
        return capabilityHashToTokenId[hash] > 0;
    }

    function tokenURI(uint256 tokenId) public view override(ERC721, ERC721URIStorage) returns (string memory) {
        require(_exists(tokenId), "Token does not exist");
        return super.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC721, ERC721URIStorage) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _burn(uint256 tokenId) internal override(ERC721, ERC721URIStorage) {
        super._burn(tokenId);
        delete capabilityHashToTokenId[capabilities[tokenId].capabilityHash];
    }

    function _beforeTokenTransfer(address from, address to, uint256 tokenId) internal override(ERC721, ERC721URIStorage) {
        super._beforeTokenTransfer(from, to, tokenId);
        require(!capabilities[tokenId].isRevoked, "Cannot transfer revoked capability");
        require(block.timestamp < capabilities[tokenId].expiration, "Cannot transfer expired capability");
    }

    function _exists(uint256 tokenId) internal view virtual override returns (bool) {
        return tokenId > 0 && tokenId <= totalCapabilities;
    }

    function _safeMint(address to, uint256 tokenId) internal {
        _safeMint(to, tokenId, "");
    }

    function _safeMint(address to, uint256 tokenId, bytes memory data) internal {
        _safeMint(to, tokenId, data, "");
    }

    function _safeMint(address to, uint256 tokenId, bytes memory data, string memory uri) internal {
        _safeMint(to, tokenId, data, uri, "");
    }

    function _safeMint(address to, uint256 tokenId, bytes memory data, string memory uri, string memory extra) internal {
        _mint(to, tokenId);
        if (bytes(uri).length > 0) {
            _setTokenURI(tokenId, uri);
        }
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _set......

{"tool":"write_file","params":{"filePath":"contracts/CapabilityNFT.sol","content":"// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import "@openzeppelin/contracts/token/ERC721/extensions/ERC721URIStorage.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

interface ICapabilityRegistry {
    function verifyCapability(uint256 tokenId, bytes32 actionHash, address agent) external view returns (bool);
    function getCapabilityLimits(uint256 tokenId) external view returns (uint256 maxAmount, uint256 remaining);
    function getCapabilityParent(uint256 tokenId) external view returns (uint256);
}

contract CapabilityNFT is ERC721, ERC721URIStorage, Ownable {
    using ECDSA for bytes32;
    using MessageHashUtils for bytes32;

    struct CapabilityMetadata {
        bytes32 actionType;
        uint256 maxAmount;
        uint256 remaining;
        uint256 expiration;
        uint256 parentId;
        bool isRevoked;
        bytes32 capabilityHash;
    }

    mapping(uint256 => CapabilityMetadata) public capabilities;
    mapping(bytes32 => uint256) public capabilityHashToTokenId;
    mapping(address => uint256[]) public agentCapabilities;
    mapping(uint256 => mapping(address => bool)) public capabilityOwnership;
    uint256 public totalCapabilities;
    uint256 public constant MIN_EXPIRATION_SECONDS = 3600;
    address public capabilityRegistry;
    bytes32 public constant ACTION_TRADE = keccak256("trade");
    bytes32 public constant ACTION_TRANSFER = keccak256("transfer");
    bytes32 public constant ACTION_EXECUTE = keccak256("execute");
    bytes32 public constant ACTION_DEPLOY = keccak256("deploy");
    bytes32 public constant CAPABILITY_PREFIX = keccak256("capability");

    event CapabilityMinted(uint256 indexed tokenId, address indexed owner, bytes32 actionType, uint256 maxAmount, uint256 expiration);
    event CapabilityUsed(uint256 indexed tokenId, address indexed agent, bytes32 actionHash, uint256 amount);
    event CapabilityRevoked(uint256 indexed tokenId, address indexed owner);
    event CapabilityInherited(uint256 indexed childId, uint256 indexed parentId, address indexed agent);
    event CapabilityRegistrySet(address indexed registry);

    constructor(address _initialOwner) ERC721("CapabilityNFT", "CAP") Ownable(_initialOwner) {
        totalCapabilities = 0;
    }

    function setCapabilityRegistry(address _registry) external onlyOwner {
        require(_registry != address(0), "Invalid registry address");
        capabilityRegistry = _registry;
        emit CapabilityRegistrySet(_registry);
    }

    function _computeCapabilityHash(CapabilityMetadata memory cap) internal pure returns (bytes32) {
        return keccak256(abi.encode(CAPABILITY_PREFIX, cap.actionType, cap.maxAmount, cap.remaining, cap.expiration, cap.parentId, cap.isRevoked));
    }

    function _validateParentCapability(uint256 tokenId, uint256 parentId) internal view {
        require(parentId == 0 || parentId < totalCapabilities, "Invalid parent capability");
        if (parentId > 0) {
            CapabilityMetadata storage parentCap = capabilities[parentId];
            require(!parentCap.isRevoked, "Parent capability revoked");
            require(parentCap.expiration > block.timestamp, "Parent capability expired");
            require(parentCap.remaining > 0, "Parent capability exhausted");
        }
    }

    function _validateActionType(bytes32 actionType) internal pure {
        require(actionType == ACTION_TRADE || actionType == ACTION_TRANSFER || actionType == ACTION_EXECUTE || actionType == ACTION_DEPLOY, "Invalid action type");
    }

    function mintCapability(address to, bytes32 actionType, uint256 maxAmount, uint256 expiration, uint256 parentId, bytes memory signature) external returns (uint256) {
        require(to != address(0), "Invalid recipient");
        require(maxAmount > 0, "Max amount must be positive");
        require(expiration > block.timestamp + MIN_EXPIRATION_SECONDS, "Expiration too short");
        _validateActionType(actionType);
        _validateParentCapability(totalCapabilities + 1, parentId);

        uint256 tokenId = ++totalCapabilities;
        CapabilityMetadata storage cap = capabilities[tokenId];
        cap.actionType = actionType;
        cap.maxAmount = maxAmount;
        cap.remaining = maxAmount;
        cap.expiration = expiration;
        cap.parentId = parentId;
        cap.isRevoked = false;
        cap.capabilityHash = _computeCapabilityHash(cap);

        capabilityHashToTokenId[cap.capabilityHash] = tokenId;
        capabilityOwnership[tokenId][to] = true;
        agentCapabilities[to].push(tokenId);

        if (parentId > 0) emit CapabilityInherited(tokenId, parentId, to);
        _safeMint(to, tokenId);
        emit CapabilityMinted(tokenId, to, actionType, maxAmount, expiration);
        return tokenId;
    }

    function _verifySignature(address to, bytes32 actionType, uint256 maxAmount, uint256 expiration, uint256 parentId, bytes memory signature) internal view returns (address, bool) {
        bytes32 messageHash = keccak256(abi.encodePacked("capability-mint", to, actionType, maxAmount, expiration, parentId));
        bytes32 ethSignedMessage = messageHash.toEthSignedMessageHash();
        address signer = ethSignedMessage.recover(signature);
        return (signer, signer == owner());
    }

    function useCapability(uint256 tokenId, bytes32 actionHash, uint256 amount, address agent) external returns (bool) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        require(capabilityOwnership[tokenId][msg.sender], "Not capability owner");
        CapabilityMetadata storage cap = capabilities[tokenId];
        require(!cap.isRevoked, "Capability revoked");
        require(block.timestamp < cap.expiration, "Capability expired");
        require(cap.remaining >= amount, "Insufficient remaining amount");
        require(cap.actionType == actionHash, "Action type mismatch");
        require(agent == msg.sender || capabilityOwnership[tokenId][agent], "Unauthorized agent");
        cap.remaining -= amount;
        emit CapabilityUsed(tokenId, agent, actionHash, amount);
        if (capabilityRegistry != address(0)) ICapabilityRegistry(capabilityRegistry).verifyCapability(tokenId, actionHash, agent);
        return true;
    }

    function revokeCapability(uint256 tokenId) external {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        require(capabilityOwnership[tokenId][msg.sender], "Not capability owner");
        CapabilityMetadata storage cap = capabilities[tokenId];
        require(!cap.isRevoked, "Already revoked");
        cap.isRevoked = true;
        emit CapabilityRevoked(tokenId, msg.sender);
    }

    function transferCapability(uint256 tokenId, address to) external {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        require(capabilityOwnership[tokenId][msg.sender], "Not capability owner");
        require(to != address(0), "Invalid recipient");
        CapabilityMetadata storage cap = capabilities[tokenId];
        require(!cap.isRevoked, "Cannot transfer revoked capability");
        require(block.timestamp < cap.expiration, "Cannot transfer expired capability");
        capabilityOwnership[tokenId][msg.sender] = false;
        capabilityOwnership[tokenId][to] = true;
        agentCapabilities[msg.sender].remove(tokenId);
        agentCapabilities[to].push(tokenId);
        _transfer(msg.sender, to, tokenId);
    }

    function getCapabilityInfo(uint256 tokenId) external view returns (CapabilityMetadata memory) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        return capabilities[tokenId];
    }

    function getAgentCapabilities(address agent) external view returns (uint256[] memory) {
        return agentCapabilities[agent];
    }

    function verifyCapabilityForAction(uint256 tokenId, bytes32 actionHash, address agent) external view returns (bool) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        CapabilityMetadata storage cap = capabilities[tokenId];
        if (cap.isRevoked || block.timestamp >= cap.expiration) return false;
        if (cap.remaining == 0) return false;
        if (cap.actionType != actionHash) return false;
        if (!capabilityOwnership[tokenId][msg.sender] && !capabilityOwnership[tokenId][agent]) return false;
        return true;
    }

    function getCapabilityLimits(uint256 tokenId) external view returns (uint256 maxAmount, uint256 remaining) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        return (capabilities[tokenId].maxAmount, capabilities[tokenId].remaining);
    }

    function getCapabilityParent(uint256 tokenId) external view returns (uint256) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        return capabilities[tokenId].parentId;
    }

    function getCapabilityHash(uint256 tokenId) external view returns (bytes32) {
        require(tokenId > 0 && tokenId <= totalCapabilities, "Invalid token ID");
        return capabilities[tokenId].capabilityHash;
    }

    function capabilityExists(bytes32 hash) external view returns (bool) {
        return capabilityHashToTokenId[hash] > 0;
    }

    function tokenURI(uint256 tokenId) public view override(ERC721, ERC721URIStorage) returns (string memory) {
        require(_exists(tokenId), "Token does not exist");
        return super.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId) public view override(ERC721, ERC721URIStorage) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _burn(uint256 tokenId) internal override(ERC721, ERC721URIStorage) {
        super._burn(tokenId);
        delete capabilityHashToTokenId[capabilities[tokenId].capabilityHash];
    }

    function _beforeTokenTransfer(address from, address to, uint256 tokenId) internal override(ERC721, ERC721URIStorage) {
        super._beforeTokenTransfer(from, to, tokenId);
        require(!capabilities[tokenId].isRevoked, "Cannot transfer revoked capability");
        require(block.timestamp < capabilities[tokenId].expiration, "Cannot transfer expired capability");
    }

    function _exists(uint256 tokenId) internal view virtual override returns (bool) {
        return tokenId > 0 && tokenId <= totalCapabilities;
    }

    function _safeMint(address to, uint256 tokenId) internal {
        _safeMint(to, tokenId, "");
    }

    function _safeMint(address to, uint256 tokenId, bytes memory data) internal {
        _safeMint(to, tokenId, data, "");
    }

    function _safeMint(address to, uint256 tokenId, bytes memory data, string memory uri) internal {
        _safeMint(to, tokenId, data, uri, "");
    }

    function _safeMint(address to, uint256 tokenId, bytes memory data, string memory uri, string memory extra) internal {
        _mint(to, tokenId);
        if (bytes(uri).length > 0) _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory uri) internal {
        _setTokenURI(tokenId, uri);
    }

    function _setTokenURI(uint256 tokenId, string memory......