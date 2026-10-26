// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IIssuerRegistry } from "./interfaces/IIssuerRegistry.sol";

/**
 * @title IssuerRegistry
 * @notice Central registry for trusted credential issuers in the TrustPass network.
 * @dev Implements two-step ownership, administrative suspension/reinstatement,
 *      and self-service key rotation for RFC 7638 ES256 JWK thumbprints.
 */
contract IssuerRegistry is IIssuerRegistry {
    // -------------------------------------------------------------------------
    // Structs
    // -------------------------------------------------------------------------

    struct Issuer {
        string name;
        bytes32 keyFingerprint;
        bool active;
        bool exists;
    }

    // -------------------------------------------------------------------------
    // State Variables
    // -------------------------------------------------------------------------

    /// @notice Current contract owner with administrative privileges.
    address public owner;

    /// @notice Address nominated to take over ownership during two-step transfer.
    address public pendingOwner;

    /// @dev Internal mapping storing registered issuers by wallet address.
    mapping(address => Issuer) private _issuers;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when a new trusted issuer is added.
    event IssuerAdded(address indexed wallet, string name, bytes32 keyFingerprint);

    /// @notice Emitted when an issuer is suspended by the owner.
    event IssuerSuspended(address indexed wallet);

    /// @notice Emitted when a suspended issuer is reinstated by the owner.
    event IssuerReinstated(address indexed wallet);

    /// @notice Emitted when an active issuer rotates its own key fingerprint.
    event KeyFingerprintRotated(address indexed wallet, bytes32 oldKeyFingerprint, bytes32 newKeyFingerprint);

    /// @notice Emitted when a two-step ownership transfer is initiated.
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);

    /// @notice Emitted when a two-step ownership transfer is completed.
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /// @notice Emitted when a pending ownership transfer is cancelled.
    event OwnershipTransferCancelled(address indexed owner, address indexed pendingOwner);

    // -------------------------------------------------------------------------
    // Custom Errors
    // -------------------------------------------------------------------------

    error Unauthorized();
    error NotPendingOwner();
    error ZeroAddress();
    error EmptyName();
    error ZeroKeyFingerprint();
    error IssuerAlreadyExists(address wallet);
    error IssuerNotFound(address wallet);
    error IssuerNotActive(address wallet);
    error IssuerAlreadyActive(address wallet);
    error IssuerAlreadySuspended(address wallet);
    error IdenticalKeyFingerprint();

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized();
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /**
     * @notice Initializes the registry with the deployer as initial owner.
     */
    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    // -------------------------------------------------------------------------
    // Two-Step Ownership Management
    // -------------------------------------------------------------------------

    /**
     * @notice Initiates a two-step ownership transfer to a new address.
     * @dev Only callable by the current owner.
     * @param newOwner Address to propose as the new owner.
     */
    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        if (newOwner == owner) revert Unauthorized();

        pendingOwner = newOwner;
        emit OwnershipTransferStarted(owner, newOwner);
    }

    /**
     * @notice Completes ownership transfer. Must be called by pendingOwner.
     */
    function acceptOwnership() external {
        if (msg.sender != pendingOwner) revert NotPendingOwner();

        address previousOwner = owner;
        owner = msg.sender;
        pendingOwner = address(0);

        emit OwnershipTransferred(previousOwner, msg.sender);
    }

    /**
     * @notice Cancels an ongoing ownership transfer.
     * @dev Only callable by the current owner.
     */
    function cancelOwnershipTransfer() external onlyOwner {
        address cancelled = pendingOwner;
        if (cancelled == address(0)) revert Unauthorized();

        pendingOwner = address(0);
        emit OwnershipTransferCancelled(owner, cancelled);
    }

    // -------------------------------------------------------------------------
    // Issuer Management (Owner)
    // -------------------------------------------------------------------------

    /**
     * @notice Registers a new trusted issuer.
     * @dev Only callable by the contract owner.
     * @param wallet The wallet address representing the issuer.
     * @param name The institutional name of the issuer (e.g. "University of TrustPass").
     * @param keyFingerprint The RFC 7638 SHA-256 JWK thumbprint of their ES256 key.
     */
    function addIssuer(
        address wallet,
        string calldata name,
        bytes32 keyFingerprint
    ) external onlyOwner {
        if (wallet == address(0)) revert ZeroAddress();
        if (bytes(name).length == 0) revert EmptyName();
        if (keyFingerprint == bytes32(0)) revert ZeroKeyFingerprint();

        Issuer storage issuer = _issuers[wallet];
        if (issuer.exists) revert IssuerAlreadyExists(wallet);

        _issuers[wallet] = Issuer({
            name: name,
            keyFingerprint: keyFingerprint,
            active: true,
            exists: true
        });

        emit IssuerAdded(wallet, name, keyFingerprint);
    }

    /**
     * @notice Suspends an active issuer, preventing new credential anchoring.
     * @dev Only callable by the contract owner.
     * @param wallet The address of the issuer to suspend.
     */
    function suspendIssuer(address wallet) external onlyOwner {
        Issuer storage issuer = _issuers[wallet];
        if (!issuer.exists) revert IssuerNotFound(wallet);
        if (!issuer.active) revert IssuerAlreadySuspended(wallet);

        issuer.active = false;
        emit IssuerSuspended(wallet);
    }

    /**
     * @notice Reinstates a previously suspended issuer.
     * @dev Only callable by the contract owner.
     * @param wallet The address of the issuer to reinstate.
     */
    function reinstateIssuer(address wallet) external onlyOwner {
        Issuer storage issuer = _issuers[wallet];
        if (!issuer.exists) revert IssuerNotFound(wallet);
        if (issuer.active) revert IssuerAlreadyActive(wallet);

        issuer.active = true;
        emit IssuerReinstated(wallet);
    }

    // -------------------------------------------------------------------------
    // Issuer Self-Service
    // -------------------------------------------------------------------------

    /**
     * @notice Rotates the caller's key fingerprint.
     * @dev Can only be called by an active issuer.
     * @param newKeyFingerprint The new RFC 7638 SHA-256 JWK thumbprint.
     */
    function rotateKeyFingerprint(bytes32 newKeyFingerprint) external {
        Issuer storage issuer = _issuers[msg.sender];
        if (!issuer.exists) revert IssuerNotFound(msg.sender);
        if (!issuer.active) revert IssuerNotActive(msg.sender);
        if (newKeyFingerprint == bytes32(0)) revert ZeroKeyFingerprint();
        if (newKeyFingerprint == issuer.keyFingerprint) revert IdenticalKeyFingerprint();

        bytes32 oldFingerprint = issuer.keyFingerprint;
        issuer.keyFingerprint = newKeyFingerprint;

        emit KeyFingerprintRotated(msg.sender, oldFingerprint, newKeyFingerprint);
    }

    // -------------------------------------------------------------------------
    // View Functions
    // -------------------------------------------------------------------------

    /**
     * @inheritdoc IIssuerRegistry
     */
    function isActive(address wallet) external view override returns (bool) {
        return _issuers[wallet].exists && _issuers[wallet].active;
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function getIssuerFingerprint(address wallet) external view override returns (bytes32) {
        Issuer storage issuer = _issuers[wallet];
        if (!issuer.exists) revert IssuerNotFound(wallet);
        return issuer.keyFingerprint;
    }

    /**
     * @inheritdoc IIssuerRegistry
     */
    function getIssuer(address wallet) external view override returns (
        string memory name,
        bytes32 keyFingerprint,
        bool active
    ) {
        Issuer storage issuer = _issuers[wallet];
        if (!issuer.exists) revert IssuerNotFound(wallet);
        return (issuer.name, issuer.keyFingerprint, issuer.active);
    }
}
