// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { IIssuerRegistry } from "./interfaces/IIssuerRegistry.sol";

/**
 * @title CredentialAnchor
 * @notice Anchors SD-JWT VC commitments on-chain to provide cryptographic tamper
 *         evidence, issuer key binding snapshots, validity checks, and revocation.
 * @dev No personal data is stored on-chain. Anchors store only the SHA-256 hash of the
 *      issuer-signed SD-JWT VC, the issuer's key fingerprint snapshot, and timestamps.
 */
contract CredentialAnchor {
    // -------------------------------------------------------------------------
    // Enums & Structs
    // -------------------------------------------------------------------------

    /// @notice States of an anchored credential.
    enum CredentialState {
        Unknown, // Hash has not been anchored
        Valid,   // Anchored, not revoked, not expired
        Revoked, // Revoked by the issuing entity
        Expired  // Passed expiry timestamp
    }

    /// @notice Record representing an anchored credential on-chain.
    struct AnchorRecord {
        address issuer;       // Address of the issuer at anchor time
        uint64 issuedAt;      // Block timestamp when credential was anchored
        uint64 expiry;        // Expiry timestamp (0 = never expires)
        bytes32 fingerprint;  // Snapshot of issuer's key fingerprint at anchor time
        bool revoked;         // Whether credential has been explicitly revoked
        bool exists;          // Record existence flag
    }

    // -------------------------------------------------------------------------
    // State Variables
    // -------------------------------------------------------------------------

    /// @notice Address of the official TrustPass Issuer Registry.
    IIssuerRegistry public immutable registry;

    /// @dev Internal mapping from credential hash (SHA-256 bytes32) to AnchorRecord.
    mapping(bytes32 => AnchorRecord) private _anchors;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when a new credential commitment is anchored.
    event CredentialAnchored(
        bytes32 indexed hash,
        address indexed issuer,
        uint64 issuedAt,
        uint64 expiry,
        bytes32 fingerprint
    );

    /// @notice Emitted when an anchored credential is revoked by its issuer.
    event CredentialRevoked(
        bytes32 indexed hash,
        address indexed issuer
    );

    // -------------------------------------------------------------------------
    // Custom Errors
    // -------------------------------------------------------------------------

    error ZeroAddress();
    error ZeroHash();
    error IssuerNotActive(address caller);
    error DuplicateCredentialHash(bytes32 hash);
    error CredentialNotFound(bytes32 hash);
    error NotOriginalIssuer(bytes32 hash, address caller, address actualIssuer);
    error AlreadyRevoked(bytes32 hash);
    error InvalidExpiry(uint64 expiry, uint256 currentTimestamp);

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /**
     * @notice Initializes the CredentialAnchor with the trusted IssuerRegistry.
     * @param registryAddress The address of the deployed IssuerRegistry contract.
     */
    constructor(address registryAddress) {
        if (registryAddress == address(0)) revert ZeroAddress();
        registry = IIssuerRegistry(registryAddress);
    }

    // -------------------------------------------------------------------------
    // External Functions
    // -------------------------------------------------------------------------

    /**
     * @notice Anchors an SD-JWT VC commitment hash on-chain.
     * @dev Caller must be an active issuer in the registry. Captures an immutable
     *      snapshot of the issuer's key fingerprint at this exact block.
     * @param hash The SHA-256 hash (bytes32) of the complete issuer-signed JWT.
     * @param expiry Expiry UNIX timestamp (uint64). Set to 0 for non-expiring credentials.
     */
    function anchor(bytes32 hash, uint64 expiry) external {
        if (!registry.isActive(msg.sender)) revert IssuerNotActive(msg.sender);
        if (hash == bytes32(0)) revert ZeroHash();
        if (_anchors[hash].exists) revert DuplicateCredentialHash(hash);
        if (expiry != 0 && expiry <= block.timestamp) {
            revert InvalidExpiry(expiry, block.timestamp);
        }

        // Efficiently read only the key fingerprint (avoids copying name string)
        bytes32 fingerprint = registry.getIssuerFingerprint(msg.sender);
        uint64 issuedAt = uint64(block.timestamp);

        _anchors[hash] = AnchorRecord({
            issuer: msg.sender,
            issuedAt: issuedAt,
            expiry: expiry,
            fingerprint: fingerprint,
            revoked: false,
            exists: true
        });

        emit CredentialAnchored(hash, msg.sender, issuedAt, expiry, fingerprint);
    }

    /**
     * @notice Revokes a previously anchored credential.
     * @dev Can only be called by the original issuer. Suspended issuers retain the
     *      security right to revoke credentials they originally issued.
     * @param hash The SHA-256 hash of the credential to revoke.
     */
    function revoke(bytes32 hash) external {
        AnchorRecord storage record = _anchors[hash];
        if (!record.exists) revert CredentialNotFound(hash);
        if (msg.sender != record.issuer) {
            revert NotOriginalIssuer(hash, msg.sender, record.issuer);
        }
        if (record.revoked) revert AlreadyRevoked(hash);

        record.revoked = true;
        emit CredentialRevoked(hash, msg.sender);
    }

    // -------------------------------------------------------------------------
    // View Functions
    // -------------------------------------------------------------------------

    /**
     * @notice Evaluates the current state and parameters of a credential hash.
     * @param hash The SHA-256 hash of the credential.
     * @return state The credential state (Unknown, Valid, Revoked, or Expired).
     * @return issuer The address of the original issuing wallet.
     * @return fingerprint The snapshot of the issuer's key fingerprint at anchor time.
     * @return issuerActive Whether the issuer is currently active in the registry.
     */
    function status(bytes32 hash) external view returns (
        CredentialState state,
        address issuer,
        bytes32 fingerprint,
        bool issuerActive
    ) {
        AnchorRecord storage record = _anchors[hash];
        if (!record.exists) {
            return (CredentialState.Unknown, address(0), bytes32(0), false);
        }

        issuer = record.issuer;
        fingerprint = record.fingerprint;
        issuerActive = registry.isActive(record.issuer);

        if (record.revoked) {
            state = CredentialState.Revoked;
        } else if (record.expiry != 0 && block.timestamp >= record.expiry) {
            // Note: block.timestamp == record.expiry counts as Expired
            state = CredentialState.Expired;
        } else {
            state = CredentialState.Valid;
        }
    }

    /**
     * @notice Retrieves full anchor record details.
     * @param hash The SHA-256 hash of the credential.
     * @return The complete AnchorRecord.
     */
    function getAnchor(bytes32 hash) external view returns (AnchorRecord memory) {
        AnchorRecord storage record = _anchors[hash];
        if (!record.exists) revert CredentialNotFound(hash);
        return record;
    }
}
