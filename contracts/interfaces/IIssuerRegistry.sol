// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/**
 * @title IIssuerRegistry
 * @notice Interface for the TrustPass Issuer Registry managing trusted issuers and key fingerprints.
 */
interface IIssuerRegistry {
    /**
     * @notice Check if an issuer address is currently active.
     * @param wallet The address of the issuer.
     * @return True if the issuer exists and is active, false otherwise.
     */
    function isActive(address wallet) external view returns (bool);

    /**
     * @notice Retrieve the current key fingerprint (RFC 7638 JWK thumbprint) of an issuer.
     * @param wallet The address of the issuer.
     * @return The 32-byte key fingerprint.
     */
    function getIssuerFingerprint(address wallet) external view returns (bytes32);

    /**
     * @notice Retrieve full issuer details.
     * @param wallet The address of the issuer.
     * @return name The institutional name of the issuer.
     * @return keyFingerprint The RFC 7638 JWK thumbprint of the issuer's ES256 key.
     * @return active Whether the issuer is currently active.
     */
    function getIssuer(address wallet) external view returns (string memory name, bytes32 keyFingerprint, bool active);
}
