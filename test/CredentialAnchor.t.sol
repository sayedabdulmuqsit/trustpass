// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/src/Test.sol";
import { IssuerRegistry } from "../contracts/IssuerRegistry.sol";
import { CredentialAnchor } from "../contracts/CredentialAnchor.sol";

contract CredentialAnchorTest is Test {
    IssuerRegistry public registry;
    CredentialAnchor public anchorContract;

    address public owner;
    address public issuerA;
    address public issuerB;
    address public unauthorizedUser;

    bytes32 public constant FINGERPRINT_A = bytes32(uint256(0xAAAA));
    bytes32 public constant FINGERPRINT_B = bytes32(uint256(0xBBBB));
    bytes32 public constant FINGERPRINT_ROTATED = bytes32(uint256(0xCCCC));

    bytes32 public constant CRED_HASH_1 = bytes32(uint256(0x1001));
    bytes32 public constant CRED_HASH_2 = bytes32(uint256(0x1002));

    // Events mirrored for vm.expectEmit checks
    event CredentialAnchored(
        bytes32 indexed hash,
        address indexed issuer,
        uint64 issuedAt,
        uint64 expiry,
        bytes32 fingerprint
    );
    event CredentialRevoked(
        bytes32 indexed hash,
        address indexed issuer
    );

    function setUp() public {
        owner = address(this);
        issuerA = makeAddr("issuerA");
        issuerB = makeAddr("issuerB");
        unauthorizedUser = makeAddr("unauthorizedUser");

        registry = new IssuerRegistry();
        anchorContract = new CredentialAnchor(address(registry));

        // Add Issuer A & Issuer B
        registry.addIssuer(issuerA, "University A", FINGERPRINT_A);
        registry.addIssuer(issuerB, "University B", FINGERPRINT_B);
    }

    // =========================================================================
    // Constructor Validation
    // =========================================================================

    function test_ConstructorRevertsOnZeroAddress() public {
        vm.expectRevert(CredentialAnchor.ZeroAddress.selector);
        new CredentialAnchor(address(0));
    }

    function test_ConstructorSetsRegistryCorrectly() public view {
        assertEq(address(anchorContract.registry()), address(registry));
    }

    // =========================================================================
    // Anchoring Logic & Access Control
    // =========================================================================

    function test_ActiveIssuerCanAnchor_EmitsEvent() public {
        uint64 expiry = uint64(block.timestamp + 365 days);

        vm.prank(issuerA);
        vm.expectEmit(true, true, false, true);
        emit CredentialAnchored(CRED_HASH_1, issuerA, uint64(block.timestamp), expiry, FINGERPRINT_A);

        anchorContract.anchor(CRED_HASH_1, expiry);

        (
            CredentialAnchor.CredentialState state,
            address issuer,
            bytes32 fp,
            bool issuerActive
        ) = anchorContract.status(CRED_HASH_1);

        assertEq(uint8(state), uint8(CredentialAnchor.CredentialState.Valid));
        assertEq(issuer, issuerA);
        assertEq(fp, FINGERPRINT_A);
        assertTrue(issuerActive);
    }

    function test_RevertWhen_NonActiveIssuerAnchors() public {
        vm.prank(unauthorizedUser);
        vm.expectRevert(abi.encodeWithSelector(CredentialAnchor.IssuerNotActive.selector, unauthorizedUser));
        anchorContract.anchor(CRED_HASH_1, 0);
    }

    function test_RevertWhen_SuspendedIssuerAnchors() public {
        registry.suspendIssuer(issuerA);

        vm.prank(issuerA);
        vm.expectRevert(abi.encodeWithSelector(CredentialAnchor.IssuerNotActive.selector, issuerA));
        anchorContract.anchor(CRED_HASH_1, 0);
    }

    function test_ReinstatedIssuerCanAnchorAgain() public {
        // Suspend
        registry.suspendIssuer(issuerA);
        vm.prank(issuerA);
        vm.expectRevert(abi.encodeWithSelector(CredentialAnchor.IssuerNotActive.selector, issuerA));
        anchorContract.anchor(CRED_HASH_1, 0);

        // Reinstate
        registry.reinstateIssuer(issuerA);

        // Can anchor successfully
        vm.prank(issuerA);
        anchorContract.anchor(CRED_HASH_1, 0);

        (CredentialAnchor.CredentialState state,,, bool issuerActive) = anchorContract.status(CRED_HASH_1);
        assertEq(uint8(state), uint8(CredentialAnchor.CredentialState.Valid));
        assertTrue(issuerActive);
    }

    function test_RevertWhen_AnchorWithZeroHash() public {
        vm.prank(issuerA);
        vm.expectRevert(CredentialAnchor.ZeroHash.selector);
        anchorContract.anchor(bytes32(0), 0);
    }

    function test_RevertWhen_AnchorDuplicateHash() public {
        vm.prank(issuerA);
        anchorContract.anchor(CRED_HASH_1, 0);

        // Second attempt by same issuer
        vm.prank(issuerA);
        vm.expectRevert(abi.encodeWithSelector(CredentialAnchor.DuplicateCredentialHash.selector, CRED_HASH_1));
        anchorContract.anchor(CRED_HASH_1, 0);

        // Second attempt by different active issuer
        vm.prank(issuerB);
        vm.expectRevert(abi.encodeWithSelector(CredentialAnchor.DuplicateCredentialHash.selector, CRED_HASH_1));
        anchorContract.anchor(CRED_HASH_1, 0);
    }

    function test_RevertWhen_ExpiryIsInPastOrCurrent() public {
        vm.warp(1000);

        vm.prank(issuerA);
        vm.expectRevert(abi.encodeWithSelector(CredentialAnchor.InvalidExpiry.selector, 1000, 1000));
        anchorContract.anchor(CRED_HASH_1, 1000);

        vm.prank(issuerA);
        vm.expectRevert(abi.encodeWithSelector(CredentialAnchor.InvalidExpiry.selector, 999, 1000));
        anchorContract.anchor(CRED_HASH_1, 999);
    }

    // =========================================================================
    // Key Rotation Snapshot Invariance
    // =========================================================================

    function test_StatusReturnsOldFingerprintSnapshotAfterKeyRotation() public {
        // 1. Anchor with initial fingerprint A
        vm.prank(issuerA);
        anchorContract.anchor(CRED_HASH_1, 0);

        // Verify initial snapshot is Fingerprint A
        (,, bytes32 fpBefore,) = anchorContract.status(CRED_HASH_1);
        assertEq(fpBefore, FINGERPRINT_A);

        // 2. Issuer rotates key in registry to FINGERPRINT_ROTATED
        vm.prank(issuerA);
        registry.rotateKeyFingerprint(FINGERPRINT_ROTATED);
        assertEq(registry.getIssuerFingerprint(issuerA), FINGERPRINT_ROTATED);

        // 3. Anchor status MUST STILL RETURN OLD FINGERPRINT_A snapshot
        (
            CredentialAnchor.CredentialState state,
            address issuer,
            bytes32 fpAfter,
            bool issuerActive
        ) = anchorContract.status(CRED_HASH_1);

        assertEq(uint8(state), uint8(CredentialAnchor.CredentialState.Valid));
        assertEq(issuer, issuerA);
        assertEq(fpAfter, FINGERPRINT_A); // Unchanged!
        assertTrue(issuerActive);
    }

    // =========================================================================
    // Issuer Suspension & Status Impact
    // =========================================================================

    function test_IssuerSuspensionImpactOnStatus() public {
        vm.prank(issuerA);
        anchorContract.anchor(CRED_HASH_1, 0);

        // Initial check: Valid & active
        (CredentialAnchor.CredentialState state1,,, bool active1) = anchorContract.status(CRED_HASH_1);
        assertEq(uint8(state1), uint8(CredentialAnchor.CredentialState.Valid));
        assertTrue(active1);

        // Suspend issuer: credential state remains Valid, but issuerActive becomes false
        registry.suspendIssuer(issuerA);
        (CredentialAnchor.CredentialState state2,,, bool active2) = anchorContract.status(CRED_HASH_1);
        assertEq(uint8(state2), uint8(CredentialAnchor.CredentialState.Valid));
        assertFalse(active2);

        // Reinstate issuer: issuerActive returns to true
        registry.reinstateIssuer(issuerA);
        (CredentialAnchor.CredentialState state3,,, bool active3) = anchorContract.status(CRED_HASH_1);
        assertEq(uint8(state3), uint8(CredentialAnchor.CredentialState.Valid));
        assertTrue(active3);
    }

    // =========================================================================
    // Revocation & Suspended Issuer Rights
    // =========================================================================

    function test_OriginalIssuerCanRevoke_EmitsEvent() public {
        vm.prank(issuerA);
        anchorContract.anchor(CRED_HASH_1, 0);

        vm.prank(issuerA);
        vm.expectEmit(true, true, false, true);
        emit CredentialRevoked(CRED_HASH_1, issuerA);

        anchorContract.revoke(CRED_HASH_1);

        (CredentialAnchor.CredentialState state,,,) = anchorContract.status(CRED_HASH_1);
        assertEq(uint8(state), uint8(CredentialAnchor.CredentialState.Revoked));
    }

    function test_SuspendedIssuerCanStillRevokeOwnCredentials() public {
        vm.prank(issuerA);
        anchorContract.anchor(CRED_HASH_1, 0);

        // Suspend Issuer A
        registry.suspendIssuer(issuerA);

        // Suspended Issuer A can still revoke their own credential
        vm.prank(issuerA);
        vm.expectEmit(true, true, false, true);
        emit CredentialRevoked(CRED_HASH_1, issuerA);

        anchorContract.revoke(CRED_HASH_1);

        (CredentialAnchor.CredentialState state,, bytes32 fp, bool issuerActive) = anchorContract.status(CRED_HASH_1);
        assertEq(uint8(state), uint8(CredentialAnchor.CredentialState.Revoked));
        assertEq(fp, FINGERPRINT_A);
        assertFalse(issuerActive);
    }

    function test_RevertWhen_NonOriginalIssuerRevokes() public {
        vm.prank(issuerA);
        anchorContract.anchor(CRED_HASH_1, 0);

        vm.prank(issuerB);
        vm.expectRevert(abi.encodeWithSelector(CredentialAnchor.NotOriginalIssuer.selector, CRED_HASH_1, issuerB, issuerA));
        anchorContract.revoke(CRED_HASH_1);
    }

    function test_RevertWhen_RevokingAlreadyRevoked() public {
        vm.prank(issuerA);
        anchorContract.anchor(CRED_HASH_1, 0);

        vm.prank(issuerA);
        anchorContract.revoke(CRED_HASH_1);

        vm.prank(issuerA);
        vm.expectRevert(abi.encodeWithSelector(CredentialAnchor.AlreadyRevoked.selector, CRED_HASH_1));
        anchorContract.revoke(CRED_HASH_1);
    }

    function test_RevertWhen_RevokingNonExistentCredential() public {
        vm.prank(issuerA);
        vm.expectRevert(abi.encodeWithSelector(CredentialAnchor.CredentialNotFound.selector, CRED_HASH_1));
        anchorContract.revoke(CRED_HASH_1);
    }

    // =========================================================================
    // Expiry & Exact-Second Boundary
    // =========================================================================

    function test_ExactSecondOfExpiryCountsAsExpired() public {
        uint64 expiry = uint64(block.timestamp + 100);

        vm.prank(issuerA);
        anchorContract.anchor(CRED_HASH_1, expiry);

        // 1 second before expiry: Valid
        vm.warp(expiry - 1);
        (CredentialAnchor.CredentialState stateBefore,,,) = anchorContract.status(CRED_HASH_1);
        assertEq(uint8(stateBefore), uint8(CredentialAnchor.CredentialState.Valid));

        // Exact second of expiry (block.timestamp == expiry): EXPIRED
        vm.warp(expiry);
        (CredentialAnchor.CredentialState stateExact,,,) = anchorContract.status(CRED_HASH_1);
        assertEq(uint8(stateExact), uint8(CredentialAnchor.CredentialState.Expired));

        // After expiry: EXPIRED
        vm.warp(expiry + 1);
        (CredentialAnchor.CredentialState stateAfter,,,) = anchorContract.status(CRED_HASH_1);
        assertEq(uint8(stateAfter), uint8(CredentialAnchor.CredentialState.Expired));
    }

    function test_CredentialBothRevokedAndExpiredReportsRevoked() public {
        uint64 expiry = uint64(block.timestamp + 50);

        vm.prank(issuerA);
        anchorContract.anchor(CRED_HASH_1, expiry);

        // Revoke before expiry
        vm.prank(issuerA);
        anchorContract.revoke(CRED_HASH_1);

        // Warp time past expiry
        vm.warp(expiry + 100);

        // Both revoked and expired: reports Revoked
        (CredentialAnchor.CredentialState state,,,) = anchorContract.status(CRED_HASH_1);
        assertEq(uint8(state), uint8(CredentialAnchor.CredentialState.Revoked));
    }

    function test_RevokingAfterExpiryWorks_AndReportsRevoked() public {
        uint64 expiry = uint64(block.timestamp + 50);

        vm.prank(issuerA);
        anchorContract.anchor(CRED_HASH_1, expiry);

        // Warp time past expiry so credential expires
        vm.warp(expiry + 100);

        // Prior to revoking, it reports Expired
        (CredentialAnchor.CredentialState stateBefore,,,) = anchorContract.status(CRED_HASH_1);
        assertEq(uint8(stateBefore), uint8(CredentialAnchor.CredentialState.Expired));

        // Revoking an already-expired credential succeeds and emits CredentialRevoked
        vm.prank(issuerA);
        vm.expectEmit(true, true, false, true);
        emit CredentialRevoked(CRED_HASH_1, issuerA);
        anchorContract.revoke(CRED_HASH_1);

        // Status now reports Revoked
        (CredentialAnchor.CredentialState stateAfter,,,) = anchorContract.status(CRED_HASH_1);
        assertEq(uint8(stateAfter), uint8(CredentialAnchor.CredentialState.Revoked));
    }

    // =========================================================================
    // Status Query for Unknown Credential
    // =========================================================================

    function test_StatusReturnsUnknownForNonExistentHash() public view {
        (
            CredentialAnchor.CredentialState state,
            address issuer,
            bytes32 fp,
            bool active
        ) = anchorContract.status(CRED_HASH_2);

        assertEq(uint8(state), uint8(CredentialAnchor.CredentialState.Unknown));
        assertEq(issuer, address(0));
        assertEq(fp, bytes32(0));
        assertFalse(active);
    }

    // =========================================================================
    // Property-Based Fuzz Testing
    // =========================================================================

    function testFuzz_AnchorValidHashAndExpiry(bytes32 hash, uint32 expiryOffset) public {
        vm.assume(hash != bytes32(0));
        vm.assume(expiryOffset > 0);

        uint64 expiry = uint64(block.timestamp) + uint64(expiryOffset);

        vm.prank(issuerA);
        anchorContract.anchor(hash, expiry);

        (CredentialAnchor.CredentialState state, address issuer, bytes32 fp, bool active) = anchorContract.status(hash);
        assertEq(uint8(state), uint8(CredentialAnchor.CredentialState.Valid));
        assertEq(issuer, issuerA);
        assertEq(fp, FINGERPRINT_A);
        assertTrue(active);
    }

    function testFuzz_DuplicateAnchorRejected(bytes32 hash) public {
        vm.assume(hash != bytes32(0));

        vm.prank(issuerA);
        anchorContract.anchor(hash, 0);

        vm.prank(issuerA);
        vm.expectRevert(abi.encodeWithSelector(CredentialAnchor.DuplicateCredentialHash.selector, hash));
        anchorContract.anchor(hash, 0);
    }

    function testFuzz_OnlyOriginalIssuerCanRevoke(address attacker, bytes32 hash) public {
        vm.assume(hash != bytes32(0));
        vm.assume(attacker != issuerA);

        vm.prank(issuerA);
        anchorContract.anchor(hash, 0);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSelector(CredentialAnchor.NotOriginalIssuer.selector, hash, attacker, issuerA));
        anchorContract.revoke(hash);
    }
}
