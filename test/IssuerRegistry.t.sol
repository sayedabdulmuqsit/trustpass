// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import { Test } from "forge-std/src/Test.sol";
import { IssuerRegistry } from "../contracts/IssuerRegistry.sol";

contract IssuerRegistryTest is Test {
    IssuerRegistry public registry;

    address public owner;
    address public issuerWallet;
    address public unauthorizedUser;
    address public newOwnerCandidate;

    bytes32 public constant FINGERPRINT_A = bytes32(uint256(0x1111));
    bytes32 public constant FINGERPRINT_B = bytes32(uint256(0x2222));
    string public constant ISSUER_NAME = "University of TrustPass";

    // Events mirrored for vm.expectEmit checks
    event IssuerAdded(address indexed wallet, string name, bytes32 keyFingerprint);
    event IssuerSuspended(address indexed wallet);
    event IssuerReinstated(address indexed wallet);
    event KeyFingerprintRotated(address indexed wallet, bytes32 oldKeyFingerprint, bytes32 newKeyFingerprint);
    event OwnershipTransferStarted(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event OwnershipTransferCancelled(address indexed owner, address indexed pendingOwner);

    function setUp() public {
        owner = address(this);
        issuerWallet = makeAddr("issuerWallet");
        unauthorizedUser = makeAddr("unauthorizedUser");
        newOwnerCandidate = makeAddr("newOwnerCandidate");

        registry = new IssuerRegistry();
    }

    // =========================================================================
    // Initial State & Constructor
    // =========================================================================

    function test_InitialOwnerIsDeployer() public view {
        assertEq(registry.owner(), owner);
        assertEq(registry.pendingOwner(), address(0));
    }

    // =========================================================================
    // Unknown Issuer Queries
    // =========================================================================

    function test_UnknownIssuer_IsActive_ReturnsFalse() public view {
        assertFalse(registry.isActive(unauthorizedUser));
    }

    function test_UnknownIssuer_GetIssuer_Reverts() public {
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.IssuerNotFound.selector, unauthorizedUser));
        registry.getIssuer(unauthorizedUser);
    }

    function test_UnknownIssuer_GetIssuerFingerprint_Reverts() public {
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.IssuerNotFound.selector, unauthorizedUser));
        registry.getIssuerFingerprint(unauthorizedUser);
    }

    // =========================================================================
    // Issuer Addition & Access Control
    // =========================================================================

    function test_OwnerCanAddIssuer_EmitsEvent() public {
        vm.expectEmit(true, false, false, true);
        emit IssuerAdded(issuerWallet, ISSUER_NAME, FINGERPRINT_A);

        registry.addIssuer(issuerWallet, ISSUER_NAME, FINGERPRINT_A);

        assertTrue(registry.isActive(issuerWallet));
        assertEq(registry.getIssuerFingerprint(issuerWallet), FINGERPRINT_A);

        (string memory name, bytes32 fp, bool active) = registry.getIssuer(issuerWallet);
        assertEq(name, ISSUER_NAME);
        assertEq(fp, FINGERPRINT_A);
        assertTrue(active);
    }

    function test_RevertWhen_NonOwnerAddsIssuer() public {
        vm.prank(unauthorizedUser);
        vm.expectRevert(IssuerRegistry.Unauthorized.selector);
        registry.addIssuer(issuerWallet, ISSUER_NAME, FINGERPRINT_A);
    }

    function test_RevertWhen_AddDuplicateIssuer() public {
        registry.addIssuer(issuerWallet, ISSUER_NAME, FINGERPRINT_A);

        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.IssuerAlreadyExists.selector, issuerWallet));
        registry.addIssuer(issuerWallet, "Another Name", FINGERPRINT_B);
    }

    function test_RevertWhen_AddIssuerWithZeroAddress() public {
        vm.expectRevert(IssuerRegistry.ZeroAddress.selector);
        registry.addIssuer(address(0), ISSUER_NAME, FINGERPRINT_A);
    }

    function test_RevertWhen_AddIssuerWithEmptyName() public {
        vm.expectRevert(IssuerRegistry.EmptyName.selector);
        registry.addIssuer(issuerWallet, "", FINGERPRINT_A);
    }

    function test_RevertWhen_AddIssuerWithZeroFingerprint() public {
        vm.expectRevert(IssuerRegistry.ZeroKeyFingerprint.selector);
        registry.addIssuer(issuerWallet, ISSUER_NAME, bytes32(0));
    }

    // =========================================================================
    // Suspension & Reinstatement
    // =========================================================================

    function test_OwnerCanSuspendAndReinstateIssuer_EmitsEvents() public {
        registry.addIssuer(issuerWallet, ISSUER_NAME, FINGERPRINT_A);

        // Suspend
        vm.expectEmit(true, false, false, true);
        emit IssuerSuspended(issuerWallet);
        registry.suspendIssuer(issuerWallet);

        assertFalse(registry.isActive(issuerWallet));

        // Re-instate
        vm.expectEmit(true, false, false, true);
        emit IssuerReinstated(issuerWallet);
        registry.reinstateIssuer(issuerWallet);

        assertTrue(registry.isActive(issuerWallet));
    }

    function test_RevertWhen_NonOwnerSuspendsIssuer() public {
        registry.addIssuer(issuerWallet, ISSUER_NAME, FINGERPRINT_A);

        vm.prank(unauthorizedUser);
        vm.expectRevert(IssuerRegistry.Unauthorized.selector);
        registry.suspendIssuer(issuerWallet);
    }

    function test_RevertWhen_NonOwnerReinstatesIssuer() public {
        registry.addIssuer(issuerWallet, ISSUER_NAME, FINGERPRINT_A);
        registry.suspendIssuer(issuerWallet);

        vm.prank(unauthorizedUser);
        vm.expectRevert(IssuerRegistry.Unauthorized.selector);
        registry.reinstateIssuer(issuerWallet);
    }

    function test_RevertWhen_SuspendNonExistentIssuer() public {
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.IssuerNotFound.selector, issuerWallet));
        registry.suspendIssuer(issuerWallet);
    }

    function test_RevertWhen_SuspendAlreadySuspended() public {
        registry.addIssuer(issuerWallet, ISSUER_NAME, FINGERPRINT_A);
        registry.suspendIssuer(issuerWallet);

        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.IssuerAlreadySuspended.selector, issuerWallet));
        registry.suspendIssuer(issuerWallet);
    }

    function test_RevertWhen_ReinstateAlreadyActive() public {
        registry.addIssuer(issuerWallet, ISSUER_NAME, FINGERPRINT_A);

        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.IssuerAlreadyActive.selector, issuerWallet));
        registry.reinstateIssuer(issuerWallet);
    }

    // =========================================================================
    // Key Rotation
    // =========================================================================

    function test_IssuerCanRotateKeyFingerprint_EmitsEvent() public {
        registry.addIssuer(issuerWallet, ISSUER_NAME, FINGERPRINT_A);

        vm.prank(issuerWallet);
        vm.expectEmit(true, false, false, true);
        emit KeyFingerprintRotated(issuerWallet, FINGERPRINT_A, FINGERPRINT_B);

        registry.rotateKeyFingerprint(FINGERPRINT_B);

        assertEq(registry.getIssuerFingerprint(issuerWallet), FINGERPRINT_B);
    }

    function test_RevertWhen_SuspendedIssuerRotatesKeyFingerprint() public {
        registry.addIssuer(issuerWallet, ISSUER_NAME, FINGERPRINT_A);
        registry.suspendIssuer(issuerWallet);

        vm.prank(issuerWallet);
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.IssuerNotActive.selector, issuerWallet));
        registry.rotateKeyFingerprint(FINGERPRINT_B);
    }

    function test_RevertWhen_NonIssuerRotatesKeyFingerprint() public {
        vm.prank(unauthorizedUser);
        vm.expectRevert(abi.encodeWithSelector(IssuerRegistry.IssuerNotFound.selector, unauthorizedUser));
        registry.rotateKeyFingerprint(FINGERPRINT_B);
    }

    function test_RevertWhen_RotateToZeroFingerprint() public {
        registry.addIssuer(issuerWallet, ISSUER_NAME, FINGERPRINT_A);

        vm.prank(issuerWallet);
        vm.expectRevert(IssuerRegistry.ZeroKeyFingerprint.selector);
        registry.rotateKeyFingerprint(bytes32(0));
    }

    function test_RevertWhen_RotateToIdenticalFingerprint() public {
        registry.addIssuer(issuerWallet, ISSUER_NAME, FINGERPRINT_A);

        vm.prank(issuerWallet);
        vm.expectRevert(IssuerRegistry.IdenticalKeyFingerprint.selector);
        registry.rotateKeyFingerprint(FINGERPRINT_A);
    }

    // =========================================================================
    // Two-Step Ownership
    // =========================================================================

    function test_TwoStepOwnershipTransfer_FullCycle() public {
        // Step 1: Propose new owner
        vm.expectEmit(true, true, false, true);
        emit OwnershipTransferStarted(owner, newOwnerCandidate);
        registry.transferOwnership(newOwnerCandidate);

        assertEq(registry.owner(), owner);
        assertEq(registry.pendingOwner(), newOwnerCandidate);

        // Step 2: Accept ownership
        vm.prank(newOwnerCandidate);
        vm.expectEmit(true, true, false, true);
        emit OwnershipTransferred(owner, newOwnerCandidate);
        registry.acceptOwnership();

        assertEq(registry.owner(), newOwnerCandidate);
        assertEq(registry.pendingOwner(), address(0));
    }

    function test_RevertWhen_NonPendingOwnerAcceptsOwnership() public {
        registry.transferOwnership(newOwnerCandidate);

        vm.prank(unauthorizedUser);
        vm.expectRevert(IssuerRegistry.NotPendingOwner.selector);
        registry.acceptOwnership();
    }

    function test_OwnerCanCancelOwnershipTransfer() public {
        registry.transferOwnership(newOwnerCandidate);

        vm.expectEmit(true, true, false, true);
        emit OwnershipTransferCancelled(owner, newOwnerCandidate);
        registry.cancelOwnershipTransfer();

        assertEq(registry.pendingOwner(), address(0));
        assertEq(registry.owner(), owner);
    }

    function test_RevertWhen_TransferOwnershipToZeroAddress() public {
        vm.expectRevert(IssuerRegistry.ZeroAddress.selector);
        registry.transferOwnership(address(0));
    }

    function test_RevertWhen_TransferOwnershipToCurrentOwner() public {
        vm.expectRevert(IssuerRegistry.Unauthorized.selector);
        registry.transferOwnership(owner);
    }

    // =========================================================================
    // Property-Based Fuzz Testing
    // =========================================================================

    function testFuzz_AddIssuer(address wallet, string calldata name, bytes32 fingerprint) public {
        vm.assume(wallet != address(0));
        vm.assume(bytes(name).length > 0 && bytes(name).length < 256);
        vm.assume(fingerprint != bytes32(0));

        registry.addIssuer(wallet, name, fingerprint);

        assertTrue(registry.isActive(wallet));
        assertEq(registry.getIssuerFingerprint(wallet), fingerprint);
    }

    function testFuzz_RotateKeyFingerprint(bytes32 newFingerprint) public {
        vm.assume(newFingerprint != bytes32(0));
        vm.assume(newFingerprint != FINGERPRINT_A);

        registry.addIssuer(issuerWallet, ISSUER_NAME, FINGERPRINT_A);

        vm.prank(issuerWallet);
        registry.rotateKeyFingerprint(newFingerprint);

        assertEq(registry.getIssuerFingerprint(issuerWallet), newFingerprint);
    }

    function testFuzz_TwoStepOwnership(address newOwner) public {
        vm.assume(newOwner != address(0));
        vm.assume(newOwner != owner);

        registry.transferOwnership(newOwner);
        assertEq(registry.pendingOwner(), newOwner);

        vm.prank(newOwner);
        registry.acceptOwnership();

        assertEq(registry.owner(), newOwner);
    }
}
