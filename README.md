# TrustPass: On-Chain Credential Layer

Privacy-first, multi-issuer credential network deployed on Ethereum Sepolia.
Built with **Hardhat 3**, **Solidity**, **Hardhat Ignition**, and native **Solidity Unit & Fuzz Tests** powered by `forge-std`.

---

## 1. Smart Contract Architecture

### `IssuerRegistry.sol`
- **Two-Step Ownership**: Secure administrative control using `transferOwnership(address)` and `acceptOwnership()`.
- **Issuer Lifecycle**: Owner registers issuers with institutional names and their public key's **RFC 7638 ES256 JWK thumbprint** (`bytes32`).
- **Suspension / Reinstatement**: Owner can suspend or reinstate issuers dynamically.
- **Self-Service Key Rotation**: Active issuers can rotate their key fingerprint at any time via `rotateKeyFingerprint(bytes32)`.
- **Gas-Optimized Querying**: Includes `getIssuerFingerprint(address)` to avoid expensive string memory copying during cross-contract calls.

### `CredentialAnchor.sol`
- **Zero Personal Data On-Chain**: Anchors only cryptographic commitment hashes (SHA-256 of the issuer-signed SD-JWT VC) with block timestamps, optional expiry, and immutable snapshots of the issuer's key fingerprint.
- **Duplicate Protection**: Prevents duplicate anchoring of the same credential hash.
- **Revocation Invariant**: Only the original issuer can revoke their credentials. Suspended issuers retain the security right to revoke their previously issued credentials.
- **Status Evaluation**: `status(bytes32 hash)` returns:
  - `state`: `Unknown`, `Valid`, `Revoked`, or `Expired` (exact second of expiry `block.timestamp == expiry` counts as `Expired`).
  - `issuer`: Issuing wallet address.
  - `fingerprint`: Immutable snapshot of the issuer's key fingerprint captured at anchor time.
  - `issuerActive`: Current real-time activity status from `IssuerRegistry`.

---

## 2. Running the Solidity Test Suite

The test suite runs natively in Solidity on Hardhat 3's Rust-powered EVM runtime:

```bash
# Run all unit and property-based fuzz tests
npm test
# or
npx hardhat test
```

### Test Coverage Highlights:
- **Access Control**: Administrative rights, unauthorized caller rejection on all mutations.
- **Two-Step Ownership**: Full lifecycle, pending owner validation, and cancellation.
- **Suspension & Reinstatement**: Reinstated issuers can anchor again; suspended issuers cannot anchor.
- **Revocation Rights**: Suspended issuers can still revoke their own credentials; non-issuers cannot revoke.
- **Fingerprint Snapshot Invariance**: Rotating an issuer's key fingerprint leaves past anchored credential fingerprint snapshots unchanged.
- **Expiry Boundary**: Verification that `block.timestamp == expiry` counts as `Expired`.
- **Duplicate Hash Rejection**: Reverts if the same credential commitment is anchored more than once.
- **Event Integrity**: `vm.expectEmit` verification for every state-changing event.
- **Property-Based Fuzzing**: 256 randomized runs each for parameter validation, duplicate rejection, and ownership transfers.

---

## 3. Sepolia Deployment via Hardhat Keystore & Ignition

Per project security rules, **no private keys or secrets are stored in any code or plaintext `.env` files**. Credentials are encrypted locally using Hardhat's keystore plugin and injected dynamically via `configVariable`.

### Step 1: Set Keystore Secrets

Set your Sepolia RPC URL and private key in the encrypted local vault:

```bash
# Set Sepolia RPC Endpoint (e.g. Alchemy or Infura)
npx hardhat keystore set SEPOLIA_RPC_URL

# Set Deployer Private Key (without exposing it in plaintext)
npx hardhat keystore set SEPOLIA_PRIVATE_KEY
```

*(You will be prompted to create or enter a master password for your local keystore vault).*

### Step 2: Deploy Contracts with Hardhat Ignition

Run the declarative Ignition deployment module:

```bash
npx hardhat ignition deploy ignition/modules/TrustPass.ts --network sepolia
```

This deploys:
1. `IssuerRegistry`
2. `CredentialAnchor` (linked to `IssuerRegistry`)
