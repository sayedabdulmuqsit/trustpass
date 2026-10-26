# TrustPass Deployments & Contract ABIs

This directory documents deployment artifacts, local simulated addresses, and ABI locations for frontend integration (Vite + React + TypeScript + Viem).

---

## 1. Local Simulated Network Addresses (In-Process Hardhat Ignition)

When deploying locally via Hardhat Ignition (`npx hardhat ignition deploy ignition/modules/TrustPass.ts`), the deterministic addresses are:

| Contract | Address | Notes |
|---|---|---|
| `IssuerRegistry` | `0x5FbDB2315678afecb367f032d93F642f64180aa3` | Manages issuers and key fingerprints |
| `CredentialAnchor` | `0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512` | Anchors SD-JWT hashes; `registry()` points to `0x5FbDB23...` |

---

## 2. ABI Locations

Hardhat 3 compiles contracts and writes JSON artifacts containing the contract `abi`, `bytecode`, and metadata to:

### `IssuerRegistry`
- **Artifact Path**: `artifacts/contracts/IssuerRegistry.sol/IssuerRegistry.json`
- **TypeScript Declarations**: `artifacts/contracts/IssuerRegistry.sol/artifacts.d.ts`
- **Core Methods**:
  - `addIssuer(address wallet, string name, bytes32 keyFingerprint)`
  - `suspendIssuer(address wallet)`
  - `reinstateIssuer(address wallet)`
  - `rotateKeyFingerprint(bytes32 newKeyFingerprint)`
  - `transferOwnership(address newOwner)`
  - `acceptOwnership()`
  - `cancelOwnershipTransfer()`
  - `isActive(address wallet) -> (bool)`
  - `getIssuerFingerprint(address wallet) -> (bytes32)`
  - `getIssuer(address wallet) -> (string name, bytes32 keyFingerprint, bool active)`

### `CredentialAnchor`
- **Artifact Path**: `artifacts/contracts/CredentialAnchor.sol/CredentialAnchor.json`
- **TypeScript Declarations**: `artifacts/contracts/CredentialAnchor.sol/artifacts.d.ts`
- **Core Methods**:
  - `anchor(bytes32 hash, uint64 expiry)`
  - `revoke(bytes32 hash)`
  - `status(bytes32 hash) -> (uint8 state, address issuer, bytes32 fingerprint, bool issuerActive)`
  - `registry() -> (address)`
  - `getAnchor(bytes32 hash) -> (AnchorRecord)`

### `IIssuerRegistry` (Interface)
- **Artifact Path**: `artifacts/contracts/interfaces/IIssuerRegistry.sol/IIssuerRegistry.json`

---

## 3. Frontend Integration Examples (Vite + Viem / Wagmi)

### Importing JSON ABIs directly in Vite / TypeScript:

```typescript
import IssuerRegistryArtifact from '../artifacts/contracts/IssuerRegistry.sol/IssuerRegistry.json';
import CredentialAnchorArtifact from '../artifacts/contracts/CredentialAnchor.sol/CredentialAnchor.json';

export const ISSUER_REGISTRY_ABI = IssuerRegistryArtifact.abi;
export const CREDENTIAL_ANCHOR_ABI = CredentialAnchorArtifact.abi;
```

### Initializing Contracts with Viem:

```typescript
import { createPublicClient, http, getContract } from 'viem';
import { sepolia, hardhat } from 'viem/chains';
import { CREDENTIAL_ANCHOR_ABI, ISSUER_REGISTRY_ABI } from './abis';

export const publicClient = createPublicClient({
  chain: hardhat, // or sepolia for testnet
  transport: http(),
});

export const credentialAnchorContract = getContract({
  address: '0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512',
  abi: CREDENTIAL_ANCHOR_ABI,
  client: publicClient,
});
```
