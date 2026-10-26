import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";

const TrustPassModule = buildModule("TrustPassModule", (m) => {
  // 1. Deploy the IssuerRegistry contract
  const issuerRegistry = m.contract("IssuerRegistry");

  // 2. Deploy the CredentialAnchor contract linked to the IssuerRegistry
  const credentialAnchor = m.contract("CredentialAnchor", [issuerRegistry]);

  return { issuerRegistry, credentialAnchor };
});

export default TrustPassModule;
