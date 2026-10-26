/**
 * Script 04 — On-chain hash design.
 *
 * After issuing a credential, compute the SHA-256 hash of the issuer-signed JWT
 * (the base JWT without disclosures). Explain why this leaks no personal data.
 */

import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import type { DisclosureFrame } from '@sd-jwt/core';
import {
  createES256KeyBundle,
  digest,
  generateSalt,
  header,
  subheader,
} from './utils/crypto.js';
import { sha256 } from '@noble/hashes/sha256';

async function main() {
  header('04 — On-Chain Hash Design');

  const issuer = await createES256KeyBundle();

  const sdjwt = new SDJwtVcInstance({
    signer: issuer.signer,
    signAlg: 'ES256',
    verifier: issuer.verifier,
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
  });

  const claims = {
    name: 'Alice Johnson',
    studentId: 'STU-2025-0042',
    degree: 'BSc Computer Science',
    grade: 'First Class Honours',
    institution: 'University of TrustPass',
    issueDate: '2025-06-15',
  };

  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['name', 'studentId', 'degree', 'grade', 'institution', 'issueDate'],
  };

  const credential = await sdjwt.issue(
    {
      iss: 'https://university.trustpass.example',
      vct: 'UniversityDegreeCredential',
      iat: Math.floor(Date.now() / 1000),
      ...claims,
    },
    disclosureFrame,
  );

  // ── Extract the issuer-signed JWT (everything before the first ~) ──
  subheader('Extracting issuer-signed JWT');

  const parts = credential.split('~');
  const issuerJwt = parts[0]!;
  console.log('Issuer JWT (truncated):', issuerJwt.slice(0, 80) + '…');

  // ── Decode and inspect the JWT payload ──
  subheader('Decoded JWT payload (what goes on-chain as _sd digests)');

  const [, payloadB64] = issuerJwt.split('.');
  const payloadJson = Buffer.from(payloadB64!, 'base64url').toString('utf-8');
  const payload = JSON.parse(payloadJson);
  console.log(JSON.stringify(payload, null, 2));

  // ── Compute SHA-256 hash of the issuer JWT ──
  subheader('On-chain hash');

  const encoder = new TextEncoder();
  const hashBytes = sha256(encoder.encode(issuerJwt));
  const hashHex = '0x' + Buffer.from(hashBytes).toString('hex');

  console.log('SHA-256 of issuer JWT:', hashHex);
  console.log('Length:', hashHex.length, 'chars (32 bytes = bytes32 in Solidity)');

  // ── Privacy analysis ──
  subheader('Privacy Analysis — Why this hash leaks no personal data');

  console.log(`
1. WHAT THE JWT PAYLOAD CONTAINS:
   • iss, vct, iat — public metadata (issuer URL, credential type, timestamp)
   • _sd_alg: "sha-256" — the hashing algorithm identifier
   • _sd: [...] — an array of BASE64URL-encoded SHA-256 digests

2. WHAT EACH _sd DIGEST IS:
   Each digest = SHA-256( BASE64URL( JSON.stringify([salt, claimName, claimValue]) ) )
   The salt is a cryptographically random value (≥ 128 bits).
   
   Even if an attacker knows the claim name and guesses the value,
   they cannot verify their guess without knowing the salt.
   This is equivalent to a salted password hash.

3. WHAT THE ON-CHAIN HASH IS:
   SHA-256( entire issuer-signed JWT including header + payload + signature )
   
   This is a hash OF a hash-containing document. An attacker would need to:
   a) Reconstruct the exact JWT (header + payload + signature)
   b) Which requires knowing all the _sd digests (which require the salts)
   c) AND the issuer's private key (to produce the signature)
   
   → Computationally infeasible. Zero personal data is recoverable.

4. ON-CHAIN USAGE:
   • Store: credentialHash → { issuer address, timestamp, revoked }
   • Verify: SHA-256(presented issuer JWT) == stored hash → credential is authentic
   • Revoke: issuer sets revoked = true → credential is invalidated
   • NO personal data touches the blockchain at any point.
`);

  // ── Show that two different issuances produce different hashes ──
  subheader('Uniqueness check');

  const credential2 = await sdjwt.issue(
    {
      iss: 'https://university.trustpass.example',
      vct: 'UniversityDegreeCredential',
      iat: Math.floor(Date.now() / 1000),
      ...claims, // same claims!
    },
    disclosureFrame,
  );

  const issuerJwt2 = credential2.split('~')[0]!;
  const hashBytes2 = sha256(encoder.encode(issuerJwt2));
  const hashHex2 = '0x' + Buffer.from(hashBytes2).toString('hex');

  console.log('Hash 1:', hashHex);
  console.log('Hash 2:', hashHex2);
  console.log(
    'Same claims, different hashes:',
    hashHex !== hashHex2 ? '✅ Yes (different salts → different _sd → different JWT)' : '❌ No',
  );
}

main().catch((err) => {
  console.error('❌ Script 04 failed:', err);
  process.exit(1);
});
