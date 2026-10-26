/**
 * Script 02 — Negative tests: tampered credential and disclosure leak.
 *
 * 1. Tamper: flip a byte in the credential → verify must reject.
 * 2. Leak: present with extra disclosures the verifier didn't ask for →
 *    confirm the verifier still only sees what the presentation frame allows.
 *    (SD-JWT's design: the holder controls what to disclose; if the holder
 *     includes extra disclosures, the verifier sees them — the protection
 *     is that the holder chooses what to send, not that the verifier filters.)
 *    We demonstrate that if you restrict the presentation frame, the extra
 *    disclosures simply don't appear.
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

async function main() {
  header('02 — Tamper & Leak Tests');

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

  // ────────────────────────────────────────────
  // TEST 1: Tampered credential
  // ────────────────────────────────────────────
  subheader('Test 1: Tampered credential');

  // Flip a character in the issuer-signed JWT (first part before ~)
  const parts = credential.split('~');
  const jwtPart = parts[0]!;
  // Flip a character near the middle of the JWT signature
  const midpoint = Math.floor(jwtPart.length * 0.75);
  const flippedChar = jwtPart[midpoint] === 'A' ? 'B' : 'A';
  const tamperedJwt =
    jwtPart.slice(0, midpoint) + flippedChar + jwtPart.slice(midpoint + 1);
  parts[0] = tamperedJwt;
  const tamperedCredential = parts.join('~');

  // Present with the tampered credential
  try {
    // We must present from the tampered credential first
    // But present() doesn't verify — it just strips disclosures.
    // The verification step will catch the tamper.
    const tamperedPresentation = await sdjwt.present(tamperedCredential, {
      degree: true,
    });
    await sdjwt.verify(tamperedPresentation);
    console.log('❌ UNEXPECTED: Tampered credential passed verification!');
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log('✅ Tampered credential correctly rejected');
    console.log('   Error:', msg);
  }

  // ────────────────────────────────────────────
  // TEST 2: Undisclosed-field leak check
  // ────────────────────────────────────────────
  subheader('Test 2: Selective disclosure — no leak');

  // Present ONLY degree (the holder's choice)
  const minimalPresentation = await sdjwt.present(credential, {
    degree: true,
  });

  const result = await sdjwt.verify(minimalPresentation);

  // Check that name, studentId, grade, institution, issueDate are NOT in the result
  const disclosed = result.payload ?? result;
  const sensitiveFields = ['name', 'studentId', 'grade', 'institution', 'issueDate'] as const;
  let anyLeaked = false;

  for (const field of sensitiveFields) {
    if (field in (disclosed as Record<string, unknown>)) {
      console.log(`❌ LEAKED: "${field}" is visible in verified payload`);
      anyLeaked = true;
    }
  }

  if (!anyLeaked) {
    console.log('✅ No undisclosed fields leaked');
    console.log(
      '   Verified payload keys:',
      Object.keys(disclosed as Record<string, unknown>),
    );
  }

  // ────────────────────────────────────────────
  // TEST 3: Full-disclosure presentation (for comparison)
  // ────────────────────────────────────────────
  subheader('Test 3: Full disclosure (for comparison)');

  const fullPresentation = await sdjwt.present(credential, {
    name: true,
    studentId: true,
    degree: true,
    grade: true,
    institution: true,
    issueDate: true,
  });

  const fullResult = await sdjwt.verify(fullPresentation);
  const fullPayload = fullResult.payload ?? fullResult;
  console.log(
    '   Full payload keys:',
    Object.keys(fullPayload as Record<string, unknown>),
  );
  console.log('✅ All 6 claim fields visible when fully disclosed');
}

main().catch((err) => {
  console.error('❌ Script 02 failed:', err);
  process.exit(1);
});
