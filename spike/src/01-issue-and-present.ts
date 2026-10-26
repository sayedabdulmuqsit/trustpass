/**
 * Script 01 — Issue a credential and selectively present it.
 *
 * Claims: name, studentId, degree, grade, institution, issueDate
 * Present: ONLY degree + institution
 * Verify: the presentation
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
  header('01 — Issue & Selective Present');

  // ── Issuer setup ──
  const issuer = await createES256KeyBundle();

  const sdjwt = new SDJwtVcInstance({
    signer: issuer.signer,
    signAlg: 'ES256',
    verifier: issuer.verifier,
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
  });

  // ── Claims ──
  const claims = {
    name: 'Alice Johnson',
    studentId: 'STU-2025-0042',
    degree: 'BSc Computer Science',
    grade: 'First Class Honours',
    institution: 'University of TrustPass',
    issueDate: '2025-06-15',
  };

  // All personal claims are selectively disclosable
  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['name', 'studentId', 'degree', 'grade', 'institution', 'issueDate'],
  };

  subheader('Issuing credential');
  const credential = await sdjwt.issue(
    {
      iss: 'https://university.trustpass.example',
      vct: 'UniversityDegreeCredential',
      iat: Math.floor(Date.now() / 1000),
      ...claims,
    },
    disclosureFrame,
  );
  console.log('Credential (truncated):', credential.slice(0, 120) + '…');
  console.log('Total length:', credential.length);

  // Count tilde-separated parts: <issuer-JWT>~<disclosure1>~...~<disclosureN>~
  const parts = credential.split('~');
  console.log(
    `Parts: 1 issuer JWT + ${parts.length - 2} disclosures (expect 6)`,
  );

  // ── Present only degree + institution ──
  subheader('Presenting (degree + institution only)');
  const presentationFrame = {
    degree: true,
    institution: true,
  };

  const presentation = await sdjwt.present(credential, presentationFrame);
  console.log('Presentation (truncated):', presentation.slice(0, 120) + '…');

  const presentedParts = presentation.split('~');
  console.log(
    `Parts: 1 issuer JWT + ${presentedParts.length - 2} disclosures (expect 2)`,
  );

  // ── Verify ──
  subheader('Verifying presentation');
  const result = await sdjwt.verify(presentation);
  console.log('✅ Verification succeeded');
  console.log('Disclosed claims:', JSON.stringify(result, null, 2));
}

main().catch((err) => {
  console.error('❌ Script 01 failed:', err);
  process.exit(1);
});
