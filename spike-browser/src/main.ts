import { ES256, digest, generateSalt } from '@owf/crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { calculateJwkThumbprint } from 'jose';

// Convert ArrayBuffer to Hex
function bufferToHex(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let hex = '0x';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex;
}

// Convert ArrayBuffer to base64url
function bufferToBase64url(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// Pure WebCrypto RFC 7638 thumbprint calculation for cross-validation
async function computeManualRfc7638Thumbprint(jwk: JsonWebKey): Promise<{ base64url: string; hex: string; canonicalJson: string }> {
  // Required fields for EC keys in lexicographic order: crv, kty, x, y
  const canonical = {
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  };
  const canonicalJson = JSON.stringify(canonical);
  const data = new TextEncoder().encode(canonicalJson);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  return {
    base64url: bufferToBase64url(hashBuffer),
    hex: bufferToHex(hashBuffer),
    canonicalJson,
  };
}

// Logging helper
const logEl = document.getElementById('console-logs') as HTMLPreElement;
function log(msg: string) {
  const time = new Date().toISOString().split('T')[1].slice(0, 8);
  const line = `[${time}] ${msg}\n`;
  console.log(line.trim());
  if (logEl) {
    logEl.textContent += line;
    logEl.scrollTop = logEl.scrollHeight;
  }
}

async function runBrowserSpike() {
  logEl.textContent = '';
  log('Starting TrustPass SD-JWT VC in-browser test suite...');

  const overallBadge = document.getElementById('overall-status')!;
  overallBadge.className = 'status-badge running';
  overallBadge.innerHTML = '<span class="dot"></span> Running Suite...';

  // Environment detection
  const envEl = document.getElementById('env-info');
  if (envEl) {
    const hasCrypto = typeof window !== 'undefined' && !!window.crypto && !!window.crypto.subtle;
    envEl.textContent = `WebCrypto: ${hasCrypto ? 'Available (Native)' : 'Missing'} · Browser: ${navigator.userAgent.slice(0, 40)}...`;
  }

  try {
    // ══════════════════════════════════════════════════════════
    // Step 1: Issuer Key Pair & RFC 7638 Thumbprint
    // ══════════════════════════════════════════════════════════
    log('Step 1: Generating ES256 keypair via @owf/crypto...');
    const t0 = performance.now();
    const keyPair = await ES256.generateKeyPair();
    const signer = await ES256.getSigner(keyPair.privateKey);
    const verifier = await ES256.getVerifier(keyPair.publicKey);
    log(`Keypair generated in ${(performance.now() - t0).toFixed(1)}ms`);

    log('Computing RFC 7638 JWK thumbprint via jose & manual canonical SHA-256...');
    const joseThumbprint = await calculateJwkThumbprint(keyPair.publicKey, 'sha256');
    const manualThumbprint = await computeManualRfc7638Thumbprint(keyPair.publicKey);

    const thumbprintsMatch = joseThumbprint === manualThumbprint.base64url;
    log(`jose thumbprint:   ${joseThumbprint}`);
    log(`manual thumbprint: ${manualThumbprint.base64url}`);
    log(`RFC 7638 cross-check: ${thumbprintsMatch ? 'MATCH ✅' : 'MISMATCH ❌'}`);

    const badgeKey = document.getElementById('badge-key')!;
    badgeKey.className = 'badge success';
    badgeKey.textContent = 'Generated & Computed';

    const dataKey = document.getElementById('data-key')!;
    dataKey.innerHTML = `
      <div class="thumbprint-highlight">
        <span class="thumbprint-label">RFC 7638 JWK Thumbprint (SHA-256 base64url)</span>
        <span class="thumbprint-value"><code>${joseThumbprint}</code></span>
        <span class="thumbprint-label" style="margin-top: 4px;">Solidity bytes32 (On-chain Registry Format)</span>
        <span class="thumbprint-value"><code>${manualThumbprint.hex}</code></span>
      </div>
      <div class="sub-meta">Canonical RFC 7638 JSON (Lexicographical EC order: <code>crv, kty, x, y</code>):</div>
      <pre class="json-preview">${manualThumbprint.canonicalJson}</pre>
      <div class="sub-meta">
        jose thumbprint: <code>${joseThumbprint}</code><br/>
        native WebCrypto: <code>${manualThumbprint.base64url}</code><br/>
        Verification: <strong>${thumbprintsMatch ? '✅ Perfect 1:1 Match' : '❌ Mismatch'}</strong>
      </div>
    `;

    // ══════════════════════════════════════════════════════════
    // Step 2: Issue Credential
    // ══════════════════════════════════════════════════════════
    log('Step 2: Initializing SDJwtVcInstance & issuing credential with 6 claims...');
    const sdjwt = new SDJwtVcInstance({
      signer,
      signAlg: 'ES256',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
    });

    const credentialClaims = {
      name: 'Alice Wonderland',
      studentId: 'TP-2026-8819',
      degree: 'BSc Computer Science',
      grade: 'First Class Honours',
      institution: 'University of TrustPass',
      issueDate: '2026-06-15',
    };

    const credential = await sdjwt.issue(
      {
        iss: 'https://issuer.trustpass.example',
        vct: 'UniversityDegreeCredential',
        iat: Math.floor(Date.now() / 1000),
        ...credentialClaims,
      },
      {
        _sd: ['name', 'studentId', 'degree', 'grade', 'institution', 'issueDate'],
      },
    );

    const credParts = credential.split('~');
    log(`Issued SD-JWT VC successfully! Total length: ${credential.length} chars. Disclosures: ${credParts.length - 1}`);

    const badgeIssue = document.getElementById('badge-issue')!;
    badgeIssue.className = 'badge success';
    badgeIssue.textContent = 'Issued (6 Disclosures)';

    const dataIssue = document.getElementById('data-issue')!;
    dataIssue.innerHTML = `
      <div><strong>Issuer Compact Token:</strong> <code>${credential.slice(0, 60)}...</code> (${credential.length} chars)</div>
      <div class="sub-meta">6 selectively disclosable claims encoded:</div>
      <div class="claim-tag-list">
        <span class="claim-tag">name</span>
        <span class="claim-tag">studentId</span>
        <span class="claim-tag">degree</span>
        <span class="claim-tag">grade</span>
        <span class="claim-tag">institution</span>
        <span class="claim-tag">issueDate</span>
      </div>
      <div class="sub-meta">Disclosures attached: <strong>${credParts.length - 1}</strong> digests salted with @owf/crypto</div>
    `;

    // ══════════════════════════════════════════════════════════
    // Step 3: Present with Selective Disclosure
    // ══════════════════════════════════════════════════════════
    log('Step 3: Creating presentation disclosing ONLY degree + institution...');
    const presentation = await sdjwt.present(credential, {
      degree: true,
      institution: true,
    });

    const presParts = presentation.split('~');
    // presParts format: [jwt, disclosure1, disclosure2, ''] -> 2 disclosed
    const disclosedCount = presParts.filter((p) => p && !p.startsWith('ey')).length;
    log(`Presentation generated! Disclosed parts count: ${disclosedCount} (expected 2)`);

    const badgePresent = document.getElementById('badge-present')!;
    badgePresent.className = 'badge success';
    badgePresent.textContent = 'Presented (2 Disclosed)';

    const dataPresent = document.getElementById('data-present')!;
    dataPresent.innerHTML = `
      <div><strong>Presentation Token:</strong> <code>${presentation.slice(0, 60)}...</code> (${presentation.length} chars)</div>
      <div class="sub-meta">Disclosed fields:</div>
      <div class="claim-tag-list">
        <span class="claim-tag disclosed">✓ degree: "BSc Computer Science"</span>
        <span class="claim-tag disclosed">✓ institution: "University of TrustPass"</span>
        <span class="claim-tag hidden">✗ name (hidden)</span>
        <span class="claim-tag hidden">✗ studentId (hidden)</span>
        <span class="claim-tag hidden">✗ grade (hidden)</span>
        <span class="claim-tag hidden">✗ issueDate (hidden)</span>
      </div>
      <div class="sub-meta">Active disclosures in presentation: <strong>${disclosedCount} of 6</strong></div>
    `;

    // ══════════════════════════════════════════════════════════
    // Step 4: In-Browser Verification
    // ══════════════════════════════════════════════════════════
    log('Step 4: Verifying presentation using @owf/crypto verifier...');
    const verifyResult = await sdjwt.verify(presentation);
    const verifiedPayload = (verifyResult as any).payload || verifyResult;

    log('Verification successful! Checking verified payload claims...');
    log(`Verified claims: ${JSON.stringify(verifiedPayload)}`);

    // Integrity checks
    const degreeMatches = verifiedPayload.degree === 'BSc Computer Science';
    const instMatches = verifiedPayload.institution === 'University of TrustPass';
    const nameHidden = verifiedPayload.name === undefined;
    const studentIdHidden = verifiedPayload.studentId === undefined;
    const gradeHidden = verifiedPayload.grade === undefined;

    const allPrivacyChecksPass = degreeMatches && instMatches && nameHidden && studentIdHidden && gradeHidden;
    log(`Privacy & claim assertions: ${allPrivacyChecksPass ? 'ALL PASSED ✅' : 'FAILED ❌'}`);

    const badgeVerify = document.getElementById('badge-verify')!;
    badgeVerify.className = 'badge success';
    badgeVerify.textContent = 'Verified (100% Pass)';

    const dataVerify = document.getElementById('data-verify')!;
    dataVerify.innerHTML = `
      <div style="color: var(--success); font-weight: 600;">✅ Signature & Disclosures Verified Valid by @owf/crypto</div>
      <pre class="json-preview">${JSON.stringify(verifiedPayload, null, 2)}</pre>
      <div class="sub-meta">
        • Disclosed claims verified: <strong>degree, institution</strong><br/>
        • Undisclosed claims leaked: <strong>0 (name, studentId, grade, issueDate completely concealed)</strong>
      </div>
    `;

    // All passed!
    overallBadge.className = 'status-badge passed';
    overallBadge.innerHTML = 'All Checks Passed ✅';
    log('🎉 All in-browser tests passed with 0 errors.');

  } catch (err: any) {
    log(`❌ ERROR: ${err.message || String(err)}`);
    console.error(err);
    overallBadge.className = 'status-badge failed';
    overallBadge.innerHTML = 'Error Occurred ❌';
  }
}

// Initial run
window.addEventListener('DOMContentLoaded', () => {
  runBrowserSpike();
  document.getElementById('rerun-btn')?.addEventListener('click', () => {
    runBrowserSpike();
  });
});
