import { ES256, digest, generateSalt } from '@owf/crypto';
import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { calculateJwkThumbprint } from 'jose';

const STORAGE_KEY = 'trustpass_issuer_key_v1';

export interface StoredKeyBundle {
  publicKey: JsonWebKey;
  privateKey: JsonWebKey;
  thumbprintB64url: string;
  thumbprintHex: `0x${string}`;
}

// Convert ArrayBuffer to Hex string with 0x prefix
export function bufferToHex(buf: ArrayBuffer): `0x${string}` {
  const bytes = new Uint8Array(buf);
  let hex = '0x';
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0');
  }
  return hex as `0x${string}`;
}

// Calculate RFC 7638 SHA-256 JWK Thumbprint for EC P-256 Key
export async function computeRfc7638Thumbprint(jwk: JsonWebKey): Promise<{
  b64url: string;
  hex: `0x${string}`;
  canonicalJson: string;
}> {
  // RFC 7638 Section 3: EC required members in lexicographic order: crv, kty, x, y
  const canonical = {
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  };
  const canonicalJson = JSON.stringify(canonical);
  const data = new TextEncoder().encode(canonicalJson);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);

  const b64url = await calculateJwkThumbprint(jwk as any, 'sha256');
  const hex = bufferToHex(hashBuffer);

  return { b64url, hex, canonicalJson };
}

// Generate, store, and return ES256 key bundle
export async function generateAndStoreIssuerKey(): Promise<StoredKeyBundle> {
  const keyPair = await ES256.generateKeyPair();
  const { b64url, hex } = await computeRfc7638Thumbprint(keyPair.publicKey);

  const bundle: StoredKeyBundle = {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    thumbprintB64url: b64url,
    thumbprintHex: hex,
  };

  localStorage.setItem(STORAGE_KEY, JSON.stringify(bundle));
  return bundle;
}

// Load key bundle from localStorage
export function loadStoredIssuerKey(): StoredKeyBundle | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as StoredKeyBundle;
  } catch {
    return null;
  }
}

// Save imported key bundle
export async function saveImportedKey(bundle: { publicKey: JsonWebKey; privateKey: JsonWebKey }): Promise<StoredKeyBundle> {
  const { b64url, hex } = await computeRfc7638Thumbprint(bundle.publicKey);
  const fullBundle: StoredKeyBundle = {
    publicKey: bundle.publicKey,
    privateKey: bundle.privateKey,
    thumbprintB64url: b64url,
    thumbprintHex: hex,
  };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(fullBundle));
  return fullBundle;
}

// Compute SHA-256 commitment hash of the issuer JWT
export async function computeOnChainHash(issuerJwt: string): Promise<`0x${string}`> {
  const data = new TextEncoder().encode(issuerJwt);
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  return bufferToHex(hashBuffer);
}

// Issue an SD-JWT VC credential with the public key in header
export async function issueCredential(
  claims: {
    name: string;
    studentId: string;
    degree: string;
    grade: string;
    institution: string;
    issueDate: string;
  },
  keyBundle: StoredKeyBundle
): Promise<{
  credential: string;
  issuerJwt: string;
  onChainHash: `0x${string}`;
}> {
  const signer = await ES256.getSigner(keyBundle.privateKey);
  const verifier = await ES256.getVerifier(keyBundle.publicKey);

  const sdjwt = new SDJwtVcInstance({
    signer,
    signAlg: 'ES256',
    verifier,
    hasher: digest,
    hashAlg: 'sha-256',
    saltGenerator: generateSalt,
  });

  const credential = await sdjwt.issue(
    {
      iss: `did:ethr:${keyBundle.thumbprintHex.slice(0, 12)}...`,
      vct: 'UniversityDegreeCredential',
      iat: Math.floor(Date.now() / 1000),
      cnf: {
        jwk: keyBundle.publicKey,
      },
      ...claims,
    },
    {
      _sd: ['name', 'studentId', 'degree', 'grade', 'institution', 'issueDate'],
    },
    {
      header: {
        typ: 'dc+sd-jwt',
        alg: 'ES256',
        jwk: keyBundle.publicKey, // Public JWK embedded directly in header
      },
    }
  );

  const [issuerJwt] = credential.split('~');
  const onChainHash = await computeOnChainHash(issuerJwt);

  return { credential, issuerJwt, onChainHash };
}

// Create a presentation disclosing only selected fields
export async function createPresentation(
  fullCredential: string,
  selectedFields: Record<string, boolean>
): Promise<string> {
  // Extract issuer key from header
  const [issuerJwt] = fullCredential.split('~');
  const [b64Header] = issuerJwt.split('.');
  const headerJson = JSON.parse(atob(b64Header.replace(/-/g, '+').replace(/_/g, '/')));
  const jwk = headerJson.jwk;

  if (!jwk) {
    throw new Error('Credential header does not contain public JWK.');
  }

  const verifier = await ES256.getVerifier(jwk);
  const sdjwt = new SDJwtVcInstance({
    verifier,
    hasher: digest,
    hashAlg: 'sha-256',
  });

  return await sdjwt.present(fullCredential, selectedFields);
}

// In-Browser Verification Result
export interface InBrowserVerifyResult {
  signatureValid: boolean;
  headerJwk: JsonWebKey | null;
  headerThumbprintHex: `0x${string}` | null;
  issuerJwt: string;
  onChainHash: `0x${string}`;
  verifiedClaims: Record<string, any>;
  disclosedKeys: string[];
}

export async function verifyPresentationToken(presentation: string): Promise<InBrowserVerifyResult> {
  const parts = presentation.split('~');
  const issuerJwt = parts[0];
  if (!issuerJwt) throw new Error('Invalid presentation format: missing issuer JWT.');

  const [b64Header] = issuerJwt.split('.');
  const headerJson = JSON.parse(atob(b64Header.replace(/-/g, '+').replace(/_/g, '/')));
  const headerJwk = headerJson.jwk as JsonWebKey;

  if (!headerJwk) {
    throw new Error('Issuer public key (JWK) not found in JWT header.');
  }

  const { hex: headerThumbprintHex } = await computeRfc7638Thumbprint(headerJwk);
  const onChainHash = await computeOnChainHash(issuerJwt);

  const verifier = await ES256.getVerifier(headerJwk);
  const sdjwt = new SDJwtVcInstance({
    verifier,
    hasher: digest,
    hashAlg: 'sha-256',
  });

  const verified = await sdjwt.verify(presentation);
  const verifiedPayload = (verified as any).payload || verified;

  const reservedKeys = ['iss', 'vct', 'iat', 'cnf', '_sd', '_sd_alg'];
  const disclosedKeys = Object.keys(verifiedPayload).filter((k) => !reservedKeys.includes(k));

  return {
    signatureValid: true,
    headerJwk,
    headerThumbprintHex,
    issuerJwt,
    onChainHash,
    verifiedClaims: verifiedPayload,
    disclosedKeys,
  };
}
