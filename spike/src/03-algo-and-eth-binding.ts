/**
 * Script 03 — Algorithm exploration: ES256 vs ES256K + Ethereum binding.
 *
 * 1. ES256 (P-256): works out of the box with @owf/crypto.
 * 2. ES256K (secp256k1) via jose: fails — jose v6 uses Web Crypto which
 *    does not support secp256k1 in Node.js 24.
 * 3. ES256K (secp256k1) via @noble/secp256k1: works! Pure-JS, no Web Crypto.
 * 4. Ethereum address derivation from secp256k1 public key.
 * 5. Alternative: ES256 + Ethereum address as a separate identifier.
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
import { generateKeyPair, exportJWK } from 'jose';
import * as secp from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { keccak_256 } from '@noble/hashes/sha3';

// @noble/secp256k1 v2 requires explicit HMAC-SHA256 configuration for RFC6979 deterministic nonces
secp.etc.hmacSha256Sync = (key: Uint8Array, ...messages: Uint8Array[]) =>
  hmac(sha256, key, secp.etc.concatBytes(...messages));

// ─── Helpers ───

function uint8ArrayToBase64Url(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64UrlToUint8Array(b64url: string): Uint8Array {
  const base64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

/**
 * Create a custom ES256K signer using @noble/secp256k1.
 * SDJwtVcInstance passes the compact header.payload string to sign.
 * The signer must return a base64url-encoded signature.
 */
function makeNobleSecp256k1Signer(privKeyBytes: Uint8Array) {
  return async (data: string): Promise<string> => {
    const encoder = new TextEncoder();
    const msgHash = sha256(encoder.encode(data));
    const sig = secp.sign(msgHash, privKeyBytes);
    // Return compact (r || s) signature as base64url — 64 bytes
    return uint8ArrayToBase64Url(sig.toCompactRawBytes());
  };
}

/**
 * Create a custom ES256K verifier using @noble/secp256k1.
 */
function makeNobleSecp256k1Verifier(pubKeyBytes: Uint8Array) {
  return async (data: string, signature: string): Promise<boolean> => {
    const encoder = new TextEncoder();
    const msgHash = sha256(encoder.encode(data));
    const sigBytes = base64UrlToUint8Array(signature);
    return secp.verify(sigBytes, msgHash, pubKeyBytes);
  };
}

/** Derive Ethereum address from uncompressed secp256k1 public key bytes */
function deriveEthAddressFromBytes(uncompressedPubKey: Uint8Array): string {
  // Ethereum address = last 20 bytes of keccak256(pubKey without 0x04 prefix)
  const pubKeyNoPrefix = uncompressedPubKey.slice(1); // remove 0x04 byte
  const hash = keccak_256(pubKeyNoPrefix);
  const addressBytes = hash.slice(-20);
  return '0x' + Buffer.from(addressBytes).toString('hex');
}

/** Derive Ethereum address from JWK (x, y) coordinates */
function deriveEthAddressFromJwk(jwk: { x?: string; y?: string }): string {
  if (!jwk.x || !jwk.y) throw new Error('JWK missing x/y coordinates');
  const xBytes = base64UrlToUint8Array(jwk.x);
  const yBytes = base64UrlToUint8Array(jwk.y);
  // For keccak we hash x || y (64 bytes, no 0x04 prefix)
  const pubKeyBytes = new Uint8Array(64);
  pubKeyBytes.set(xBytes, 0);
  pubKeyBytes.set(yBytes, 32);
  const hash = keccak_256(pubKeyBytes);
  const addressBytes = hash.slice(-20);
  return '0x' + Buffer.from(addressBytes).toString('hex');
}

// ─── Main ───

async function main() {
  header('03 — Algorithm & Ethereum Binding');

  const baseClaims = {
    name: 'Alice Johnson',
    degree: 'BSc Computer Science',
    institution: 'University of TrustPass',
  };

  const disclosureFrame: DisclosureFrame<typeof baseClaims> = {
    _sd: ['name', 'degree', 'institution'],
  };

  // ────────────────────────────────────────────
  // TEST A: ES256 (P-256) via @owf/crypto
  // ────────────────────────────────────────────
  subheader('Test A: ES256 (P-256) via @owf/crypto');

  try {
    const es256Keys = await createES256KeyBundle();

    const sdjwtES256 = new SDJwtVcInstance({
      signer: es256Keys.signer,
      signAlg: 'ES256',
      verifier: es256Keys.verifier,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
    });

    const cred = await sdjwtES256.issue(
      {
        iss: 'https://university.trustpass.example',
        vct: 'UniversityDegreeCredential',
        iat: Math.floor(Date.now() / 1000),
        ...baseClaims,
      },
      disclosureFrame,
    );

    const pres = await sdjwtES256.present(cred, { degree: true });
    await sdjwtES256.verify(pres);

    console.log('✅ ES256 works end-to-end with @owf/crypto');
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log('❌ ES256 failed:', msg);
  }

  // ────────────────────────────────────────────
  // TEST B: ES256K (secp256k1) via jose (Web Crypto)
  // ────────────────────────────────────────────
  subheader('Test B: ES256K via jose (Web Crypto)');

  try {
    const { publicKey, privateKey } = await generateKeyPair('ES256K');
    console.log('✅ jose.generateKeyPair("ES256K") succeeded');
    // If we get here, try to use it...
    const jwk = await exportJWK(publicKey);
    console.log('   Public key JWK curve:', jwk.crv);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log('❌ jose ES256K failed:', msg);
    console.log('   WHY: jose v6 delegates to Web Crypto API (crypto.subtle).');
    console.log('   Node.js 24 Web Crypto does NOT support secp256k1 natively.');
    console.log('   This is a Node.js / Web Crypto limitation, not jose\'s fault.');
  }

  // ────────────────────────────────────────────
  // TEST C: ES256K (secp256k1) via @noble/secp256k1 (pure JS)
  // ────────────────────────────────────────────
  subheader('Test C: ES256K via @noble/secp256k1 (pure JS)');

  try {
    // Generate a secp256k1 key pair using @noble/secp256k1
    const privKey = secp.utils.randomPrivateKey();
    const pubKey = secp.getPublicKey(privKey, false); // uncompressed (65 bytes)

    const signer = makeNobleSecp256k1Signer(privKey);
    const verifier = makeNobleSecp256k1Verifier(pubKey);

    const sdjwtES256K = new SDJwtVcInstance({
      signer,
      signAlg: 'ES256K',
      verifier,
      hasher: digest,
      hashAlg: 'sha-256',
      saltGenerator: generateSalt,
    });

    const cred = await sdjwtES256K.issue(
      {
        iss: 'https://university.trustpass.example',
        vct: 'UniversityDegreeCredential',
        iat: Math.floor(Date.now() / 1000),
        ...baseClaims,
      },
      disclosureFrame,
    );

    const pres = await sdjwtES256K.present(cred, { degree: true });
    await sdjwtES256K.verify(pres);

    console.log('✅ ES256K works end-to-end via @noble/secp256k1');

    // Derive Ethereum address
    const ethAddress = deriveEthAddressFromBytes(pubKey);
    console.log('   Derived Ethereum address:', ethAddress);
    console.log('   Private key (hex, NEVER store on-chain):', Buffer.from(privKey).toString('hex'));
    console.log('');
    console.log('   → The issuer signs SD-JWT VCs with this secp256k1 key');
    console.log('   → The same key derives their Ethereum address');
    console.log('   → On-chain registry: issuers[ethAddress].active = true');
    console.log('   → Verifier: recover ethAddress from JWK → check on-chain');
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log('❌ ES256K via @noble failed:', msg);
  }

  // ────────────────────────────────────────────
  // TEST D: ES256 with Ethereum address as separate identifier
  // ────────────────────────────────────────────
  subheader('Test D: ES256 (P-256) + Ethereum address mapping');

  try {
    // Use jose to generate a P-256 key pair for JWK export
    // (@owf/crypto's key wrapper isn't compatible with jose.exportJWK)
    const { publicKey: p256PubKey } = await generateKeyPair('ES256');
    const jwk = await exportJWK(p256PubKey);
    console.log('P-256 JWK:', JSON.stringify({ kty: jwk.kty, crv: jwk.crv, x: (jwk.x ?? '').slice(0, 8) + '…', y: (jwk.y ?? '').slice(0, 8) + '…' }));

    // Compute a fingerprint of the P-256 JWK (canonical JSON → SHA-256)
    const jwkFingerprint = sha256(
      new TextEncoder().encode(JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y })),
    );
    const fingerprintHex = '0x' + Buffer.from(jwkFingerprint).toString('hex');

    console.log('JWK fingerprint (bytes32):', fingerprintHex);
    console.log('');
    console.log('ALTERNATIVE APPROACH — if ES256K is not desired:');
    console.log('  • Issuer registers with their Ethereum wallet (EOA)');
    console.log('  • On-chain: issuers[ethAddress] = { jwkFingerprint, active }');
    console.log('  • Issuer signs SD-JWT VCs with ES256 (P-256)');
    console.log('  • Verifier: hash the issuer\'s JWK → check fingerprint on-chain');
    console.log('  • The Ethereum address is an identifier, NOT the signing key');
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log('❌ Test D failed:', msg);
  }

  // ────────────────────────────────────────────
  // Summary
  // ────────────────────────────────────────────
  subheader('FINDINGS SUMMARY');
  console.log(`
┌─────────────────────────────────────────────────────────┐
│ Algorithm    │ Library          │ Works? │ Eth binding?  │
├─────────────────────────────────────────────────────────┤
│ ES256 (P256) │ @owf/crypto      │ ✅     │ via JWK hash  │
│ ES256K       │ jose (WebCrypto) │ ❌     │ N/A           │
│ ES256K       │ @noble/secp256k1 │ ✅*    │ native addr   │
└─────────────────────────────────────────────────────────┘

* ES256K via @noble works because it's pure JS, bypassing Web Crypto.
  The signer/verifier are custom functions plugged into SDJwtVcInstance.

RECOMMENDATION:
  Option A (simpler): ES256 + map Ethereum EOA → JWK fingerprint on-chain.
  Option B (native):  ES256K via @noble — same key signs JWT & derives eth addr.
  Both are valid for TrustPass. ES256 has wider ecosystem support.
  ES256K is more "Ethereum-native" but requires custom crypto wiring.
`);
}

main().catch((err) => {
  console.error('❌ Script 03 failed:', err);
  process.exit(1);
});
