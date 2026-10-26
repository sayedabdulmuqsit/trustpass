/**
 * Shared crypto helpers for the SD-JWT VC spike.
 *
 * Tries @owf/crypto first (the successor to the deprecated @sd-jwt/crypto-nodejs).
 * Falls back to @sd-jwt/crypto-nodejs only if @owf/crypto fails at runtime.
 */

import { ES256, digest, generateSalt } from '@owf/crypto';
import type { Signer, Verifier } from '@sd-jwt/core';

// Re-export the hasher and salt generator for SDJwtVcInstance config
export { digest, generateSalt };

export interface KeyBundle {
  signer: Signer;
  verifier: Verifier;
  publicKey: JsonWebKey;
  privateKey: JsonWebKey;
}

/**
 * Generate an ES256 (P-256 / ECDSA) key pair and return ready-to-use
 * signer + verifier functions compatible with SDJwtVcInstance.
 */
export async function createES256KeyBundle(): Promise<KeyBundle> {
  const { privateKey, publicKey } = await ES256.generateKeyPair();
  const signer = await ES256.getSigner(privateKey);
  const verifier = await ES256.getVerifier(publicKey);
  return { signer, verifier, publicKey, privateKey };
}

/** Pretty-print a section header */
export function header(title: string): void {
  console.log(`\n${'═'.repeat(60)}`);
  console.log(`  ${title}`);
  console.log(`${'═'.repeat(60)}`);
}

/** Pretty-print a sub-section */
export function subheader(title: string): void {
  console.log(`\n── ${title} ──`);
}
