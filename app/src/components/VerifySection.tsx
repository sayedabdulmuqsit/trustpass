import React, { useState } from 'react';
import { verifyPresentationToken, type InBrowserVerifyResult } from '../crypto';
import {
  publicClient,
  CREDENTIAL_ANCHOR_ADDRESS,
  CREDENTIAL_ANCHOR_ABI,
} from '../contracts';
import type { Address } from 'viem';

export type VerificationStatus = 'VALID' | 'INVALID' | 'NOT TRUSTED' | 'REVOKED' | 'EXPIRED' | null;

export const VerifySection: React.FC = () => {
  const [tokenInput, setTokenInput] = useState('');
  const [isVerifying, setIsVerifying] = useState(false);
  const [status, setStatus] = useState<VerificationStatus>(null);
  const [statusReason, setStatusReason] = useState<string>('');
  const [verifyDetails, setVerifyDetails] = useState<{
    local: InBrowserVerifyResult;
    onChain: {
      state: number; // 0=Unknown, 1=Valid, 2=Revoked, 3=Expired
      issuer: Address;
      fingerprint: `0x${string}`;
      issuerActive: boolean;
    };
    checks: {
      signature: boolean;
      thumbprintMatch: boolean;
      issuerActive: boolean;
      stateValid: boolean;
    };
  } | null>(null);

  const handleVerify = async (e: React.FormEvent) => {
    e.preventDefault();
    const token = tokenInput.trim();
    if (!token) return;

    setIsVerifying(true);
    setStatus(null);
    setStatusReason('');
    setVerifyDetails(null);

    try {
      // 1. In-Browser Cryptographic Verification (Signature & Disclosures)
      let localRes: InBrowserVerifyResult;
      try {
        localRes = await verifyPresentationToken(token);
      } catch (err: any) {
        setStatus('INVALID');
        setStatusReason(err.message || 'Cryptographic verification failed: malformed token or altered disclosure.');
        return;
      }

      // 2. Query On-Chain Status via Public Sepolia RPC (Zero Wallet Required)
      const onChainData = (await publicClient.readContract({
        address: CREDENTIAL_ANCHOR_ADDRESS,
        abi: CREDENTIAL_ANCHOR_ABI,
        functionName: 'status',
        args: [localRes.onChainHash],
      })) as [number, Address, `0x${string}`, boolean];

      const [stateNum, issuerAddr, anchorFp, issuerActive] = onChainData;

      const thumbprintMatch =
        !!localRes.headerThumbprintHex &&
        localRes.headerThumbprintHex.toLowerCase() === anchorFp.toLowerCase();

      const checks = {
        signature: localRes.signatureValid,
        thumbprintMatch,
        issuerActive,
        stateValid: stateNum === 1,
      };

      setVerifyDetails({
        local: localRes,
        onChain: {
          state: stateNum,
          issuer: issuerAddr,
          fingerprint: anchorFp,
          issuerActive,
        },
        checks,
      });

      // 3. Evaluate Status Decision
      if (stateNum === 0) {
        setStatus('NOT TRUSTED');
        setStatusReason('Credential commitment was not found on Ethereum Sepolia.');
      } else if (stateNum === 2) {
        setStatus('REVOKED');
        setStatusReason('This credential was revoked by the issuing institution.');
      } else if (stateNum === 3) {
        setStatus('EXPIRED');
        setStatusReason('This credential has passed its on-chain expiration timestamp.');
      } else if (!thumbprintMatch) {
        setStatus('NOT TRUSTED');
        setStatusReason('The signing key in the credential header does not match the on-chain anchor fingerprint.');
      } else if (!issuerActive) {
        setStatus('NOT TRUSTED');
        setStatusReason('The issuing institution is currently suspended or inactive in the Issuer Registry.');
      } else if (checks.signature && thumbprintMatch && issuerActive && checks.stateValid) {
        setStatus('VALID');
        setStatusReason('Cryptographic signature valid, issuer is active on Sepolia, and on-chain commitment is valid.');
      } else {
        setStatus('INVALID');
        setStatusReason('Verification checks failed.');
      }
    } catch (err: any) {
      setStatus('INVALID');
      setStatusReason('Verification error: ' + (err.shortMessage || err.message));
    } finally {
      setIsVerifying(false);
    }
  };

  return (
    <div className="portal-card">
      <h2 className="card-title">Verify · Zero-Wallet Decentralized Verification</h2>
      <p className="card-subtitle">
        Verify an SD-JWT presentation against the Ethereum Sepolia blockchain using public RPC. No wallet connection or browser extensions required.
      </p>

      {/* Verification Input Form */}
      <form onSubmit={handleVerify} style={{ marginBottom: '1.5rem' }}>
        <div className="form-group">
          <label htmlFor="verify-token">Paste Presentation Token or Credential String</label>
          <textarea
            id="verify-token"
            className="form-control"
            placeholder="eyJ0eXAiOiJkYytzZC1qd3Qi..."
            value={tokenInput}
            onChange={(e) => setTokenInput(e.target.value)}
            required
            rows={4}
          />
        </div>

        <div className="button-group">
          <button type="submit" className="btn btn-primary" disabled={isVerifying || !tokenInput.trim()}>
            {isVerifying ? 'Verifying on Sepolia...' : 'Verify Credential Presentation'}
          </button>
        </div>
      </form>

      {/* Result Banner */}
      {status && (
        <div
          className={`result-banner ${
            status === 'VALID'
              ? 'result-valid'
              : status === 'NOT TRUSTED'
              ? 'result-not-trusted'
              : status === 'REVOKED'
              ? 'result-revoked'
              : status === 'EXPIRED'
              ? 'result-expired'
              : 'result-invalid'
          }`}
        >
          <h2>{status}</h2>
          <p>{statusReason}</p>
        </div>
      )}

      {/* Verification Details Table */}
      {verifyDetails && (
        <div style={{ marginTop: '1.25rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.5rem' }}>
            Verification Checkpoints
          </h3>
          <table className="portal-table">
            <thead>
              <tr>
                <th>Verification Step</th>
                <th>Result</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>(1) Cryptographic Signature</td>
                <td>
                  <span style={{ color: verifyDetails.checks.signature ? 'var(--success)' : 'var(--danger)', fontWeight: 600 }}>
                    {verifyDetails.checks.signature ? '✓ Passed' : '✗ Failed'}
                  </span>
                </td>
                <td>ECDSA P-256 signature verified via Web Crypto</td>
              </tr>
              <tr>
                <td>(2) RFC 7638 Key Binding</td>
                <td>
                  <span style={{ color: verifyDetails.checks.thumbprintMatch ? 'var(--success)' : 'var(--danger)', fontWeight: 600 }}>
                    {verifyDetails.checks.thumbprintMatch ? '✓ Matched' : '✗ Mismatch'}
                  </span>
                </td>
                <td>
                  Header JWK matches on-chain fingerprint snapshot (<code>{verifyDetails.onChain.fingerprint.slice(0, 14)}...</code>)
                </td>
              </tr>
              <tr>
                <td>(3) Issuer Registry Authority</td>
                <td>
                  <span style={{ color: verifyDetails.checks.issuerActive ? 'var(--success)' : 'var(--danger)', fontWeight: 600 }}>
                    {verifyDetails.checks.issuerActive ? '✓ Active' : '✗ Inactive / Suspended'}
                  </span>
                </td>
                <td>Issuer wallet: <code>{verifyDetails.onChain.issuer}</code></td>
              </tr>
              <tr>
                <td>(4) On-Chain Anchor State</td>
                <td>
                  <span style={{ color: verifyDetails.checks.stateValid ? 'var(--success)' : 'var(--danger)', fontWeight: 600 }}>
                    {verifyDetails.onChain.state === 1
                      ? '✓ Valid'
                      : verifyDetails.onChain.state === 2
                      ? '✗ Revoked'
                      : verifyDetails.onChain.state === 3
                      ? '✗ Expired'
                      : '✗ Unknown'}
                  </span>
                </td>
                <td>Commitment Hash: <code>{verifyDetails.local.onChainHash}</code></td>
              </tr>
            </tbody>
          </table>

          {/* Disclosed Claims Preview */}
          <h3 style={{ fontSize: '1rem', fontWeight: 600, marginTop: '1.5rem', marginBottom: '0.5rem' }}>
            Verified Disclosed Claims
          </h3>
          <table className="portal-table">
            <thead>
              <tr>
                <th>Claim Attribute</th>
                <th>Disclosed Value</th>
              </tr>
            </thead>
            <tbody>
              {verifyDetails.local.disclosedKeys.map((key) => (
                <tr key={key}>
                  <td><strong>{key}</strong></td>
                  <td>{String(verifyDetails.local.verifiedClaims[key])}</td>
                </tr>
              ))}
              {verifyDetails.local.disclosedKeys.length === 0 && (
                <tr>
                  <td colSpan={2} style={{ color: 'var(--text-sub)' }}>
                    No selective claims disclosed in this presentation.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
};
