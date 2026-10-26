import React, { useState } from 'react';
import {
  publicClient,
  getWalletClient,
  CREDENTIAL_ANCHOR_ADDRESS,
  CREDENTIAL_ANCHOR_ABI,
} from '../contracts';
import { computeOnChainHash } from '../crypto';
import type { Address } from 'viem';

interface RevokeSectionProps {
  connectedAccount: Address | null;
  onConnectWallet: () => void;
}

export const RevokeSection: React.FC<RevokeSectionProps> = ({
  connectedAccount,
  onConnectWallet,
}) => {
  const [hashInput, setHashInput] = useState('');
  const [rawTokenInput, setRawTokenInput] = useState('');
  const [isRevoking, setIsRevoking] = useState(false);
  const [txHash, setTxHash] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<{ type: 'info' | 'success' | 'danger'; text: string } | null>(null);

  const handleComputeHashFromToken = async () => {
    const raw = rawTokenInput.trim();
    if (!raw) return;
    try {
      const [issuerJwt] = raw.split('~');
      const hash = await computeOnChainHash(issuerJwt);
      setHashInput(hash);
      setStatusMsg({ type: 'info', text: 'Commitment hash auto-computed from credential token.' });
    } catch (err: any) {
      setStatusMsg({ type: 'danger', text: 'Failed to compute hash from token: ' + err.message });
    }
  };

  const handleRevoke = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!connectedAccount) {
      onConnectWallet();
      return;
    }

    const hash = hashInput.trim();
    if (!hash.startsWith('0x') || hash.length !== 66) {
      setStatusMsg({ type: 'danger', text: 'Hash must be a 32-byte hex string (66 characters starting with 0x).' });
      return;
    }

    setIsRevoking(true);
    setTxHash(null);
    setStatusMsg({ type: 'info', text: 'Confirm revocation transaction in MetaMask...' });

    try {
      const walletClient = await getWalletClient();
      const tx = await walletClient.writeContract({
        address: CREDENTIAL_ANCHOR_ADDRESS,
        abi: CREDENTIAL_ANCHOR_ABI,
        functionName: 'revoke',
        args: [hash as `0x${string}`],
      });

      setTxHash(tx);
      setStatusMsg({ type: 'info', text: 'Transaction submitted! Awaiting Sepolia block confirmation...' });

      await publicClient.waitForTransactionReceipt({ hash: tx });

      // Verify on-chain status updated to Revoked (state == 2)
      const onChainData = (await publicClient.readContract({
        address: CREDENTIAL_ANCHOR_ADDRESS,
        abi: CREDENTIAL_ANCHOR_ABI,
        functionName: 'status',
        args: [hash as `0x${string}`],
      })) as [number, Address, `0x${string}`, boolean];

      if (onChainData[0] === 2) {
        setStatusMsg({
          type: 'success',
          text: 'Credential successfully revoked on Sepolia! On-chain status is now REVOKED.',
        });
      } else {
        setStatusMsg({
          type: 'info',
          text: `Revocation transaction confirmed: ${tx}`,
        });
      }
    } catch (err: any) {
      setStatusMsg({
        type: 'danger',
        text: err.shortMessage || err.message || 'Revocation failed.',
      });
    } finally {
      setIsRevoking(false);
    }
  };

  return (
    <div className="portal-card">
      <h2 className="card-title">Revoke · Invalidate Credential Commitment</h2>
      <p className="card-subtitle">
        Issuing entities can revoke a previously anchored credential on Sepolia. Only the original issuing wallet has the authority to revoke.
      </p>

      {/* Auto-compute hash tool */}
      <div style={{ background: '#f8fafc', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: '0.85rem', marginBottom: '1.25rem' }}>
        <label htmlFor="raw-token-helper" style={{ fontSize: '0.82rem', fontWeight: 600, display: 'block', marginBottom: '0.35rem' }}>
          Auto-Derive Commitment Hash from Credential Token (Optional):
        </label>
        <div style={{ display: 'flex', gap: '0.5rem' }}>
          <input
            id="raw-token-helper"
            type="text"
            className="form-control"
            placeholder="Paste credential token (eyJ0eXAiOiJkYytzZC1qd3Qi...)"
            value={rawTokenInput}
            onChange={(e) => setRawTokenInput(e.target.value)}
            style={{ flex: 1 }}
          />
          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleComputeHashFromToken}
            disabled={!rawTokenInput.trim()}
          >
            Compute Hash
          </button>
        </div>
      </div>

      {/* Revocation Form */}
      <form onSubmit={handleRevoke}>
        <div className="form-group">
          <label htmlFor="revoke-hash">Credential Commitment Hash (bytes32)</label>
          <input
            id="revoke-hash"
            type="text"
            className="form-control"
            placeholder="0x... (66 characters)"
            value={hashInput}
            onChange={(e) => setHashInput(e.target.value)}
            required
          />
        </div>

        <div className="button-group">
          <button type="submit" className="btn btn-danger" disabled={isRevoking || !hashInput.trim()}>
            {isRevoking ? 'Revoking on Sepolia...' : 'Revoke Credential on Sepolia'}
          </button>
          {!connectedAccount && (
            <span style={{ fontSize: '0.82rem', color: 'var(--text-sub)' }}>
              (MetaMask connection required as original issuer)
            </span>
          )}
        </div>
      </form>

      {/* Status Message */}
      {statusMsg && (
        <div className={`alert alert-${statusMsg.type}`} style={{ marginTop: '1.25rem' }}>
          <div>{statusMsg.text}</div>
          {txHash && (
            <div style={{ marginTop: '0.25rem' }}>
              <a
                href={`https://sepolia.etherscan.io/tx/${txHash}`}
                target="_blank"
                rel="noreferrer"
                style={{ color: 'inherit', fontWeight: 600 }}
              >
                View Revocation on Etherscan ↗
              </a>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
