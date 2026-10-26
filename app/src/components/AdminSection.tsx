import React, { useState } from 'react';
import {
  publicClient,
  getWalletClient,
  ISSUER_REGISTRY_ADDRESS,
  ISSUER_REGISTRY_ABI,
} from '../contracts';
import type { Address } from 'viem';

interface AdminSectionProps {
  connectedAccount: Address | null;
  onConnectWallet: () => void;
}

export const AdminSection: React.FC<AdminSectionProps> = ({
  connectedAccount,
  onConnectWallet,
}) => {
  const [wallet, setWallet] = useState('');
  const [name, setName] = useState('');
  const [fingerprint, setFingerprint] = useState('');
  const [txHash, setTxHash] = useState<string | null>(null);
  const [statusMsg, setStatusMsg] = useState<{ type: 'info' | 'success' | 'danger'; text: string } | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  // Issuer lookup state
  const [lookupAddress, setLookupAddress] = useState('');
  const [lookupResult, setLookupResult] = useState<{
    name: string;
    fingerprint: string;
    active: boolean;
  } | null>(null);
  const [lookupError, setLookupError] = useState<string | null>(null);
  const [isLookingUp, setIsLookingUp] = useState(false);

  const handleAddIssuer = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!connectedAccount) {
      onConnectWallet();
      return;
    }

    if (!wallet.startsWith('0x') || wallet.length !== 42) {
      setStatusMsg({ type: 'danger', text: 'Please enter a valid 20-byte Ethereum address (0x...).' });
      return;
    }
    if (!name.trim()) {
      setStatusMsg({ type: 'danger', text: 'Please enter an issuer institution name.' });
      return;
    }
    if (!fingerprint.startsWith('0x') || fingerprint.length !== 66) {
      setStatusMsg({ type: 'danger', text: 'Fingerprint must be a 32-byte hex string (66 chars starting with 0x).' });
      return;
    }

    setIsSubmitting(true);
    setStatusMsg({ type: 'info', text: 'Confirm transaction in MetaMask...' });
    setTxHash(null);

    try {
      const walletClient = await getWalletClient();
      const hash = await walletClient.writeContract({
        address: ISSUER_REGISTRY_ADDRESS,
        abi: ISSUER_REGISTRY_ABI,
        functionName: 'addIssuer',
        args: [wallet as Address, name.trim(), fingerprint as `0x${string}`],
      });

      setTxHash(hash);
      setStatusMsg({ type: 'info', text: `Transaction submitted! Waiting for block confirmation...` });

      await publicClient.waitForTransactionReceipt({ hash });

      setStatusMsg({ type: 'success', text: `Issuer "${name}" successfully registered on Sepolia!` });
      setWallet('');
      setName('');
      setFingerprint('');
    } catch (err: any) {
      setStatusMsg({ type: 'danger', text: err.shortMessage || err.message || 'Transaction failed.' });
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleLookup = async () => {
    if (!lookupAddress.startsWith('0x') || lookupAddress.length !== 42) {
      setLookupError('Enter a valid 0x address.');
      return;
    }

    setIsLookingUp(true);
    setLookupError(null);
    setLookupResult(null);

    try {
      const data = await publicClient.readContract({
        address: ISSUER_REGISTRY_ADDRESS,
        abi: ISSUER_REGISTRY_ABI,
        functionName: 'getIssuer',
        args: [lookupAddress as Address],
      }) as [string, `0x${string}`, boolean];

      setLookupResult({
        name: data[0],
        fingerprint: data[1],
        active: data[2],
      });
    } catch (err: any) {
      setLookupError('Issuer not found or error reading from registry.');
    } finally {
      setIsLookingUp(false);
    }
  };

  return (
    <div className="portal-card">
      <h2 className="card-title">Admin · Issuer Registry Management</h2>
      <p className="card-subtitle">
        Register trusted educational or governmental issuing institutions by binding their Ethereum wallet address to their RFC 7638 ES256 key fingerprint.
      </p>

      {/* Add Issuer Form */}
      <form onSubmit={handleAddIssuer} style={{ marginBottom: '2rem' }}>
        <div className="form-grid">
          <div className="form-group form-full">
            <label htmlFor="issuer-wallet">Issuer Wallet Address</label>
            <input
              id="issuer-wallet"
              type="text"
              className="form-control"
              placeholder="0x..."
              value={wallet}
              onChange={(e) => setWallet(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="issuer-name">Institutional Name</label>
            <input
              id="issuer-name"
              type="text"
              className="form-control"
              placeholder="e.g. University of TrustPass"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="issuer-fingerprint">Key Fingerprint (RFC 7638 SHA-256)</label>
            <input
              id="issuer-fingerprint"
              type="text"
              className="form-control"
              placeholder="0x... (bytes32 hex)"
              value={fingerprint}
              onChange={(e) => setFingerprint(e.target.value)}
              required
            />
          </div>
        </div>

        <div className="button-group" style={{ marginTop: '0.75rem' }}>
          <button type="submit" className="btn btn-primary" disabled={isSubmitting}>
            {isSubmitting ? 'Submitting...' : 'Register Issuer on Sepolia'}
          </button>
          {!connectedAccount && (
            <span style={{ fontSize: '0.82rem', color: 'var(--text-sub)' }}>
              (MetaMask connection required for owner transaction)
            </span>
          )}
        </div>
      </form>

      {/* Transaction status */}
      {statusMsg && (
        <div className={`alert alert-${statusMsg.type}`}>
          <div>{statusMsg.text}</div>
          {txHash && (
            <div style={{ marginTop: '0.25rem' }}>
              <a
                href={`https://sepolia.etherscan.io/tx/${txHash}`}
                target="_blank"
                rel="noreferrer"
                style={{ color: 'inherit', fontWeight: 600 }}
              >
                View on Sepolia Etherscan ↗
              </a>
            </div>
          )}
        </div>
      )}

      {/* Registry Lookup Inspector */}
      <div style={{ borderTop: '1px solid var(--border-muted)', paddingTop: '1.25rem' }}>
        <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.6rem' }}>
          Query Issuer Registry
        </h3>
        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.75rem' }}>
          <input
            type="text"
            className="form-control"
            placeholder="Search issuer by address (0x...)"
            value={lookupAddress}
            onChange={(e) => setLookupAddress(e.target.value)}
            style={{ flex: 1 }}
          />
          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleLookup}
            disabled={isLookingUp}
          >
            {isLookingUp ? 'Searching...' : 'Lookup'}
          </button>
        </div>

        {lookupError && <div className="alert alert-warning">{lookupError}</div>}

        {lookupResult && (
          <table className="portal-table">
            <thead>
              <tr>
                <th>Field</th>
                <th>Value</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>Institutional Name</td>
                <td><strong>{lookupResult.name}</strong></td>
              </tr>
              <tr>
                <td>Key Fingerprint (bytes32)</td>
                <td><code>{lookupResult.fingerprint}</code></td>
              </tr>
              <tr>
                <td>Registry Status</td>
                <td>
                  <span style={{ color: lookupResult.active ? 'var(--success)' : 'var(--danger)', fontWeight: 600 }}>
                    {lookupResult.active ? '● Active' : '○ Suspended'}
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
};
