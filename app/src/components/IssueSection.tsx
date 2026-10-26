import React, { useState, useEffect } from 'react';
import {
  loadStoredIssuerKey,
  generateAndStoreIssuerKey,
  saveImportedKey,
  issueCredential,
  type StoredKeyBundle,
} from '../crypto';
import {
  publicClient,
  getWalletClient,
  CREDENTIAL_ANCHOR_ADDRESS,
  CREDENTIAL_ANCHOR_ABI,
} from '../contracts';
import type { Address } from 'viem';

interface IssueSectionProps {
  connectedAccount: Address | null;
  onConnectWallet: () => void;
}

export const IssueSection: React.FC<IssueSectionProps> = ({
  connectedAccount,
  onConnectWallet,
}) => {
  const [keyBundle, setKeyBundle] = useState<StoredKeyBundle | null>(null);
  const [copiedFp, setCopiedFp] = useState(false);

  // Form fields
  const [name, setName] = useState('Alice Wonderland');
  const [studentId, setStudentId] = useState('TP-2026-8819');
  const [degree, setDegree] = useState('Bachelor of Science in Computer Science');
  const [grade, setGrade] = useState('First Class Honours');
  const [institution, setInstitution] = useState('University of TrustPass');
  const [issueDate, setIssueDate] = useState('2026-06-15');
  const [expiryDays, setExpiryDays] = useState<string>('0');

  // Status & outputs
  const [isProcessing, setIsProcessing] = useState(false);
  const [statusMsg, setStatusMsg] = useState<{ type: 'info' | 'success' | 'danger'; text: string } | null>(null);
  const [issuedCredential, setIssuedCredential] = useState<string | null>(null);
  const [onChainHash, setOnChainHash] = useState<`0x${string}` | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);

  useEffect(() => {
    const existing = loadStoredIssuerKey();
    if (existing) {
      setKeyBundle(existing);
    }
  }, []);

  const handleGenerateKey = async () => {
    try {
      const bundle = await generateAndStoreIssuerKey();
      setKeyBundle(bundle);
      setStatusMsg({ type: 'success', text: 'New ES256 keypair generated and saved to localStorage.' });
    } catch (err: any) {
      setStatusMsg({ type: 'danger', text: 'Failed to generate key: ' + err.message });
    }
  };

  const handleDownloadKeyBackup = () => {
    if (!keyBundle) return;
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(keyBundle, null, 2));
    const a = document.createElement('a');
    a.href = dataStr;
    a.download = `trustpass_issuer_key_${keyBundle.thumbprintHex.slice(2, 10)}.json`;
    a.click();
  };

  const handleImportKey = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = async (evt) => {
      try {
        const parsed = JSON.parse(evt.target?.result as string);
        if (!parsed.publicKey || !parsed.privateKey) {
          throw new Error('Invalid key backup file format.');
        }
        const bundle = await saveImportedKey(parsed);
        setKeyBundle(bundle);
        setStatusMsg({ type: 'success', text: 'Issuer key backup successfully restored!' });
      } catch (err: any) {
        setStatusMsg({ type: 'danger', text: 'Import error: ' + err.message });
      }
    };
    reader.readAsText(file);
  };

  const handleCopyFingerprint = () => {
    if (!keyBundle) return;
    navigator.clipboard.writeText(keyBundle.thumbprintHex);
    setCopiedFp(true);
    setTimeout(() => setCopiedFp(false), 2000);
  };

  const handleIssueAndAnchor = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!keyBundle) {
      setStatusMsg({ type: 'danger', text: 'Please generate or import an issuer key first.' });
      return;
    }
    if (!connectedAccount) {
      onConnectWallet();
      return;
    }

    setIsProcessing(true);
    setIssuedCredential(null);
    setOnChainHash(null);
    setTxHash(null);
    setStatusMsg({ type: 'info', text: 'Signing SD-JWT VC with in-browser ES256 key...' });

    try {
      // 1. Issue SD-JWT VC with header JWK
      const res = await issueCredential(
        { name, studentId, degree, grade, institution, issueDate },
        keyBundle
      );

      setIssuedCredential(res.credential);
      setOnChainHash(res.onChainHash);

      // 2. Compute expiry timestamp (0 = non-expiring)
      const days = parseInt(expiryDays, 10) || 0;
      const expiryTimestamp = days > 0 ? BigInt(Math.floor(Date.now() / 1000) + days * 86400) : 0n;

      // 3. Anchor commitment hash on-chain via MetaMask
      setStatusMsg({ type: 'info', text: 'Confirm anchoring transaction in MetaMask...' });
      const walletClient = await getWalletClient();
      const hash = await walletClient.writeContract({
        address: CREDENTIAL_ANCHOR_ADDRESS,
        abi: CREDENTIAL_ANCHOR_ABI,
        functionName: 'anchor',
        args: [res.onChainHash, expiryTimestamp],
      });

      setTxHash(hash);
      setStatusMsg({ type: 'info', text: 'Transaction submitted! Awaiting Sepolia confirmation...' });

      await publicClient.waitForTransactionReceipt({ hash });

      setStatusMsg({
        type: 'success',
        text: 'Credential successfully issued, signed, and anchored on Sepolia!',
      });
    } catch (err: any) {
      setStatusMsg({ type: 'danger', text: err.shortMessage || err.message || 'Issuance failed.' });
    } finally {
      setIsProcessing(false);
    }
  };

  const handleDownloadCredential = () => {
    if (!issuedCredential) return;
    const credObj = {
      credentialToken: issuedCredential,
      onChainCommitmentHash: onChainHash,
      issuedAt: new Date().toISOString(),
      claims: { name, studentId, degree, grade, institution, issueDate },
    };
    const dataStr = 'data:text/json;charset=utf-8,' + encodeURIComponent(JSON.stringify(credObj, null, 2));
    const a = document.createElement('a');
    a.href = dataStr;
    a.download = `credential_${studentId}_${Date.now()}.json`;
    a.click();
  };

  return (
    <div className="portal-card">
      <h2 className="card-title">Issue · Selective Disclosure Credential</h2>
      <p className="card-subtitle">
        Generate an in-browser ES256 key pair, sign an SD-JWT VC with the public JWK in the header, and anchor the cryptographic hash on Ethereum Sepolia.
      </p>

      {/* Mandatory Demo Banner */}
      <div className="demo-banner">
        ⚠️ <strong>Demo only:</strong> the issuer key is stored in this browser's <code>localStorage</code>.
      </div>

      {/* Key Management Box */}
      <div style={{ background: '#ffffff', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '1rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.6rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <h3 style={{ fontSize: '0.95rem', fontWeight: 600 }}>Issuer Signing Key (ES256 / P-256)</h3>
          <div className="button-group">
            <button type="button" className="btn btn-secondary" onClick={handleGenerateKey}>
              {keyBundle ? 'Regenerate Key' : 'Generate Key'}
            </button>
            {keyBundle && (
              <>
                <button type="button" className="btn btn-secondary" onClick={handleDownloadKeyBackup}>
                  Download key backup
                </button>
                <label className="btn btn-secondary" style={{ cursor: 'pointer' }}>
                  Import key
                  <input type="file" accept=".json" onChange={handleImportKey} style={{ display: 'none' }} />
                </label>
              </>
            )}
          </div>
        </div>

        {keyBundle ? (
          <div>
            <div style={{ fontSize: '0.8rem', color: 'var(--text-sub)', marginBottom: '0.2rem' }}>
              RFC 7638 JWK Thumbprint (Solidity bytes32 format for Admin registration):
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <div className="code-box" style={{ flex: 1, padding: '0.4rem 0.6rem' }}>
                <code>{keyBundle.thumbprintHex}</code>
              </div>
              <button type="button" className="btn btn-secondary" onClick={handleCopyFingerprint}>
                {copiedFp ? 'Copied!' : 'Copy'}
              </button>
            </div>
          </div>
        ) : (
          <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
            No key found in storage. Click <strong>Generate Key</strong> to initialize an issuer keypair.
          </div>
        )}
      </div>

      {/* Credential Form */}
      <form onSubmit={handleIssueAndAnchor}>
        <div className="form-grid">
          <div className="form-group">
            <label htmlFor="student-name">Student Full Name</label>
            <input
              id="student-name"
              type="text"
              className="form-control"
              value={name}
              onChange={(e) => setName(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="student-id">Student ID</label>
            <input
              id="student-id"
              type="text"
              className="form-control"
              value={studentId}
              onChange={(e) => setStudentId(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="degree-name">Degree Awarded</label>
            <input
              id="degree-name"
              type="text"
              className="form-control"
              value={degree}
              onChange={(e) => setDegree(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="student-grade">Grade / Classification</label>
            <input
              id="student-grade"
              type="text"
              className="form-control"
              value={grade}
              onChange={(e) => setGrade(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="institution-name">Issuing Institution</label>
            <input
              id="institution-name"
              type="text"
              className="form-control"
              value={institution}
              onChange={(e) => setInstitution(e.target.value)}
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="issue-date">Issue Date</label>
            <input
              id="issue-date"
              type="date"
              className="form-control"
              value={issueDate}
              onChange={(e) => setIssueDate(e.target.value)}
              required
            />
          </div>

          <div className="form-group form-full">
            <label htmlFor="expiry-days">Expiry Duration (Days from now, 0 = Non-expiring)</label>
            <input
              id="expiry-days"
              type="number"
              min="0"
              className="form-control"
              value={expiryDays}
              onChange={(e) => setExpiryDays(e.target.value)}
            />
          </div>
        </div>

        <div className="button-group" style={{ marginTop: '0.75rem' }}>
          <button type="submit" className="btn btn-primary" disabled={isProcessing || !keyBundle}>
            {isProcessing ? 'Processing & Anchoring...' : 'Issue & Anchor on Sepolia'}
          </button>
          {!connectedAccount && (
            <span style={{ fontSize: '0.82rem', color: 'var(--text-sub)' }}>
              (MetaMask connection required for issuer anchoring transaction)
            </span>
          )}
        </div>
      </form>

      {/* Transaction status */}
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
                View Anchoring Transaction on Etherscan ↗
              </a>
            </div>
          )}
        </div>
      )}

      {/* Issued Credential Token Display */}
      {issuedCredential && (
        <div style={{ marginTop: '1.5rem', borderTop: '1px solid var(--border-muted)', paddingTop: '1.25rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.4rem' }}>
            Issued SD-JWT VC Commitment
          </h3>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-sub)', marginBottom: '0.4rem' }}>
            On-chain Anchor Commitment Hash (SHA-256): <code>{onChainHash}</code>
          </div>
          <div className="code-box" style={{ marginBottom: '0.75rem' }}>
            {issuedCredential}
          </div>
          <div className="button-group">
            <button type="button" className="btn btn-secondary" onClick={() => navigator.clipboard.writeText(issuedCredential)}>
              Copy Credential Token
            </button>
            <button type="button" className="btn btn-primary" onClick={handleDownloadCredential}>
              Download Credential File (.json)
            </button>
          </div>
        </div>
      )}
    </div>
  );
};
