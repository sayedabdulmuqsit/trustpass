import React, { useState, useRef, useEffect } from 'react';
import QRCode from 'qrcode';
import { createPresentation } from '../crypto';

export const ShareSection: React.FC = () => {
  const [credentialInput, setCredentialInput] = useState('');
  const [fields, setFields] = useState<Record<string, boolean>>({
    name: false,
    studentId: false,
    degree: true,
    grade: false,
    institution: true,
    issueDate: false,
  });

  const [presentationToken, setPresentationToken] = useState<string | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [qrTooLarge, setQrTooLarge] = useState(false);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  const handleToggle = (key: string) => {
    setFields((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault();
    const token = credentialInput.trim();
    if (!token) return;

    setErrorMsg(null);
    setPresentationToken(null);
    setQrTooLarge(false);

    try {
      const pres = await createPresentation(token, fields);
      setPresentationToken(pres);
    } catch (err: any) {
      setErrorMsg(err.message || 'Failed to create selective disclosure presentation.');
    }
  };

  useEffect(() => {
    if (!presentationToken || !canvasRef.current) return;

    // Render QR code
    QRCode.toCanvas(
      canvasRef.current,
      presentationToken,
      {
        width: 256,
        margin: 2,
        errorCorrectionLevel: 'L',
      },
      (err) => {
        if (err) {
          console.warn('QR code generation warning:', err);
          setQrTooLarge(true);
        } else {
          setQrTooLarge(false);
        }
      }
    );
  }, [presentationToken]);

  const handleDownloadPresentation = () => {
    if (!presentationToken) return;
    const blob = new Blob([presentationToken], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `trustpass_presentation_${Date.now()}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="portal-card">
      <h2 className="card-title">Share · Selective Disclosure Presentation</h2>
      <p className="card-subtitle">
        Students control their own data privacy. Choose exactly which credential attributes to disclose to an employer or verifier.
      </p>

      <form onSubmit={handleGenerate}>
        <div className="form-group">
          <label htmlFor="share-cred-input">Paste Full Credential Token</label>
          <textarea
            id="share-cred-input"
            className="form-control"
            placeholder="Paste your issued SD-JWT VC credential here..."
            value={credentialInput}
            onChange={(e) => setCredentialInput(e.target.value)}
            required
            rows={3}
          />
        </div>

        <div style={{ marginBottom: '1.25rem' }}>
          <label style={{ fontSize: '0.88rem', fontWeight: 600, display: 'block', marginBottom: '0.5rem' }}>
            Select Claims to Disclose:
          </label>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: '0.5rem' }}>
            {Object.keys(fields).map((k) => (
              <label
                key={k}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  padding: '0.5rem 0.75rem',
                  border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)',
                  background: fields[k] ? 'var(--primary-blue-light)' : '#ffffff',
                  cursor: 'pointer',
                  fontSize: '0.88rem',
                }}
              >
                <input
                  type="checkbox"
                  checked={fields[k]}
                  onChange={() => handleToggle(k)}
                  style={{ cursor: 'pointer' }}
                />
                <span style={{ fontWeight: fields[k] ? 600 : 400, color: fields[k] ? 'var(--primary-blue)' : 'var(--text-main)' }}>
                  {k}
                </span>
              </label>
            ))}
          </div>
        </div>

        <div className="button-group">
          <button type="submit" className="btn btn-primary" disabled={!credentialInput.trim()}>
            Generate Presentation Token
          </button>
        </div>
      </form>

      {errorMsg && <div className="alert alert-danger" style={{ marginTop: '1rem' }}>{errorMsg}</div>}

      {/* Presentation Output & QR Code */}
      {presentationToken && (
        <div style={{ marginTop: '1.5rem', borderTop: '1px solid var(--border-muted)', paddingTop: '1.25rem' }}>
          <h3 style={{ fontSize: '1rem', fontWeight: 600, marginBottom: '0.4rem' }}>
            Selective Disclosure Presentation Token
          </h3>
          <p style={{ fontSize: '0.82rem', color: 'var(--text-sub)', marginBottom: '0.5rem' }}>
            Only the selected fields are included with their salted disclosures. Remaining fields cannot be seen or reverse-engineered by the verifier.
          </p>

          <div className="code-box" style={{ marginBottom: '0.75rem' }}>
            {presentationToken}
          </div>

          <div className="button-group">
            <button
              type="button"
              className="btn btn-secondary"
              onClick={() => navigator.clipboard.writeText(presentationToken)}
            >
              Copy Presentation Token
            </button>
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleDownloadPresentation}
            >
              Download Presentation (.txt)
            </button>
          </div>

          {/* QR Code Presentation */}
          <div className="qr-container">
            <h4 style={{ fontSize: '0.88rem', fontWeight: 600, marginBottom: '0.5rem' }}>
              Verification QR Code
            </h4>
            <canvas ref={canvasRef} style={{ maxWidth: '100%', height: 'auto' }} />
            {qrTooLarge && (
              <p style={{ fontSize: '0.78rem', color: 'var(--text-sub)', marginTop: '0.5rem' }}>
                Token size exceeds standard QR payload limits; use the text token above instead.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
};
