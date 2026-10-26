import React, { useState, useEffect } from 'react';
import type { Address } from 'viem';
import {
  getWalletClient,
  ISSUER_REGISTRY_ADDRESS,
  CREDENTIAL_ANCHOR_ADDRESS,
} from './contracts';

import { AdminSection } from './components/AdminSection';
import { IssueSection } from './components/IssueSection';
import { VerifySection } from './components/VerifySection';
import { ShareSection } from './components/ShareSection';
import { RevokeSection } from './components/RevokeSection';

type ActiveTab = 'admin' | 'issue' | 'verify' | 'share' | 'revoke';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<ActiveTab>('admin');
  const [connectedAccount, setConnectedAccount] = useState<Address | null>(null);
  const [isConnecting, setIsConnecting] = useState(false);

  // Check if wallet is already connected
  useEffect(() => {
    if (typeof window !== 'undefined' && (window as any).ethereum) {
      const ethereum = (window as any).ethereum;
      ethereum
        .request({ method: 'eth_accounts' })
        .then((accounts: string[]) => {
          if (accounts && accounts[0]) {
            setConnectedAccount(accounts[0] as Address);
          }
        })
        .catch(() => {});

      const handleAccountsChanged = (accounts: string[]) => {
        if (accounts && accounts[0]) {
          setConnectedAccount(accounts[0] as Address);
        } else {
          setConnectedAccount(null);
        }
      };

      ethereum.on('accountsChanged', handleAccountsChanged);
      return () => {
        ethereum.removeListener('accountsChanged', handleAccountsChanged);
      };
    }
  }, []);

  const handleConnectWallet = async () => {
    setIsConnecting(true);
    try {
      const walletClient = await getWalletClient();
      setConnectedAccount(walletClient.account.address);
    } catch (err: any) {
      console.error('Wallet connection error:', err);
      alert(err.message || 'Failed to connect MetaMask.');
    } finally {
      setIsConnecting(false);
    }
  };

  return (
    <div className="portal-container">
      {/* Header */}
      <header className="portal-header">
        <div className="portal-title-group">
          <h1>🛡️ TrustPass Protocol</h1>
          <p>Decentralized Multi-Issuer Credential Network · Ethereum Sepolia</p>
          <div className="contract-links">
            <span>Contracts:</span>
            <a
              href={`https://sepolia.etherscan.io/address/${ISSUER_REGISTRY_ADDRESS}`}
              target="_blank"
              rel="noreferrer"
            >
              Registry ({ISSUER_REGISTRY_ADDRESS.slice(0, 6)}...{ISSUER_REGISTRY_ADDRESS.slice(-4)}) ↗
            </a>
            <span>·</span>
            <a
              href={`https://sepolia.etherscan.io/address/${CREDENTIAL_ANCHOR_ADDRESS}`}
              target="_blank"
              rel="noreferrer"
            >
              Anchor ({CREDENTIAL_ANCHOR_ADDRESS.slice(0, 6)}...{CREDENTIAL_ANCHOR_ADDRESS.slice(-4)}) ↗
            </a>
          </div>
        </div>

        <div className="header-status-group">
          {connectedAccount ? (
            <div className="wallet-badge">
              ● Sepolia · {connectedAccount.slice(0, 6)}...{connectedAccount.slice(-4)}
            </div>
          ) : (
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleConnectWallet}
              disabled={isConnecting}
            >
              {isConnecting ? 'Connecting...' : 'Connect MetaMask'}
            </button>
          )}
        </div>
      </header>

      {/* Navigation Tabs */}
      <nav className="portal-tabs">
        <button
          type="button"
          className={`tab-btn ${activeTab === 'admin' ? 'active' : ''}`}
          onClick={() => setActiveTab('admin')}
        >
          Admin
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'issue' ? 'active' : ''}`}
          onClick={() => setActiveTab('issue')}
        >
          Issue
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'verify' ? 'active' : ''}`}
          onClick={() => setActiveTab('verify')}
        >
          Verify
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'share' ? 'active' : ''}`}
          onClick={() => setActiveTab('share')}
        >
          Share
        </button>
        <button
          type="button"
          className={`tab-btn ${activeTab === 'revoke' ? 'active' : ''}`}
          onClick={() => setActiveTab('revoke')}
        >
          Revoke
        </button>
      </nav>

      {/* Active Tab Section */}
      <main>
        {activeTab === 'admin' && (
          <AdminSection
            connectedAccount={connectedAccount}
            onConnectWallet={handleConnectWallet}
          />
        )}

        {activeTab === 'issue' && (
          <IssueSection
            connectedAccount={connectedAccount}
            onConnectWallet={handleConnectWallet}
          />
        )}

        {activeTab === 'verify' && <VerifySection />}

        {activeTab === 'share' && <ShareSection />}

        {activeTab === 'revoke' && (
          <RevokeSection
            connectedAccount={connectedAccount}
            onConnectWallet={handleConnectWallet}
          />
        )}
      </main>
    </div>
  );
};

export default App;
