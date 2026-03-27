import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { ethers } from 'ethers';

const CONTRACT_ADDRESSES = {
  CAPABILITY_NFT: process.env.REACT_APP_CAPABILITY_NFT_ADDRESS || '0x0000000000000000000000000000000000000000',
  AGENT_AUTH: process.env.REACT_APP_AGENT_AUTH_ADDRESS || '0x0000000000000000000000000000000000000000',
};

const ABI = {
  CAPABILITY_NFT: [
    'function balanceOf(address owner) view returns (uint256)',
    'function tokenOfOwnerByIndex(address owner, uint256 index) view returns (uint256)',
    'function tokenURI(uint256 tokenId) view returns (string)',
    'function name() view returns (string)',
    'function symbol() view returns (string)',
    'function mintCapability(address to, string memory capabilityType, uint256 limit) returns (uint256)',
    'function ownerOf(uint256 tokenId) view returns (address)',
    'function getCapabilityDetails(uint256 tokenId) view returns (string, uint256, uint256, bool)',
  ],
  AGENT_AUTH: [
    'function getAgentCapabilities(address agent) view returns (uint256[] memory)',
    'function getCapabilityOwner(uint256 tokenId) view returns (address)',
    'function getTransactionHistory(address user) view returns (tuple(address, string, uint256, uint256)[] memory)',
    'function getActiveCapabilities(address user) view returns (tuple(uint256, string, uint256, bool)[] memory)',
  ],
};

const CAPABILITY_TYPES = {
  TRADE: 'Trade',
  TRANSFER: 'Transfer',
  DEPLOY: 'Deploy',
  EXECUTE: 'Execute',
  GOVERN: 'Govern',
};

const CAPABILITY_LIMITS = [1000, 5000, 10000, 50000, 100000];

const formatAddress = (addr) => {
  if (!addr) return '0x...';
  return `${addr.slice(0, 6)}...${addr.slice(-4)}`;
};

const formatTimestamp = (ts) => {
  return new Date(Number(ts) * 1000).toLocaleString();
};

const formatGas = (gas) => {
  return `${(Number(gas) / 1e9).toFixed(2)} Gwei`;
};

const useWallet = () => {
  const [account, setAccount] = useState(null);
  const [provider, setProvider] = useState(null);
  const [signer, setSigner] = useState(null);
  const [chainId, setChainId] = useState(null);
  const [error, setError] = useState(null);

  const connect = useCallback(async () => {
    if (typeof window.ethereum === 'undefined') {
      setError('MetaMask not found. Please install it.');
      return false;
    }

    try {
      const web3Provider = new ethers.BrowserProvider(window.ethereum);
      const accounts = await web3Provider.send('eth_requestAccounts', []);
      const providerInstance = web3Provider;
      const signerInstance = await providerInstance.getSigner();
      const network = await providerInstance.getNetwork();

      setProvider(providerInstance);
      setSigner(signerInstance);
      setAccount(accounts[0]);
      setChainId(Number(network.chainId));
      setError(null);
      return true;
    } catch (err) {
      setError(err.message || 'Connection failed');
      return false;
    }
  }, []);

  const disconnect = useCallback(() => {
    setAccount(null);
    setProvider(null);
    setSigner(null);
    setChainId(null);
    setError(null);
  }, []);

  useEffect(() => {
    if (typeof window.ethereum !== 'undefined') {
      window.ethereum.on('accountsChanged', (accounts) => {
        if (accounts.length > 0) {
          setAccount(accounts[0]);
        } else {
          disconnect();
        }
      });

      window.ethereum.on('chainChanged', (chainId) => {
        window.location.reload();
      });

      window.ethereum.on('networkChanged', (chainId) => {
        window.location.reload();
      });

      return () => {
        window.ethereum.removeAllListeners('accountsChanged');
        window.ethereum.removeAllListeners('chainChanged');
        window.ethereum.removeAllListeners('networkChanged');
      };
    }
  }, [disconnect]);

  return { account, provider, signer, chainId, error, connect, disconnect };
};

const useCapabilities = (account, provider, contractAddress, abi) => {
  const [capabilities, setCapabilities] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const loadCapabilities = useCallback(async () => {
    if (!account || !provider || !contractAddress) return;

    setLoading(true);
    setError(null);

    try {
      const contract = new ethers.Contract(contractAddress, abi, provider);
      const balance = await contract.balanceOf(account);
      const capList = [];

      for (let i = 0; i < Number(balance); i++) {
        const tokenId = await contract.tokenOfOwnerByIndex(account, i);
        const details = await contract.getCapabilityDetails(tokenId);
        const tokenUri = await contract.tokenURI(tokenId);

        capList.push({
          tokenId: tokenId.toString(),
          type: details[0],
          limit: Number(details[1]),
          currentUsage: Number(details[2]),
          isActive: details[3],
          uri: tokenUri,
        });
      }

      setCapabilities(capList);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [account, provider, contractAddress, abi]);

  useEffect(() => {
    loadCapabilities();
  }, [loadCapabilities]);

  return { capabilities, loading, error, loadCapabilities };
};

const useTransactionHistory = (account, provider, contractAddress, abi) => {
  const [history, setHistory] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const loadHistory = useCallback(async () => {
    if (!account || !provider || !contractAddress) return;

    setLoading(true);
    setError(null);

    try {
      const contract = new ethers.Contract(contractAddress, abi, provider);
      const txs = await contract.getTransactionHistory(account);

      const formatted = txs.map((tx) => ({
        from: tx[0],
        action: tx[1],
        amount: Number(tx[2]),
        timestamp: Number(tx[3]),
      }));

      setHistory(formatted);
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }, [account, provider, contractAddress, abi]);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  return { history, loading, error, loadHistory };
};

const CapabilityCard = ({ capability, onRevoke }) => {
  const progress = Math.min((Number(capability.currentUsage) / Number(capability.limit)) * 100, 100);

  return (
    <div className="capability-card">
      <div className="capability-header">
        <span className="capability-type">{capability.type}</span>
        <span className={`status ${capability.isActive ? 'active' : 'revoked'}`}>
          {capability.isActive ? 'Active' : 'Revoked'}
        </span>
      </div>
      <div className="capability-details">
        <div className="detail-row">
          <span className="label">Token ID:</span>
          <span className="value">#{capability.tokenId}</span>
        </div>
        <div className="detail-row">
          <span className="label">Limit:</span>
          <span className="value">{Number(capability.limit).toLocaleString()}</span>
        </div>
        <div className="detail-row">
          <span className="label">Used:</span>
          <span className="value">{Number(capability.currentUsage).toLocaleString()}</span>
        </div>
        <div className="progress-bar">
          <div className="progress-fill" style={{ width: `${progress}%` }}></div>
        </div>
      </div>
      <div className="capability-actions">
        <button className="btn-revoke" onClick={() => onRevoke(capability.tokenId)} disabled={!capability.isActive}>
          Revoke
        </button>
      </div>
    </div>
  );
};

const MintCapabilityForm = ({ provider, signer, contractAddress, abi, onMint }) => {
  const [type, setType] = useState(CAPABILITY_TYPES.TRANSFER);
  const [limit, setLimit] = useState(10000);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(false);

  const handleMint = async () => {
    if (!provider || !signer || !contractAddress) {
      setError('Wallet not connected');
      return;
    }

    setLoading(true);
    setError(null);
    setSuccess(false);

    try {
      const contract = new ethers.Contract(contractAddress, abi, signer);
      const tx = await contract.mintCapability(
        await signer.getAddress(),
        type,
        limit
      );
      await tx.wait();
      setSuccess(true);
      onMint();
    } catch (err) {
      setError(err.message || 'Mint failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="mint-form">
      <h3>Mint New Capability</h3>
      <div className="form-group">
        <label>Capability Type</label>
        <select value={type} onChange={(e) => setType(e.target.value)}>
          {Object.entries(CAPABILITY_TYPES).map(([key, value]) => (
            <option key={key} value={value}>
              {value}
            </option>
          ))}
        </select>
      </div>
      <div className="form-group">
        <label>Execution Limit</label>
        <select value={limit} onChange={(e) => setLimit(Number(e.target.value))}>
          {CAPABILITY_LIMITS.map((l) => (
            <option key={l} value={l}>
              {l.toLocaleString()}
            </option>
          ))}
        </select>
      </div>
      {error && <div className="error-message">{error}</div>}
      {success && <div className="success-message">Capability minted successfully!</div>}
      <button className="btn-mint" onClick={handleMint} disabled={loading}>
        {loading ? 'Minting...' : 'Mint Capability'}
      </button>
    </div>
  );
};

const TransactionHistory = ({ history, loading }) => {
  if (loading) return <div className="loading">Loading history...</div>;

  if (history.length === 0) return <div className="empty-state">No transactions yet</div>;

  return (
    <div className="transaction-list">
      <h3>Transaction History</h3>
      {history.slice(0, 10).map((tx, idx) => (
        <div key={idx} className="transaction-item">
          <div className="tx-action">{tx.action}</div>
          <div className="tx-amount">{Number(tx.amount).toLocaleString()}</div>
          <div className="tx-time">{formatTimestamp(tx.timestamp)}</div>
        </div>
      ))}
    </div>
  );
};

const NetworkStatus = ({ chainId }) => {
  const networks = {
    1: 'Ethereum Mainnet',
    5: 'Goerli Testnet',
    11155111: 'Sepolia Testnet',
    137: 'Polygon',
    8453: 'Base',
  };

  return (
    <div className="network-status">
      <span className="status-indicator {chainId ? 'connected' : 'disconnected'}"></span>
      <span>{networks[chainId] || 'Unknown Network'}</span>
    </div>
  );
};

const Dashboard = () => {
  const { account, provider, signer, chainId, error: walletError, connect, disconnect } = useWallet();
  const { capabilities, loading: capsLoading, error: capsError, loadCapabilities } = useCapabilities(
    account,
    provider,
    CONTRACT_ADDRESSES.CAPABILITY_NFT,
    ABI.CAPABILITY_NFT
  );
  const { history, loading: txLoading, error: txError, loadHistory } = useTransactionHistory(
    account,
    provider,
    CONTRACT_ADDRESSES.AGENT_AUTH,
    ABI.AGENT_AUTH
  );

  const handleRevoke = useCallback(async (tokenId) => {
    if (!signer || !CONTRACT_ADDRESSES.CAPABILITY_NFT) return;

    try {
      const contract = new ethers.Contract(CONTRACT_ADDRESSES.CAPABILITY_NFT, ABI.CAPABILITY_NFT, signer);
      const tx = await contract.revokeCapability(tokenId);
      await tx.wait();
      loadCapabilities();
    } catch (err) {
      console.error('Revoke failed:', err);
    }
  }, [signer, loadCapabilities]);

  const handleMint = useCallback(() => {
    loadCapabilities();
    loadHistory();
  }, [loadCapabilities, loadHistory]);

  const activeCapabilities = useMemo(() => capabilities.filter((c) => c.isActive), [capabilities]);

  return (
    <div className="dashboard">
      <header className="dashboard-header">
        <h1>CapAgent Dashboard</h1>
        <NetworkStatus chainId={chainId} />
        <div className="wallet-section">
          {account ? (
            <div className="wallet-info">
              <span className="wallet-address">{formatAddress(account)}</span>
              <button className="btn-disconnect" onClick={disconnect}>Disconnect</button>
            </div>
          ) : (
            <button className="btn-connect" onClick={connect}>
              Connect Wallet
            </button>
          )}
        </div>
      </header>

      {walletError && <div className="error-banner">{walletError}</div>}
      {capsError && <div className="error-banner">Capabilities Error: {capsError}</div>}
      {txError && <div className="error-banner">History Error: {txError}</div>}

      <main className="dashboard-main">
        <section className="capabilities-section">
          <div className="section-header">
            <h2>Active Capabilities</h2>
            <button className="btn-refresh" onClick={loadCapabilities} disabled={capsLoading}>
              {capsLoading ? 'Loading...' : 'Refresh'}
            </button>
          </div>
          <div className="capabilities-grid">
            {activeCapabilities.length === 0 ? (
              <div className="empty-state">No active capabilities. Mint one to get started.</div>
            ) : (
              activeCapabilities.map((cap) => (
                <CapabilityCard key={cap.tokenId} capability={cap} onRevoke={handleRevoke} />
              ))
            )}
          </div>
        </section>

        <section className="mint-section">
          <MintCapabilityForm
            provider={provider}
            signer={signer}
            contractAddress={CONTRACT_ADDRESSES.CAPABILITY_NFT}
            abi={ABI.CAPABILITY_NFT}
            onMint={handleMint}
          />
        </section>

        <section className="history-section">
          <TransactionHistory history={history} loading={txLoading} />
        </section>
      </main>

      <footer className="dashboard-footer">
        <p>CapAgent v1.0 | Capability-Based Authorization for AI Agents</p>
        <p className="contract-info">
          NFT: {formatAddress(CONTRACT_ADDRESSES.CAPABILITY_NFT)} | Auth: {formatAddress(CONTRACT_ADDRESSES.AGENT_AUTH)}
        </p>
      </footer>
    </div>
  );
};

export default Dashboard;

const styles = `
.dashboard {
  min-height: 100vh;
  background: linear-gradient(135deg, #0f0f1a 0%, #1a1a2e 100%);
  color: #e0e0e0;
  font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
}

.dashboard-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1.5rem 2rem;
  border-bottom: 1px solid rgba(255, 255, 255, 0.1);
}

.dashboard-header h1 {
  font-size: 1.75rem;
  font-weight: 700;
  background: linear-gradient(90deg, #00d4ff, #7c3aed);
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  background-clip: text;
}

.network-status {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  padding: 0.5rem 1rem;
  background: rgba(0, 212, 255, 0.1);
  border-radius: 8px;
  font-size: 0.875rem;
}

.status-indicator {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: #00d4ff;
}

.status-indicator.disconnected {
  background: #ef4444;
}

.wallet-section {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.wallet-info {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.wallet-address {
  font-family: 'Monaco', monospace;
  font-size: 0.875rem;
  color: #00d4ff;
}

.btn-connect,
.btn-disconnect,
.btn-mint,
.btn-revoke,
.btn-refresh {
  padding: 0.625rem 1.25rem;
  border-radius: 8px;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.2s;
  border: none;
}

.btn-connect {
  background: linear-gradient(90deg, #00d4ff, #7c3aed);
  color: white;
}

.btn-connect:hover {
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0, 212, 255, 0.3);
}

.btn-disconnect {
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
  border: 1px solid rgba(239, 68, 68, 0.3);
}

.btn-mint {
  background: linear-gradient(90deg, #10b981, #059669);
  color: white;
  width: 100%;
  margin-top: 1rem;
}

.btn-revoke {
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
  border: 1px solid rgba(239, 68, 68, 0.3);
}

.btn-revoke:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.btn-refresh {
  background: rgba(124, 58, 237, 0.1);
  color: #7c3aed;
  border: 1px solid rgba(124, 58, 237, 0.3);
}

.dashboard-main {
  padding: 2rem;
  display: grid;
  gap: 2rem;
  max-width: 1400px;
  margin: 0 auto;
}

.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.section-header h2 {
  font-size: 1.25rem;
  font-weight: 600;
  color: #e0e0e0;
}

.capabilities-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 1.5rem;
}

.capability-card {
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 12px;
  padding: 1.5rem;
  transition: all 0.2s;
}

.capability-card:hover {
  border-color: rgba(0, 212, 255, 0.3);
  transform: translateY(-2px);
}

.capability-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 1rem;
}

.capability-type {
  font-weight: 700;
  font-size: 1.125rem;
  color: #00d4ff;
}

.status {
  padding: 0.25rem 0.75rem;
  border-radius: 20px;
  font-size: 0.75rem;
  font-weight: 600;
}

.status.active {
  background: rgba(16, 185, 129, 0.1);
  color: #10b981;
}

.status.revoked {
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
}

.capability-details {
  margin-bottom: 1rem;
}

.detail-row {
  display: flex;
  justify-content: space-between;
  margin-bottom: 0.5rem;
  font-size: 0.875rem;
}

.detail-row .label {
  color: #888;
}

.detail-row .value {
  color: #e0e0e0;
  font-family: 'Monaco', monospace;
}

.progress-bar {
  height: 6px;
  background: rgba(255, 255, 255, 0.1);
  border-radius: 3px;
  overflow: hidden;
  margin-top: 0.75rem;
}

.progress-fill {
  height: 100%;
  background: linear-gradient(90deg, #00d4ff, #7c3aed);
  border-radius: 3px;
  transition: width 0.3s;
}

.capability-actions {
  display: flex;
  justify-content: flex-end;
}

.mint-form {
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 12px;
  padding: 1.5rem;
}

.mint-form h3 {
  margin: 0 0 1rem 0;
  font-size: 1.125rem;
  font-weight: 600;
}

.form-group {
  margin-bottom: 1rem;
}

.form-group label {
  display: block;
  margin-bottom: 0.5rem;
  font-size: 0.875rem;
  color: #888;
}

.form-group select {
  width: 100%;
  padding: 0.75rem;
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 8px;
  color: #e0e0e0;
  font-size: 0.875rem;
}

.form-group select:focus {
  outline: none;
  border-color: #00d4ff;
}

.error-message,
.success-message {
  padding: 0.75rem;
  border-radius: 8px;
  margin-bottom: 1rem;
  font-size: 0.875rem;
}

.error-message {
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
}

.success-message {
  background: rgba(16, 185, 129, 0.1);
  color: #10b981;
}

.transaction-list {
  background: rgba(255, 255, 255, 0.05);
  border: 1px solid rgba(255, 255, 255, 0.1);
  border-radius: 12px;
  padding: 1.5rem;
}

.transaction-list h3 {
  margin: 0 0 1rem 0;
  font-size: 1.125rem;
  font-weight: 600;
}

.transaction-item {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 0.75rem 0;
  border-bottom: 1px solid rgba(255, 255, 255, 0.05);
}

.transaction-item:last-child {
  border-bottom: none;
}

.tx-action {
  font-weight: 600;
  color: #00d4ff;
}

.tx-amount {
  font-family: 'Monaco', monospace;
  color: #e0e0e0;
}

.tx-time {
  color: #888;
  font-size: 0.875rem;
}

.empty-state {
  text-align: center;
  padding: 3rem;
  color: #888;
  font-size: 0.875rem;
}

.loading {
  text-align: center;
  padding: 2rem;
  color: #888;
}

.error-banner {
  background: rgba(239, 68, 68, 0.1);
  color: #ef4444;
  padding: 1rem;
  border-radius: 8px;
  margin-bottom: 1rem;
  text-align: center;
}

.dashboard-footer {
  padding: 2rem;
  text-align: center;
  border-top: 1px solid rgba(255, 255, 255, 0.1);
  color: #888;
  font-size: 0.875rem;
}

.contract-info {
  margin-top: 0.5rem;
  font-family: 'Monaco', monospace;
  font-size: 0.75rem;
}

@media (max-width: 768px) {
  .dashboard-header {
    flex-direction: column;
    gap: 1rem;
  }

  .dashboard-main {
    padding: 1rem;
  }

  .capabilities-grid {
    grid-template-columns: 1fr;
  }

  .transaction-item {
    flex-direction: column;
    align-items: flex-start;
    gap: 0.5rem;
  }
}
`;

const styleSheet = document.createElement('style');
styleSheet.innerText = styles;
document.head.appendChild(styleSheet);
