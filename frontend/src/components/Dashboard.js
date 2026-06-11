import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { hasKeyPair, getKeyPair, storeKeyPair } from '../utils/keyStorage';
import { keyAPI } from '../services/api';
import { generateKeyPair, exportPublicKey, exportPrivateKey, getKeyFingerprint } from '../utils/crypto';
import AppHeader from './AppHeader';
import socketService from '../services/socket';
import './Dashboard.css';

const Dashboard = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const [keyInfo, setKeyInfo] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadKeyInfo();
    // eslint-disable-next-line
  }, [user]);

  const loadKeyInfo = async () => {
    if (!user?.id) return;

    try {
      const hasKeys = await hasKeyPair(user.id);

      if (hasKeys) {
        const localKeys = await getKeyPair(user.id);
        const serverInfo = await keyAPI.getMyKeyInfo();

        setKeyInfo({
          hasKeys: true,
          algorithm: localKeys.algorithm,
          keyFingerprint: serverInfo.data.keyFingerprint,
          createdAt: localKeys.createdAt
        });
      } else {
        setKeyInfo({ hasKeys: false });
      }
    } catch (error) {
      console.error('Failed to load key info:', error);
      setKeyInfo({ hasKeys: false });
    } finally {
      setLoading(false);
    }
  };

  const handleLogout = () => {
    socketService.disconnect();
    logout();
    navigate('/login');
  };

  const handleGenerateKeys = async () => {
    setLoading(true);
    try {
      const algorithm = 'RSA_2048';

      const keyPair = await generateKeyPair(algorithm);

      const publicKeyJWK = await exportPublicKey(keyPair.publicKey);
      const privateKeyJWK = await exportPrivateKey(keyPair.privateKey);
      const fingerprint = await getKeyFingerprint(keyPair.publicKey);

      // Store in IndexedDB
      await storeKeyPair(user.id, privateKeyJWK, publicKeyJWK, algorithm);

      // Upload public key to server
      await keyAPI.uploadPublicKey(publicKeyJWK, algorithm, fingerprint);

      // Reload key info
      await loadKeyInfo();

      alert('Encryption keys generated successfully!');
    } catch (error) {
      console.error('Failed to generate keys:', error);
      alert('Failed to generate encryption keys. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="dashboard-container">
      <AppHeader showBack={false} onLogout={handleLogout} />

      <div className="dashboard-content">
        <div className="info-card">
          <h3>Authentication Status</h3>
          <p>You are logged in with secure bcrypt password hashing.</p>
          <div className="user-details">
            <p><strong>User ID:</strong> {user?.id}</p>
            <p><strong>Username:</strong> {user?.username}</p>
          </div>
        </div>

        <div className="info-card">
          <h3>Encryption Keys</h3>
          {loading ? (
            <p>Loading key information...</p>
          ) : keyInfo?.hasKeys ? (
            <div>
              <div className="key-status-success">
                <p>Encryption keys active and secure</p>
              </div>
              <div className="user-details">
                <p><strong>Algorithm:</strong> {keyInfo.algorithm}</p>
                <p><strong>Private Key:</strong> Stored in IndexedDB (never sent to server)</p>
                <p><strong>Public Key:</strong> Uploaded to server</p>
                {keyInfo.keyFingerprint && (
                  <p><strong>Fingerprint:</strong> <code>{keyInfo.keyFingerprint.substring(0, 16)}...</code></p>
                )}
                <p><strong>Created:</strong> {new Date(keyInfo.createdAt).toLocaleString()}</p>
              </div>
            </div>
          ) : (
            <div>
              <div className="key-status-warning">
                <p>No encryption keys found</p>
              </div>
              <button
                onClick={handleGenerateKeys}
                className="action-button"
                disabled={loading}
                style={{ marginTop: '20px' }}
              >
                🔑 Generate Encryption Keys
              </button>
              <p className="key-generation-hint">
                Keys are required for end-to-end encrypted messaging
              </p>
            </div>
          )}
        </div>

        <div className="info-card">
          <h3>Quick Actions</h3>
          <button
            onClick={() => navigate('/chat')}
            className="action-button"
            disabled={!keyInfo?.hasKeys}
          >
            💬 Open Secure Chat
          </button>
          {!keyInfo?.hasKeys && (
            <p className="action-hint">Generate encryption keys first to use chat</p>
          )}
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
