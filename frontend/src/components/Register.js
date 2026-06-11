import React, { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import { generateKeyPair, exportPublicKey, exportPrivateKey, getKeyFingerprint } from '../utils/crypto';
import { storeKeyPair } from '../utils/keyStorage';
import { keyAPI } from '../services/api';
import './Auth.css';

const Register = () => {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [algorithm, setAlgorithm] = useState('RSA_2048');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState('');

  const { register } = useAuth();
  const { isDarkMode, toggleTheme } = useTheme();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');
    setStatus('');

    if (username.length < 3) {
      setError('Username must be at least 3 characters');
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    if (password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setLoading(true);

    try {
      setStatus('Registering user...');
      const result = await register(username, password);

      if (!result.success) {
        setError(result.message || 'Registration failed');
        setLoading(false);
        return;
      }

      setStatus(`Generating ${algorithm} keys...`);
      const keyPair = await generateKeyPair(algorithm);

      setStatus('Exporting keys...');
      const publicKeyJWK = await exportPublicKey(keyPair.publicKey);
      const privateKeyJWK = await exportPrivateKey(keyPair.privateKey);

      setStatus('Calculating fingerprint...');
      const fingerprint = await getKeyFingerprint(keyPair.publicKey);

      setStatus('Storing private key locally...');
      await storeKeyPair(result.user.id, privateKeyJWK, publicKeyJWK, algorithm);

      setStatus('Uploading public key...');
      await keyAPI.uploadPublicKey(publicKeyJWK, algorithm, fingerprint);

      setStatus('Complete!');
      setTimeout(() => navigate('/dashboard'), 500);

    } catch (error) {
      console.error('Registration error:', error);
      setError(error.message || 'Failed to complete registration');
      setLoading(false);
    }
  };

  return (
    <div className="auth-container">
      <button className="theme-toggle-auth" onClick={toggleTheme} title={isDarkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}>
        {isDarkMode ? '☀️' : '🌙'}
      </button>
      <div className="auth-card">
        <h2>Create Account</h2>
        <p className="auth-subtitle">Register for secure E2EE messaging</p>

        {error && <div className="error-message">{error}</div>}
        {status && <div className="info-message">{status}</div>}

        <form onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              type="text"
              id="username"
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="Enter username"
              required
              minLength={3}
              maxLength={30}
            />
          </div>

          <div className="form-group">
            <label htmlFor="password">Password</label>
            <input
              type="password"
              id="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder="Enter password"
              required
              minLength={8}
            />
          </div>

          <div className="form-group">
            <label htmlFor="confirmPassword">Confirm Password</label>
            <input
              type="password"
              id="confirmPassword"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              placeholder="Confirm password"
              required
              minLength={8}
            />
          </div>

          <div className="form-group">
            <label htmlFor="algorithm">Encryption Algorithm</label>
            <select
              id="algorithm"
              value={algorithm}
              onChange={(e) => setAlgorithm(e.target.value)}
              disabled={loading}
            >
              <option value="RSA_2048">RSA-2048 (Recommended)</option>
              <option value="RSA_3072">RSA-3072 (More Secure)</option>
              <option value="ECC_P256">ECC P-256 (Compact)</option>
              <option value="ECC_P384">ECC P-384 (Balanced)</option>
            </select>
            <small className="form-hint">Choose encryption algorithm for your keys</small>
          </div>

          <button
            type="submit"
            className="auth-button"
            disabled={loading}
          >
            {loading ? 'Creating Account...' : 'Register'}
          </button>
        </form>

        <p className="auth-link">
          Already have an account? <Link to="/login">Login here</Link>
        </p>
      </div>
    </div>
  );
};

export default Register;
