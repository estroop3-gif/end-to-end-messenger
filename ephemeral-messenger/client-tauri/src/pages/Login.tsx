import React, { useState, useEffect } from 'react';
import { invoke } from '../services/api';
import { LoginResponse, HardKeyStatus } from '../types';
import './Login.css';


interface LoginProps {
  onLoginSuccess: () => void;
  initialTab?: 'passphrase' | 'hardkey';
}

const Login: React.FC<LoginProps> = ({ onLoginSuccess, initialTab = 'hardkey' }) => {
  const [activeTab, setActiveTab] = useState<'passphrase' | 'hardkey'>(initialTab);
  const [passphrase, setPassphrase] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hardKeyStatus, setHardKeyStatus] = useState<HardKeyStatus>({ present: false });
  const [showSetup, setShowSetup] = useState(false);

  useEffect(() => {
    if (activeTab === 'hardkey') {
      checkHardKey();
      // Set up periodic checking for hardware key
      const interval = setInterval(checkHardKey, 2000);
      return () => clearInterval(interval);
    }
  }, [activeTab]);

  const checkHardKey = async () => {
    try {
      const status = await invoke('check_hardkey_cmd');
      setHardKeyStatus(status);
    } catch (err) {
      console.error('Failed to check hardware key:', err);
      setHardKeyStatus({ present: false });
    }
  };

  const handlePassphraseLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passphrase.trim()) {
      setError('Please enter your passphrase');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await invoke('verify_local_passphrase_cmd', {
        passphrase: passphrase,
      });

      if (response.ok) {
        onLoginSuccess();
      } else {
        setError(response.error || 'Authentication failed');
      }
    } catch (err) {
      setError(`Login error: ${err}`);
    } finally {
      setLoading(false);
    }
  };

  const handleHardKeyLogin = async () => {
    if (!hardKeyStatus.present) {
      setError('No hardware key detected. Please insert your hardware key.');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await invoke('set_hardkey_mode_cmd');

      if (response.ok) {
        onLoginSuccess();
      } else {
        setError(response.error || 'Hardware key authentication failed');
      }
    } catch (err) {
      setError(`Hardware key error: ${err}`);
    } finally {
      setLoading(false);
    }
  };

  const handleSetupPassphrase = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!passphrase.trim()) {
      setError('Please enter a passphrase');
      return;
    }

    if (passphrase.length < 10) {
      setError('Passphrase must be at least 10 characters long');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await invoke('set_local_passphrase_cmd', {
        passphrase: passphrase,
      });

      if (response.ok) {
        setShowSetup(false);
        onLoginSuccess();
      } else {
        setError(response.error || 'Failed to set passphrase');
      }
    } catch (err) {
      setError(`Setup error: ${err}`);
    } finally {
      setLoading(false);
    }
  };

  if (showSetup) {
    return (
      <div className="login-container">
        <div className="login-card">
          <div className="login-header">
            <h1>🔒 Set Up Local Passphrase</h1>
            <p>Create a passphrase for local-only access</p>
          </div>

          <div className="security-warning">
            <div className="warning-icon">⚠️</div>
            <div className="warning-content">
              <h3>Security Warning</h3>
              <p>Local-only login stores an encrypted credential on this device. This can be a security hazard if the device is seized.</p>
              <ul>
                <li>Your passphrase will be encrypted and stored locally</li>
                <li>Use a strong, unique passphrase</li>
                <li>Consider using a hardware key instead for maximum security</li>
              </ul>
            </div>
          </div>

          {error && (
            <div className="error-message">
              <span>❌ {error}</span>
            </div>
          )}

          <form onSubmit={handleSetupPassphrase} className="login-form">
            <div className="form-group">
              <label htmlFor="setup-passphrase">New Passphrase (minimum 10 characters)</label>
              <input
                id="setup-passphrase"
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Enter a strong passphrase..."
                className="passphrase-input"
                disabled={loading}
                autoFocus
              />
            </div>

            <div className="button-group">
              <button
                type="button"
                onClick={() => setShowSetup(false)}
                className="secondary-button"
                disabled={loading}
              >
                Cancel
              </button>
              <button
                type="submit"
                className="primary-button"
                disabled={loading || passphrase.length < 10}
              >
                {loading ? 'Setting up...' : 'Create Passphrase'}
              </button>
            </div>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <h1>🔑 Ephemeral Messenger</h1>
          <p className="brand-tagline">✝️ Jesus is King</p>
          <p>Please authenticate to continue</p>
        </div>

        <div className="login-tabs">
          <button
            className={`tab-button ${activeTab === 'hardkey' ? 'active' : ''}`}
            onClick={() => setActiveTab('hardkey')}
          >
            🔒 Use Hard Key
          </button>
          <button
            className={`tab-button ${activeTab === 'passphrase' ? 'active' : ''}`}
            onClick={() => setActiveTab('passphrase')}
          >
            🔑 Use Passphrase
          </button>
        </div>

        {error && (
          <div className="error-message">
            <span>❌ {error}</span>
            <button onClick={() => setError(null)} className="error-close">×</button>
          </div>
        )}

        {activeTab === 'hardkey' && (
          <div className="tab-content">
            <div className="hardkey-section">
              <div className="hardkey-status">
                <div className={`status-indicator ${hardKeyStatus.present ? 'connected' : 'disconnected'}`}>
                  {hardKeyStatus.present ? '🟢' : '🔴'}
                </div>
                <div className="status-text">
                  {hardKeyStatus.present ? (
                    <div>
                      <div className="status-title">Hardware Key Detected</div>
                      <div className="status-detail">
                        ID: {hardKeyStatus.fingerprint}
                      </div>
                    </div>
                  ) : (
                    <div>
                      <div className="status-title">No Hardware Key Detected</div>
                      <div className="status-detail">
                        Please insert your hardware key with KEYSTORE/secure_key.json
                      </div>
                    </div>
                  )}
                </div>
              </div>

              <div className="hardkey-instructions">
                <h3>Instructions:</h3>
                <ol>
                  <li>Insert your removable hardware key</li>
                  <li>Ensure it contains <code>KEYSTORE/secure_key.json</code></li>
                  <li>Click "Continue with Hard Key" when detected</li>
                </ol>
              </div>

              <div className="button-group">
                <button
                  onClick={handleHardKeyLogin}
                  className="primary-button"
                  disabled={!hardKeyStatus.present || loading}
                >
                  {loading ? 'Authenticating...' : 'Continue with Hard Key'}
                </button>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'passphrase' && (
          <div className="tab-content">
            <div className="security-warning">
              <div className="warning-icon">⚠️</div>
              <div className="warning-content">
                <h3>Security Notice</h3>
                <p>Local-only login stores an encrypted credential on this device. This can be a security hazard if the device is seized. Use a strong passphrase or prefer Hard Key authentication.</p>
              </div>
            </div>

            <form onSubmit={handlePassphraseLogin} className="login-form">
              <div className="form-group">
                <label htmlFor="passphrase">Master Passphrase</label>
                <input
                  id="passphrase"
                  type="password"
                  value={passphrase}
                  onChange={(e) => setPassphrase(e.target.value)}
                  placeholder="Enter your passphrase..."
                  className="passphrase-input"
                  disabled={loading}
                  autoFocus
                />
              </div>

              <div className="button-group">
                <button
                  type="submit"
                  className="primary-button"
                  disabled={!passphrase.trim() || loading}
                >
                  {loading ? 'Unlocking...' : 'Unlock'}
                </button>
              </div>
            </form>

            <div className="setup-link">
              <p>Don't have a passphrase set up?</p>
              <button
                onClick={() => setShowSetup(true)}
                className="link-button"
                disabled={loading}
              >
                Set up local passphrase
              </button>
            </div>
          </div>
        )}

        <div className="login-footer">
          <p>
            🔒 Zero persistence • Triple encryption • Hardware token ready
          </p>
          <p className="login-tagline">
            ✝️ Jesus is King
          </p>
        </div>
      </div>
    </div>
  );
};

export default Login;