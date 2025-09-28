import React, { useState, useEffect } from 'react';
import { invoke } from './services/api';
import Login from './pages/Login';
import IdentityManager from './components/IdentityManager';
import DocumentEditor from './components/DocumentEditor';
import MessageCenter from './components/MessageCenter';
import TorStatusMonitor from './components/TorStatusMonitor';
import OnionServiceManager from './components/OnionServiceManager';
import { Identity, Document } from './types';
import './App.css';

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);
  const [currentIdentity, setCurrentIdentity] = useState<Identity | null>(null);
  const [activeTab, setActiveTab] = useState<'messages' | 'documents' | 'tor' | 'network' | 'prayer' | 'moral'>('messages');
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Check authentication status first
    checkAuthenticationStatus();
  }, []);

  const checkAuthenticationStatus = async () => {
    try {
      setIsLoading(true);
      // Check if user is authenticated with login system
      const authenticated = await invoke<boolean>('is_authenticated_cmd');
      setIsAuthenticated(authenticated);

      if (authenticated) {
        // If authenticated, check for existing identity
        await checkExistingIdentity();
      }
    } catch (err) {
      console.log('Authentication check failed:', err);
      setIsAuthenticated(false);
    } finally {
      setIsLoading(false);
    }
  };

  const checkExistingIdentity = async () => {
    try {
      // Check if there's an existing identity in memory
      const identity = await invoke<Identity | null>('get_current_identity');
      setCurrentIdentity(identity);
    } catch (err) {
      console.log('No existing identity found');
    }
  };

  const handleIdentityCreated = (identity: Identity) => {
    setCurrentIdentity(identity);
    setError(null);
  };

  const handleLoginSuccess = () => {
    setIsAuthenticated(true);
    setError(null);
    // Check for existing identity after successful login
    checkExistingIdentity();
  };

  const handleIdentityCleared = () => {
    setCurrentIdentity(null);
    setActiveTab('messages');
  };

  const handleLogout = async () => {
    try {
      await invoke('logout_cmd');
      setIsAuthenticated(false);
      setCurrentIdentity(null);
      setActiveTab('messages');
    } catch (err) {
      console.error('Logout failed:', err);
      handleError('Failed to logout properly');
    }
  };

  const handleError = (errorMessage: string) => {
    setError(errorMessage);
  };

  const clearError = () => {
    setError(null);
  };

  if (isLoading) {
    return (
      <div className="app-loading">
        <div className="loading-spinner"></div>
        <h2 style={{ color: 'var(--color-primary)', fontSize: '1.5rem', fontWeight: 'bold' }}>✝️ Jesus is King</h2>
        <p>Initializing secure environment...</p>
      </div>
    );
  }

  // Show login screen if not authenticated
  if (!isAuthenticated) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div className="app">
      <header className="app-header">
        <div className="flex items-center">
          <h1>Ephemeral Messenger</h1>
          <span className="brand-tagline">✝️ Jesus is King</span>
        </div>
        <div className="header-info">
          {currentIdentity && (
            <span className="identity-info">
              Identity: {currentIdentity.fingerprint.slice(0, 8)}...
            </span>
          )}
          <span className="security-indicator">🔒 Secure</span>
        </div>
      </header>

      {error && (
        <div className="error-banner">
          <span>{error}</span>
          <button onClick={clearError} className="error-close">×</button>
        </div>
      )}

      <main className="app-main">
        {!currentIdentity ? (
          <IdentityManager
            onIdentityCreated={handleIdentityCreated}
            onError={handleError}
          />
        ) : (
          <>
            <nav className="app-nav">
              <button
                className={`nav-button ${activeTab === 'messages' ? 'active' : ''}`}
                onClick={() => setActiveTab('messages')}
              >
                Messages
              </button>
              <button
                className={`nav-button ${activeTab === 'documents' ? 'active' : ''}`}
                onClick={() => setActiveTab('documents')}
              >
                Documents
              </button>
              <button
                className={`nav-button ${activeTab === 'tor' ? 'active' : ''}`}
                onClick={() => setActiveTab('tor')}
              >
                Tor Status
              </button>
              <button
                className={`nav-button ${activeTab === 'network' ? 'active' : ''}`}
                onClick={() => setActiveTab('network')}
              >
                Network
              </button>
              <button
                className={`nav-button ${activeTab === 'prayer' ? 'active' : ''}`}
                onClick={() => setActiveTab('prayer')}
              >
                🙏 Prayer
              </button>
              <button
                className={`nav-button ${activeTab === 'moral' ? 'active' : ''}`}
                onClick={() => setActiveTab('moral')}
              >
                📜 Moral Code
              </button>
              <button
                className="nav-button logout"
                onClick={handleIdentityCleared}
              >
                Clear Identity
              </button>
              <button
                className="nav-button logout"
                onClick={handleLogout}
              >
                Logout
              </button>
            </nav>

            <div className="app-content">
              {activeTab === 'messages' && (
                <MessageCenter
                  identity={currentIdentity}
                  onError={handleError}
                />
              )}
              {activeTab === 'documents' && (
                <DocumentEditor
                  identity={currentIdentity}
                  onError={handleError}
                />
              )}
              {activeTab === 'tor' && (
                <TorStatusMonitor />
              )}
              {activeTab === 'network' && (
                <OnionServiceManager />
              )}
              {activeTab === 'prayer' && (
                <div className="prayer-content">
                  <div className="card">
                    <div className="card-header">
                      <h2>🙏 Prayer Center</h2>
                      <p>Spiritual communication and reflection</p>
                    </div>
                    <div className="card-content">
                      <div className="daily-verse">
                        <p>"For where two or three gather in my name, there am I with them."</p>
                        <div className="verse-reference">— Matthew 18:20</div>
                      </div>
                      <p>Prayer features will be available in the next update. This section will include:</p>
                      <ul>
                        <li>• Daily verses and spiritual guidance</li>
                        <li>• Encrypted prayer tracking</li>
                        <li>• Prayer categories and sessions</li>
                        <li>• Answer tracking and statistics</li>
                      </ul>
                    </div>
                  </div>
                </div>
              )}
              {activeTab === 'moral' && (
                <div className="moral-content">
                  <div className="card">
                    <div className="card-header">
                      <h2>📜 Moral Code of Conduct</h2>
                      <p>Biblical principles for ethical digital communication</p>
                    </div>
                    <div className="card-content">
                      <div className="daily-verse">
                        <p>"Let your light shine before others, that they may see your good deeds and glorify your Father in heaven."</p>
                        <div className="verse-reference">— Matthew 5:16</div>
                      </div>
                      <h3>Core Principles:</h3>
                      <ul>
                        <li>• <strong>Truthfulness:</strong> Speak truth in love, avoiding deception</li>
                        <li>• <strong>Love and Respect:</strong> Treat all persons with dignity</li>
                        <li>• <strong>Confidentiality:</strong> Protect sensitive information</li>
                        <li>• <strong>Purity:</strong> Maintain moral purity in communications</li>
                        <li>• <strong>Wisdom:</strong> Exercise godly wisdom in digital interactions</li>
                        <li>• <strong>Protection:</strong> Defend those who cannot protect themselves</li>
                        <li>• <strong>Stewardship:</strong> Use technology to glorify God</li>
                        <li>• <strong>Reconciliation:</strong> Seek peace and forgiveness</li>
                      </ul>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </>
        )}
      </main>

      <footer className="app-footer">
        <p>
          Zero persistence • Triple encryption • Hardware token ready • Jesus is King ✝️
        </p>
      </footer>
    </div>
  );
}

export default App;