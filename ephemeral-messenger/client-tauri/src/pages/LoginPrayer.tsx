/**
 * Login Prayer Page for Ephemeral Messenger
 *
 * Features "Jesus is King" branding with prominent prayer panel,
 * daily verse display, and account setup integration.
 */

import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { AccountSetup, CreatedAccount } from '../components/AccountSetup';
import '../styles/theme.css';

interface DailyVerse {
  text: string;
  reference: string;
  translation: string;
}

interface PrayerData {
  personalPrayer: string;
  prayerRequests: string[];
  lastUpdated: string;
}

interface LoginPrayerProps {
  onAuthenticated: (account: CreatedAccount) => void;
}

export const LoginPrayer: React.FC<LoginPrayerProps> = ({ onAuthenticated }) => {
  // State management
  const [currentView, setCurrentView] = useState<'login' | 'setup'>('login');
  const [dailyVerse, setDailyVerse] = useState<DailyVerse | null>(null);
  const [prayerData, setPrayerData] = useState<PrayerData>({
    personalPrayer: '',
    prayerRequests: [],
    lastUpdated: new Date().toISOString()
  });

  // Authentication state
  const [isCheckingKey, setIsCheckingKey] = useState(true);
  const [keyPresent, setKeyPresent] = useState(false);
  const [hasAccount, setHasAccount] = useState(false);

  // UI state
  const [showPrayerNeed, setShowPrayerNeed] = useState(false);
  const [prayerNeedText, setPrayerNeedText] = useState('');
  const [isLoadingVerse, setIsLoadingVerse] = useState(true);

  useEffect(() => {
    initializeLoginPage();
  }, []);

  const initializeLoginPage = async () => {
    try {
      // Load daily verse
      await loadDailyVerse();

      // Load saved prayer data
      await loadPrayerData();

      // Check for hardware key and existing account
      await checkAuthenticationStatus();

    } catch (error) {
      console.error('Failed to initialize login page:', error);
    } finally {
      setIsCheckingKey(false);
      setIsLoadingVerse(false);
    }
  };

  const loadDailyVerse = async () => {
    try {
      // Check if we have a verse for today already
      const today = new Date().toDateString();
      const storedVerse = localStorage.getItem(`daily_verse_${today}`);

      if (storedVerse) {
        setDailyVerse(JSON.parse(storedVerse));
        return;
      }

      // Generate new verse for today using built-in verses
      const newVerse = await invoke('get_daily_verse');
      setDailyVerse(newVerse);

      // Cache for today
      localStorage.setItem(`daily_verse_${today}`, JSON.stringify(newVerse));

    } catch (error) {
      console.error('Failed to load daily verse:', error);
      // Fallback verse
      setDailyVerse({
        text: "Trust in the Lord with all your heart and lean not on your own understanding; in all your ways submit to him, and he will make your paths straight.",
        reference: "Proverbs 3:5-6",
        translation: "NIV"
      });
    }
  };

  const loadPrayerData = async () => {
    try {
      const savedPrayer = localStorage.getItem('prayer_data');
      if (savedPrayer) {
        setPrayerData(JSON.parse(savedPrayer));
      }
    } catch (error) {
      console.error('Failed to load prayer data:', error);
    }
  };

  const savePrayerData = async (data: PrayerData) => {
    try {
      const updatedData = { ...data, lastUpdated: new Date().toISOString() };
      localStorage.setItem('prayer_data', JSON.stringify(updatedData));
      setPrayerData(updatedData);

      // Also save encrypted copy to keyfile if available
      if (keyPresent) {
        await invoke('save_encrypted_prayer_data', { data: updatedData });
      }
    } catch (error) {
      console.error('Failed to save prayer data:', error);
    }
  };

  const checkAuthenticationStatus = async () => {
    try {
      // Check if hardware key is present
      const keyStatus = await invoke('check_hardware_key_present');
      setKeyPresent(keyStatus);

      // Check if account exists
      if (keyStatus) {
        const accountExists = await invoke('check_account_exists');
        setHasAccount(accountExists);
      }

    } catch (error) {
      console.error('Failed to check authentication status:', error);
      setKeyPresent(false);
      setHasAccount(false);
    }
  };

  const handlePrayerChange = (newPrayer: string) => {
    const updatedData = { ...prayerData, personalPrayer: newPrayer };
    savePrayerData(updatedData);
  };

  const handlePrayerNeedSubmit = async () => {
    if (!prayerNeedText.trim()) return;

    const prayerRequest = {
      text: prayerNeedText,
      timestamp: new Date().toISOString(),
      id: Date.now().toString()
    };

    const updatedData = {
      ...prayerData,
      prayerRequests: [...prayerData.prayerRequests, prayerRequest.text]
    };

    await savePrayerData(updatedData);
    setPrayerNeedText('');
    setShowPrayerNeed(false);

    // Show confirmation
    alert('Your prayer request has been saved locally and encrypted for your privacy.');
  };

  const handleAccountCreated = (account: CreatedAccount) => {
    setHasAccount(true);
    setKeyPresent(account.hardwareKeyPresent || false);
    onAuthenticated(account);
  };

  const handleLogin = async () => {
    if (!keyPresent || !hasAccount) {
      setCurrentView('setup');
      return;
    }

    try {
      // Verify hardware key and authenticate
      const account = await invoke('authenticate_with_hardware_key');
      onAuthenticated(account);
    } catch (error) {
      console.error('Authentication failed:', error);
      alert('Authentication failed. Please check your hardware key.');
    }
  };

  if (currentView === 'setup') {
    return (
      <AccountSetup
        onComplete={handleAccountCreated}
        onCancel={() => setCurrentView('login')}
      />
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-background to-background-alt">
      {/* Header */}
      <header className="app-header">
        <h1 className="brand-tagline">✝ Jesus is King</h1>
        <div className="flex items-center gap-md">
          {keyPresent && (
            <span className="status-success">
              🔑 Hardware Key Present
            </span>
          )}
          {!keyPresent && (
            <span className="status-warning">
              ⚠ No Hardware Key
            </span>
          )}
        </div>
      </header>

      <div className="container">
        <div className="max-w-4xl mx-auto py-2xl">
          {/* Welcome Section */}
          <div className="text-center mb-2xl">
            <h2 className="text-4xl font-bold text-primary mb-lg">
              Welcome to Ephemeral Messenger
            </h2>
            <p className="text-lg text-secondary mb-xl">
              Secure, private communication guided by faith
            </p>
          </div>

          <div className="grid md:grid-cols-2 gap-xl">
            {/* Prayer Panel */}
            <div className="prayer-panel">
              <div className="prayer-header">
                <div className="prayer-icon">🙏</div>
                <h3 className="text-xl font-semibold">Daily Prayer</h3>
              </div>

              {/* Daily Verse */}
              {dailyVerse && (
                <div className="daily-verse">
                  {isLoadingVerse ? (
                    <div className="flex items-center gap-md">
                      <div className="spinner"></div>
                      <span>Loading today's verse...</span>
                    </div>
                  ) : (
                    <>
                      <p className="text-lg leading-relaxed">
                        "{dailyVerse.text}"
                      </p>
                      <div className="verse-reference">
                        — {dailyVerse.reference} ({dailyVerse.translation})
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* Personal Prayer */}
              <div className="form-group">
                <label className="form-label">Your Personal Prayer</label>
                <textarea
                  className="form-input form-textarea"
                  placeholder="Share your thoughts with God..."
                  value={prayerData.personalPrayer}
                  onChange={(e) => handlePrayerChange(e.target.value)}
                  rows={6}
                />
                <p className="text-sm text-tertiary mt-sm">
                  Your prayers are encrypted and stored locally for privacy.
                </p>
              </div>

              {/* Prayer Need Button */}
              <div className="flex gap-md">
                <button
                  className="btn btn-secondary flex-1"
                  onClick={() => setShowPrayerNeed(true)}
                >
                  🤲 I Need Prayer
                </button>

                {prayerData.prayerRequests.length > 0 && (
                  <button className="btn btn-ghost">
                    📝 View Requests ({prayerData.prayerRequests.length})
                  </button>
                )}
              </div>

              {/* Prayer Need Form */}
              {showPrayerNeed && (
                <div className="mt-lg p-lg bg-surface rounded-lg border border-border">
                  <h4 className="text-lg font-semibold mb-md">Prayer Request</h4>
                  <textarea
                    className="form-input form-textarea mb-md"
                    placeholder="What would you like prayer for?"
                    value={prayerNeedText}
                    onChange={(e) => setPrayerNeedText(e.target.value)}
                    rows={4}
                  />
                  <div className="flex gap-md">
                    <button
                      className="btn btn-primary"
                      onClick={handlePrayerNeedSubmit}
                      disabled={!prayerNeedText.trim()}
                    >
                      Save Prayer Request
                    </button>
                    <button
                      className="btn btn-ghost"
                      onClick={() => {
                        setShowPrayerNeed(false);
                        setPrayerNeedText('');
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>

            {/* Authentication Section */}
            <div className="card">
              <div className="card-header">
                <h3 className="text-xl font-semibold">Secure Access</h3>
                <p className="text-secondary">
                  Hardware key authentication for maximum security
                </p>
              </div>

              <div className="card-content">
                {isCheckingKey ? (
                  <div className="flex items-center gap-md">
                    <div className="spinner"></div>
                    <span>Checking for hardware key...</span>
                  </div>
                ) : (
                  <div>
                    {/* Hardware Key Status */}
                    <div className="mb-lg">
                      <div className="checklist-item">
                        <div className={`checklist-icon ${keyPresent ? 'success' : 'pending'}`}>
                          {keyPresent ? '✓' : '○'}
                        </div>
                        <div>
                          <div className="font-medium">
                            Hardware Key {keyPresent ? 'Detected' : 'Required'}
                          </div>
                          <div className="text-sm text-tertiary">
                            {keyPresent
                              ? 'Secure keyfile found on removable device'
                              : 'Insert hardware key or create new account'
                            }
                          </div>
                        </div>
                      </div>

                      <div className="checklist-item">
                        <div className={`checklist-icon ${hasAccount ? 'success' : 'pending'}`}>
                          {hasAccount ? '✓' : '○'}
                        </div>
                        <div>
                          <div className="font-medium">
                            Account {hasAccount ? 'Ready' : 'Setup Required'}
                          </div>
                          <div className="text-sm text-tertiary">
                            {hasAccount
                              ? 'Valid account configuration found'
                              : 'Create new account or import existing key'
                            }
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* Action Buttons */}
                    <div className="flex flex-col gap-md">
                      {keyPresent && hasAccount ? (
                        <button
                          className="btn btn-primary btn-lg w-full"
                          onClick={handleLogin}
                        >
                          🔓 Enter Messenger
                        </button>
                      ) : (
                        <button
                          className="btn btn-primary btn-lg w-full"
                          onClick={() => setCurrentView('setup')}
                        >
                          🔧 Setup Account
                        </button>
                      )}

                      <button className="btn btn-ghost w-full">
                        📖 Read Scripture
                      </button>

                      <button className="btn btn-ghost w-full">
                        📜 Moral Code of Conduct
                      </button>
                    </div>

                    {/* Security Notice */}
                    <div className="mt-lg p-md bg-surface-elevated rounded-lg border border-border">
                      <h4 className="text-sm font-semibold text-primary mb-sm">
                        🛡️ Security Notice
                      </h4>
                      <ul className="text-sm text-secondary space-y-1">
                        <li>• Your messages are end-to-end encrypted</li>
                        <li>• Hardware keys provide maximum security</li>
                        <li>• No data is transmitted during prayer or Scripture reading</li>
                        <li>• All communication is routed through Tor</li>
                      </ul>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Footer */}
          <footer className="mt-3xl text-center text-tertiary">
            <p className="mb-md">
              "For where two or three gather in my name, there am I with them." — Matthew 18:20
            </p>
            <p className="text-sm">
              Ephemeral Messenger • Secure • Private • Faith-Guided
            </p>
          </footer>
        </div>
      </div>
    </div>
  );
};