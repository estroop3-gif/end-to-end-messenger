import React, { useState, useEffect } from 'react';
import { invoke } from '../services/api';
import './SettingsSecurity.css';

interface Settings {
  version: number;
  access_mode: AccessMode;
  wipe_policy: WipePolicy;
  messaging: MessagingSettings;
  cryptography: CryptographySettings;
  scripture: ScriptureSettings;
  admin_lock: boolean;
  created_at: number;
  modified_at: number;
}

interface AccessMode {
  HardKey?: {};
  LocalOnly?: {
    encrypted_credential: number[];
    salt: number[];
    argon2_params: Argon2Params;
  };
}

interface Argon2Params {
  time_cost: number;
  memory_cost: number;
  parallelism: number;
}

interface WipePolicy {
  selective_program_data: boolean;
  full_drive_enabled: boolean;
  countdown_seconds: number;
  require_confirmation_phrase: boolean;
  confirmation_phrase: string;
}

interface MessagingSettings {
  retention_mode: 'MemoryOnly' | 'SessionOnly' | 'Bounded' | 'ExplicitKeep';
  max_messages: number;
  max_days: number;
  burner_default_ttl: number;
  burner_allow_files: boolean;
  sealed_sender_enforced: boolean;
  cover_traffic: boolean;
  panic_on_key_removal: boolean;
  dead_man_switch: boolean;
}

interface CryptographySettings {
  hybrid_pq_kem: boolean;
  watermark_required: boolean;
  clipboard_guard: boolean;
}

interface ScriptureSettings {
  esv_license_key?: string;
  enable_prayer_panel: boolean;
  prayer_text: string;
  daily_verse_source: string;
}

interface HazardWarning {
  title: string;
  message: string;
  risks: string[];
  mitigation: string[];
  acknowledgment_required: string;
}

interface PasswordStrength {
  level: 'Weak' | 'Medium' | 'Strong' | 'VeryStrong';
  score: number;
  feedback: string[];
}

interface DeviceInfo {
  path: string;
  id: string;
  serial?: string;
  model?: string;
  size: number;
  is_removable: boolean;
  is_system_disk: boolean;
  mount_points: string[];
}

interface WipePlan {
  id: string;
  created_at: string;
  target_device: TargetDevice;
  wipe_method: 'SecureErase' | 'MultiPassRandom' | 'SinglePassZero' | 'BlkDiscard' | 'Hybrid';
  verification_required: boolean;
  admin_signature: number[];
  approval_audit_id: string;
}

interface TargetDevice {
  device_path: string;
  device_id: string;
  serial_number?: string;
  model?: string;
  size_bytes: number;
  verified_twice: boolean;
}

const SettingsSecurity: React.FC = () => {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [activeSection, setActiveSection] = useState<string>('access');

  // Access Mode state
  const [showLocalAccessWarning, setShowLocalAccessWarning] = useState(false);
  const [hazardWarning, setHazardWarning] = useState<HazardWarning | null>(null);
  const [localPassphrase, setLocalPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [acknowledgmentText, setAcknowledgmentText] = useState('');
  const [passphraseStrength, setPassphraseStrength] = useState<PasswordStrength | null>(null);

  // Wipe Policy state
  const [showWipeWarning, setShowWipeWarning] = useState(false);
  const [countdownSeconds, setCountdownSeconds] = useState(30);
  const [confirmationPhrase, setConfirmationPhrase] = useState('I understand this action cannot be undone');
  const [showAdvancedWipe, setShowAdvancedWipe] = useState(false);

  // Full Wipe state
  const [storageDevices, setStorageDevices] = useState<DeviceInfo[]>([]);
  const [selectedWipeDevice, setSelectedWipeDevice] = useState<string>('');
  const [selectedWipeMethod, setSelectedWipeMethod] = useState<string>('multi_pass_random');
  const [showCreateWipeUSB, setShowCreateWipeUSB] = useState(false);
  const [wipePlan, setWipePlan] = useState<WipePlan | null>(null);

  // Admin approval state
  const [adminApprovalRequired, setAdminApprovalRequired] = useState(false);
  const [approvalAction, setApprovalAction] = useState<string>('');
  const [adminPassphrase, setAdminPassphrase] = useState('');

  useEffect(() => {
    loadSettings();
    loadHazardWarning();
  }, []);

  const loadSettings = async () => {
    try {
      setLoading(true);
      const response = await invoke('settings_load', {
        accessMode: 'hardware_key', // Default to hardware key
        passphrase: null,
      });

      if (response.success) {
        setSettings(response.settings);
      } else {
        setError(response.error);
      }
    } catch (err) {
      setError(`Failed to load settings: ${err}`);
    } finally {
      setLoading(false);
    }
  };

  const loadHazardWarning = async () => {
    try {
      const warning = await invoke('get_local_access_warning');
      setHazardWarning(warning);
    } catch (err) {
      console.error('Failed to load hazard warning:', err);
    }
  };

  const saveSettings = async () => {
    if (!settings) return;

    try {
      const response = await invoke('settings_save', { settings });
      if (!response.success) {
        setError(response.error);
      }
    } catch (err) {
      setError(`Failed to save settings: ${err}`);
    }
  };

  const handlePassphraseChange = async (value: string) => {
    setLocalPassphrase(value);

    if (value.length > 0) {
      try {
        const strength = await invoke('validate_passphrase_strength', {
          passphrase: value,
        });
        setPassphraseStrength(strength);
      } catch (err) {
        console.error('Failed to validate passphrase strength:', err);
      }
    } else {
      setPassphraseStrength(null);
    }
  };

  const enableLocalAccess = async () => {
    if (localPassphrase !== confirmPassphrase) {
      setError('Passphrases do not match');
      return;
    }

    if (!hazardWarning || acknowledgmentText !== hazardWarning.acknowledgment_required) {
      setError('Please acknowledge the security risks by typing the exact phrase');
      return;
    }

    try {
      const success = await invoke('enable_local_access', {
        passphrase: localPassphrase,
        confirmation: acknowledgmentText,
      });

      if (success) {
        setShowLocalAccessWarning(false);
        setLocalPassphrase('');
        setConfirmPassphrase('');
        setAcknowledgmentText('');
        await loadSettings();
      }
    } catch (err) {
      setError(`Failed to enable local access: ${err}`);
    }
  };

  const loadStorageDevices = async () => {
    try {
      const devices = await invoke('list_storage_devices');
      setStorageDevices(devices);
    } catch (err) {
      setError(`Failed to load storage devices: ${err}`);
    }
  };

  const createWipePlan = async () => {
    const selectedDevice = storageDevices.find(d => d.path === selectedWipeDevice);
    if (!selectedDevice) {
      setError('Please select a storage device');
      return;
    }

    try {
      const plan = await invoke('create_wipe_plan', {
        devicePath: selectedDevice.path,
        deviceId: selectedDevice.id,
        serialNumber: selectedDevice.serial,
        model: selectedDevice.model,
        sizeBytes: selectedDevice.size,
        wipeMethod: selectedWipeMethod,
      });

      setWipePlan(plan);
      setShowCreateWipeUSB(true);
    } catch (err) {
      setError(`Failed to create wipe plan: ${err}`);
    }
  };

  const formatSize = (bytes: number): string => {
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    if (bytes === 0) return '0 B';
    const i = Math.floor(Math.log(bytes) / Math.log(1024));
    return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${sizes[i]}`;
  };

  const getStrengthColor = (level: string): string => {
    switch (level) {
      case 'Weak': return 'var(--color-error)';
      case 'Medium': return 'var(--color-warning)';
      case 'Strong': return 'var(--color-success)';
      case 'VeryStrong': return 'var(--color-primary)';
      default: return 'var(--color-text-tertiary)';
    }
  };

  if (loading) {
    return (
      <div className="settings-loading">
        <div className="loading-spinner"></div>
        <p>Loading security settings...</p>
      </div>
    );
  }

  if (!settings) {
    return (
      <div className="settings-error">
        <h2>⚠️ Settings Error</h2>
        <p>{error || 'Failed to load settings'}</p>
        <button onClick={loadSettings} className="retry-button">
          Retry Loading
        </button>
      </div>
    );
  }

  return (
    <div className="settings-security">
      <div className="settings-header">
        <h1>🔒 Security & Privacy Settings</h1>
        <p>Configure access modes, wipe policies, and security features</p>
      </div>

      {error && (
        <div className="error-banner">
          <span>{error}</span>
          <button onClick={() => setError(null)} className="error-close">×</button>
        </div>
      )}

      <div className="settings-nav">
        <button
          className={`nav-tab ${activeSection === 'access' ? 'active' : ''}`}
          onClick={() => setActiveSection('access')}
        >
          🔑 Access Mode
        </button>
        <button
          className={`nav-tab ${activeSection === 'wipe' ? 'active' : ''}`}
          onClick={() => setActiveSection('wipe')}
        >
          🗑️ Wipe Policy
        </button>
        <button
          className={`nav-tab ${activeSection === 'messaging' ? 'active' : ''}`}
          onClick={() => setActiveSection('messaging')}
        >
          💬 Messaging
        </button>
        <button
          className={`nav-tab ${activeSection === 'crypto' ? 'active' : ''}`}
          onClick={() => setActiveSection('crypto')}
        >
          🔐 Cryptography
        </button>
        <button
          className={`nav-tab ${activeSection === 'scripture' ? 'active' : ''}`}
          onClick={() => setActiveSection('scripture')}
        >
          📖 Scripture
        </button>
      </div>

      <div className="settings-content">
        {/* Access Mode Section */}
        {activeSection === 'access' && (
          <div className="settings-section">
            <div className="section-header">
              <h2>🔑 Access Mode Configuration</h2>
              <p>Choose how you authenticate to access the application</p>
            </div>

            <div className="access-mode-options">
              <div className="option-card recommended">
                <div className="option-header">
                  <h3>🔒 Physical Hard Key</h3>
                  <span className="recommended-badge">Recommended</span>
                </div>
                <p>Requires a removable hardware key or hardware token for access</p>
                <div className="option-status">
                  <input
                    type="radio"
                    id="hardkey"
                    name="accessMode"
                    checked={'HardKey' in settings.access_mode}
                    onChange={() => {}}
                  />
                  <label htmlFor="hardkey">Use Physical Hard Key (Default)</label>
                </div>
              </div>

              <div className="option-card warning">
                <div className="option-header">
                  <h3>⚠️ Local-Only Login</h3>
                  <span className="warning-badge">Higher Risk</span>
                </div>
                <p>Store encrypted login credentials locally (no hardware key required)</p>
                <div className="option-status">
                  <input
                    type="radio"
                    id="localonly"
                    name="accessMode"
                    checked={'LocalOnly' in settings.access_mode}
                    onChange={() => setShowLocalAccessWarning(true)}
                  />
                  <label htmlFor="localonly">Local-Only Login (encrypted, higher risk)</label>
                </div>

                {showLocalAccessWarning && hazardWarning && (
                  <div className="hazard-warning">
                    <h4>🚨 {hazardWarning.title}</h4>
                    <p>{hazardWarning.message}</p>

                    <div className="risks-section">
                      <h5>⚠️ Security Risks:</h5>
                      <ul>
                        {hazardWarning.risks.map((risk, index) => (
                          <li key={index}>{risk}</li>
                        ))}
                      </ul>
                    </div>

                    <div className="mitigation-section">
                      <h5>🛡️ Mitigation Steps:</h5>
                      <ul>
                        {hazardWarning.mitigation.map((step, index) => (
                          <li key={index}>{step}</li>
                        ))}
                      </ul>
                    </div>

                    <div className="passphrase-setup">
                      <div className="form-group">
                        <label>Master Passphrase (minimum 20 characters)</label>
                        <input
                          type="password"
                          value={localPassphrase}
                          onChange={(e) => handlePassphraseChange(e.target.value)}
                          placeholder="Enter a strong passphrase"
                          className="passphrase-input"
                        />
                        {passphraseStrength && (
                          <div className="strength-meter">
                            <div className="strength-bar">
                              <div
                                className="strength-fill"
                                style={{
                                  width: `${(passphraseStrength.score / 6) * 100}%`,
                                  backgroundColor: getStrengthColor(passphraseStrength.level),
                                }}
                              />
                            </div>
                            <div className="strength-info">
                              <span style={{ color: getStrengthColor(passphraseStrength.level) }}>
                                {passphraseStrength.level}
                              </span>
                              {passphraseStrength.feedback.length > 0 && (
                                <ul className="strength-feedback">
                                  {passphraseStrength.feedback.map((feedback, index) => (
                                    <li key={index}>{feedback}</li>
                                  ))}
                                </ul>
                              )}
                            </div>
                          </div>
                        )}
                      </div>

                      <div className="form-group">
                        <label>Confirm Passphrase</label>
                        <input
                          type="password"
                          value={confirmPassphrase}
                          onChange={(e) => setConfirmPassphrase(e.target.value)}
                          placeholder="Confirm your passphrase"
                          className="passphrase-input"
                        />
                      </div>

                      <div className="form-group">
                        <label>Risk Acknowledgment</label>
                        <p>Type the following phrase exactly to acknowledge the risks:</p>
                        <code>"{hazardWarning.acknowledgment_required}"</code>
                        <input
                          type="text"
                          value={acknowledgmentText}
                          onChange={(e) => setAcknowledgmentText(e.target.value)}
                          placeholder="Type the exact phrase above"
                          className="acknowledgment-input"
                        />
                      </div>

                      <div className="warning-actions">
                        <button
                          onClick={() => setShowLocalAccessWarning(false)}
                          className="cancel-button"
                        >
                          Cancel
                        </button>
                        <button
                          onClick={enableLocalAccess}
                          className="confirm-button"
                          disabled={
                            !localPassphrase ||
                            !confirmPassphrase ||
                            localPassphrase !== confirmPassphrase ||
                            acknowledgmentText !== hazardWarning.acknowledgment_required ||
                            passphraseStrength?.level === 'Weak'
                          }
                        >
                          Enable Local-Only Access
                        </button>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Wipe Policy Section */}
        {activeSection === 'wipe' && (
          <div className="settings-section">
            <div className="section-header">
              <h2>🗑️ Data Wipe Policies</h2>
              <p>Configure data destruction and emergency wipe procedures</p>
            </div>

            <div className="wipe-options">
              <div className="wipe-option">
                <div className="option-header">
                  <h3>📁 Selective Program-Data Wipe</h3>
                  <label className="toggle-switch">
                    <input
                      type="checkbox"
                      checked={settings.wipe_policy.selective_program_data}
                      onChange={(e) => {
                        setSettings(prev => prev ? {
                          ...prev,
                          wipe_policy: {
                            ...prev.wipe_policy,
                            selective_program_data: e.target.checked,
                          }
                        } : null);
                        saveSettings();
                      }}
                    />
                    <span className="slider"></span>
                  </label>
                </div>
                <p>Enable controlled wipe of application data and user files</p>

                {settings.wipe_policy.selective_program_data && (
                  <div className="wipe-controls">
                    <div className="form-group">
                      <label>Countdown Duration (seconds)</label>
                      <input
                        type="number"
                        min="10"
                        max="300"
                        value={countdownSeconds}
                        onChange={(e) => setCountdownSeconds(parseInt(e.target.value))}
                      />
                    </div>

                    <div className="form-group">
                      <label>Confirmation Phrase</label>
                      <input
                        type="text"
                        value={confirmationPhrase}
                        onChange={(e) => setConfirmationPhrase(e.target.value)}
                        placeholder="Phrase required to confirm wipe"
                      />
                    </div>

                    <div className="wipe-actions">
                      <button className="preview-button">
                        🔍 Preview (Dry-run)
                      </button>
                      <button className="enable-button">
                        ✅ Enable Policy
                      </button>
                    </div>
                  </div>
                )}
              </div>

              <div className="wipe-option advanced">
                <div className="option-header">
                  <h3>💾 Full-Drive Wipe</h3>
                  <button
                    className="expand-button"
                    onClick={() => setShowAdvancedWipe(!showAdvancedWipe)}
                  >
                    {showAdvancedWipe ? '▼' : '▶'} Advanced/Dangerous
                  </button>
                </div>
                <p>Prepare external wipe tool for complete drive destruction</p>

                {showAdvancedWipe && (
                  <div className="advanced-wipe-section">
                    <div className="danger-notice">
                      <h4>⚠️ EXTREME CAUTION REQUIRED</h4>
                      <p>This creates an external tool; the main app does NOT wipe your OS drive directly.</p>
                      <p>Only use on devices you explicitly intend to completely destroy.</p>
                    </div>

                    <div className="device-selection">
                      <button
                        onClick={loadStorageDevices}
                        className="scan-button"
                      >
                        🔍 Scan Storage Devices
                      </button>

                      {storageDevices.length > 0 && (
                        <div className="device-list">
                          <h5>Available Storage Devices:</h5>
                          {storageDevices.map((device) => (
                            <div
                              key={device.path}
                              className={`device-item ${device.is_system_disk ? 'system-disk' : ''} ${selectedWipeDevice === device.path ? 'selected' : ''}`}
                              onClick={() => {
                                if (!device.is_system_disk) {
                                  setSelectedWipeDevice(device.path);
                                }
                              }}
                            >
                              <div className="device-info">
                                <div className="device-path">{device.path}</div>
                                <div className="device-details">
                                  {device.model && <span>Model: {device.model}</span>}
                                  {device.serial && <span>Serial: {device.serial}</span>}
                                  <span>Size: {formatSize(device.size)}</span>
                                  <span className={device.is_removable ? 'removable' : 'fixed'}>
                                    {device.is_removable ? '📱 Removable' : '💾 Fixed'}
                                  </span>
                                  {device.is_system_disk && (
                                    <span className="system-warning">⚠️ SYSTEM DISK</span>
                                  )}
                                </div>
                              </div>
                              {device.is_system_disk && (
                                <div className="system-warning-text">
                                  Cannot select system disk for safety
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}

                      {selectedWipeDevice && (
                        <div className="wipe-method-selection">
                          <h5>Wipe Method:</h5>
                          <select
                            value={selectedWipeMethod}
                            onChange={(e) => setSelectedWipeMethod(e.target.value)}
                          >
                            <option value="secure_erase">Hardware Secure Erase (if supported)</option>
                            <option value="multi_pass_random">Multi-Pass Random Data (3 passes)</option>
                            <option value="single_pass_zero">Single Pass Zero</option>
                            <option value="blk_discard">TRIM/Discard</option>
                            <option value="hybrid">Hybrid (TRIM + Random + Zero)</option>
                          </select>
                        </div>
                      )}

                      {selectedWipeDevice && (
                        <div className="create-usb-section">
                          <button
                            onClick={createWipePlan}
                            className="create-plan-button"
                          >
                            📋 Create Wipe Plan
                          </button>

                          {wipePlan && (
                            <div className="wipe-plan-summary">
                              <h5>✅ Wipe Plan Created</h5>
                              <div className="plan-details">
                                <p><strong>Plan ID:</strong> {wipePlan.id}</p>
                                <p><strong>Target:</strong> {wipePlan.target_device.device_path}</p>
                                <p><strong>Method:</strong> {wipePlan.wipe_method}</p>
                                <p><strong>Size:</strong> {formatSize(wipePlan.target_device.size_bytes)}</p>
                              </div>

                              <button
                                onClick={() => setShowCreateWipeUSB(true)}
                                className="create-usb-button"
                              >
                                💾 Create Bootable Wipe USB
                              </button>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Other sections would be implemented similarly */}
        {activeSection === 'messaging' && (
          <div className="settings-section">
            <h2>💬 Messaging & Files Settings</h2>
            <p>Configure retention, burner accounts, and messaging security</p>
            {/* Messaging settings implementation */}
          </div>
        )}

        {activeSection === 'crypto' && (
          <div className="settings-section">
            <h2>🔐 Cryptography Settings</h2>
            <p>Configure encryption features and security options</p>
            {/* Cryptography settings implementation */}
          </div>
        )}

        {activeSection === 'scripture' && (
          <div className="settings-section">
            <h2>📖 Scripture & Branding Settings</h2>
            <p>Configure ESV access, prayer features, and spiritual content</p>
            {/* Scripture settings implementation */}
          </div>
        )}
      </div>

      <div className="settings-footer">
        <div className="settings-lock">
          <label className="toggle-switch">
            <input
              type="checkbox"
              checked={settings.admin_lock}
              onChange={(e) => {
                setSettings(prev => prev ? {
                  ...prev,
                  admin_lock: e.target.checked,
                } : null);
                saveSettings();
              }}
            />
            <span className="slider"></span>
          </label>
          <span>🔒 Admin Lock (requires admin approval for changes)</span>
        </div>

        <div className="settings-info">
          <p>Settings saved automatically • Last modified: {new Date(settings.modified_at * 1000).toLocaleString()}</p>
        </div>
      </div>
    </div>
  );
};

export default SettingsSecurity;