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

interface DeadManSwitchSettings {
  enabled: boolean;
  check_interval_hours: number;
  max_inactive_hours: number;
  policy_signature: string | null;
  policy_hash: string | null;
  admin_pubkey: string | null;
  machine_binding: string | null;
  last_checkin: number | null;
  configured_at: number | null;
}

interface DmsPolicy {
  version: number;
  policy_id: string;
  admin_pubkey: string;
  machine_binding: string;
  max_inactive_hours: number;
  check_interval_hours: number;
  wipe_actions: string[];
  emergency_contact: string | null;
  created_at: number;
  expires_at: number | null;
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

  // Dead-Man Switch state
  const [dmsSettings, setDmsSettings] = useState<DeadManSwitchSettings | null>(null);
  const [showDmsConfiguration, setShowDmsConfiguration] = useState(false);
  const [dmsPolicy, setDmsPolicy] = useState<DmsPolicy | null>(null);
  const [policyJson, setPolicyJson] = useState('');
  const [policySignature, setPolicySignature] = useState('');
  const [adminPublicKey, setAdminPublicKey] = useState('');
  const [machineId, setMachineId] = useState('');
  const [dmsCountdown, setDmsCountdown] = useState<number | null>(null);
  const [showDmsWarning, setShowDmsWarning] = useState(false);

  useEffect(() => {
    loadSettings();
    loadHazardWarning();
    loadDmsSettings();
    loadMachineId();
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

  // Dead-Man Switch functions
  const loadDmsSettings = async () => {
    try {
      await invoke('initialize_dms');
      const settings = await invoke('get_dms_settings');
      setDmsSettings(settings);
    } catch (err) {
      console.error('Failed to load DMS settings:', err);
    }
  };

  const loadMachineId = async () => {
    try {
      const id = await invoke('get_machine_identifier');
      setMachineId(id);
    } catch (err) {
      console.error('Failed to load machine ID:', err);
    }
  };

  const verifyDmsPolicy = async () => {
    if (!policyJson || !policySignature || !adminPublicKey) {
      setError('All DMS policy fields are required');
      return;
    }

    try {
      const policy = await invoke('verify_dms_policy', {
        policyJson,
        signatureB64: policySignature,
        adminPubkeyB64: adminPublicKey,
      });
      setDmsPolicy(policy);
    } catch (err) {
      setError(`Policy verification failed: ${err}`);
    }
  };

  const configureDms = async () => {
    if (!dmsPolicy || !policySignature) {
      setError('Policy must be verified before configuration');
      return;
    }

    try {
      await invoke('configure_dms', {
        policy: dmsPolicy,
        signature: policySignature,
      });
      await loadDmsSettings();
      setShowDmsConfiguration(false);
      setPolicyJson('');
      setPolicySignature('');
      setAdminPublicKey('');
    } catch (err) {
      setError(`DMS configuration failed: ${err}`);
    }
  };

  const performDmsCheckin = async () => {
    try {
      await invoke('perform_dms_checkin');
      await loadDmsSettings();
    } catch (err) {
      setError(`DMS checkin failed: ${err}`);
    }
  };

  const checkDmsStatus = async () => {
    try {
      const shouldTrigger = await invoke('check_dms_status');
      if (shouldTrigger) {
        setShowDmsWarning(true);
        // Start countdown for emergency wipe
        const countdownTime = 300; // 5 minutes
        setDmsCountdown(countdownTime);

        const countdown = setInterval(() => {
          setDmsCountdown(prev => {
            if (prev && prev > 1) {
              return prev - 1;
            } else {
              clearInterval(countdown);
              triggerEmergencyWipe('DMS timeout expired');
              return 0;
            }
          });
        }, 1000);
      }
    } catch (err) {
      console.error('DMS status check failed:', err);
    }
  };

  const triggerEmergencyWipe = async (reason: string) => {
    try {
      await invoke('trigger_emergency_wipe', { reason });
      alert('Emergency wipe has been triggered. Application will close.');
      // Application should close itself after this
    } catch (err) {
      setError(`Emergency wipe failed: ${err}`);
    }
  };

  const disableDms = async (adminSignature: string) => {
    try {
      await invoke('disable_dms', { adminSignature });
      await loadDmsSettings();
      setShowDmsWarning(false);
      setDmsCountdown(null);
    } catch (err) {
      setError(`Failed to disable DMS: ${err}`);
    }
  };

  const formatDuration = (hours: number): string => {
    if (hours < 24) {
      return `${hours} hour${hours !== 1 ? 's' : ''}`;
    } else {
      const days = Math.floor(hours / 24);
      const remainingHours = hours % 24;
      return `${days} day${days !== 1 ? 's' : ''}${remainingHours > 0 ? ` ${remainingHours} hour${remainingHours !== 1 ? 's' : ''}` : ''}`;
    }
  };

  const formatTimestamp = (timestamp: number): string => {
    return new Date(timestamp * 1000).toLocaleString();
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
        <button
          className={`nav-tab ${activeSection === 'dms' ? 'active' : ''}`}
          onClick={() => setActiveSection('dms')}
        >
          ⏱️ Dead-Man Switch
        </button>
      </div>

      {/* DMS Emergency Warning Overlay */}
      {showDmsWarning && dmsCountdown !== null && (
        <div className="dms-emergency-overlay">
          <div className="dms-emergency-dialog">
            <div className="emergency-header">
              <h2>🚨 DEAD-MAN SWITCH TRIGGERED</h2>
              <div className="countdown-display">
                <span className="countdown-time">{Math.floor(dmsCountdown / 60)}:{(dmsCountdown % 60).toString().padStart(2, '0')}</span>
                <span className="countdown-label">until emergency wipe</span>
              </div>
            </div>

            <div className="emergency-content">
              <p>The Dead-Man Switch has detected prolonged inactivity and will trigger an emergency wipe in:</p>

              <div className="emergency-actions">
                <button
                  onClick={performDmsCheckin}
                  className="checkin-button"
                >
                  ✅ I'm Here - Perform Check-in
                </button>

                <div className="admin-override">
                  <h4>Admin Override:</h4>
                  <input
                    type="text"
                    placeholder="Admin signature to disable DMS"
                    className="admin-signature-input"
                    onKeyPress={(e) => {
                      if (e.key === 'Enter') {
                        disableDms(e.currentTarget.value);
                      }
                    }}
                  />
                  <button
                    onClick={() => {
                      const input = document.querySelector('.admin-signature-input') as HTMLInputElement;
                      if (input?.value) {
                        disableDms(input.value);
                      }
                    }}
                    className="override-button"
                  >
                    🔓 Admin Override
                  </button>
                </div>
              </div>

              <div className="emergency-warning">
                <p>⚠️ If no action is taken, all sensitive data will be securely wiped.</p>
                <p>This action cannot be undone.</p>
              </div>
            </div>
          </div>
        </div>
      )}

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

        {/* Dead-Man Switch Section */}
        {activeSection === 'dms' && (
          <div className="settings-section">
            <div className="section-header">
              <h2>⏱️ Dead-Man Switch Configuration</h2>
              <p>Configure automated security responses for prolonged inactivity</p>
            </div>

            <div className="dms-status-card">
              <h3>🔍 Current Status</h3>
              {dmsSettings ? (
                <div className="status-info">
                  <div className="status-row">
                    <span className="status-label">Status:</span>
                    <span className={`status-value ${dmsSettings.enabled ? 'enabled' : 'disabled'}`}>
                      {dmsSettings.enabled ? '✅ Enabled' : '⭕ Disabled'}
                    </span>
                  </div>

                  {dmsSettings.enabled && (
                    <>
                      <div className="status-row">
                        <span className="status-label">Check Interval:</span>
                        <span className="status-value">{formatDuration(dmsSettings.check_interval_hours)}</span>
                      </div>
                      <div className="status-row">
                        <span className="status-label">Max Inactive Time:</span>
                        <span className="status-value">{formatDuration(dmsSettings.max_inactive_hours)}</span>
                      </div>
                      <div className="status-row">
                        <span className="status-label">Last Check-in:</span>
                        <span className="status-value">
                          {dmsSettings.last_checkin ? formatTimestamp(dmsSettings.last_checkin) : 'Never'}
                        </span>
                      </div>
                      {dmsSettings.configured_at && (
                        <div className="status-row">
                          <span className="status-label">Configured:</span>
                          <span className="status-value">{formatTimestamp(dmsSettings.configured_at)}</span>
                        </div>
                      )}
                    </>
                  )}

                  <div className="status-actions">
                    {dmsSettings.enabled && (
                      <button onClick={performDmsCheckin} className="checkin-button">
                        ✅ Perform Check-in
                      </button>
                    )}
                    <button onClick={checkDmsStatus} className="status-check-button">
                      🔍 Check DMS Status
                    </button>
                  </div>
                </div>
              ) : (
                <div className="loading-status">
                  <p>Loading DMS status...</p>
                </div>
              )}
            </div>

            <div className="machine-info-card">
              <h3>🖥️ Machine Information</h3>
              <div className="machine-details">
                <div className="info-row">
                  <span className="info-label">Machine ID:</span>
                  <code className="machine-id">{machineId || 'Loading...'}</code>
                </div>
                <p className="info-note">
                  This identifier is used to bind DMS policies to this specific machine.
                </p>
              </div>
            </div>

            <div className="dms-configuration-card">
              <div className="card-header">
                <h3>⚙️ DMS Configuration</h3>
                <button
                  onClick={() => setShowDmsConfiguration(!showDmsConfiguration)}
                  className="expand-button"
                >
                  {showDmsConfiguration ? '▼' : '▶'} Configure DMS Policy
                </button>
              </div>

              {showDmsConfiguration && (
                <div className="dms-config-form">
                  <div className="config-warning">
                    <h4>⚠️ Administrative Authorization Required</h4>
                    <p>
                      Dead-Man Switch configuration requires a signed policy from an authorized administrator.
                      The policy must be cryptographically signed and machine-bound for security.
                    </p>
                  </div>

                  <div className="form-group">
                    <label>Admin Public Key (Base64)</label>
                    <input
                      type="text"
                      value={adminPublicKey}
                      onChange={(e) => setAdminPublicKey(e.target.value)}
                      placeholder="Enter Ed25519 public key in Base64 format"
                      className="pubkey-input"
                    />
                  </div>

                  <div className="form-group">
                    <label>DMS Policy (JSON)</label>
                    <textarea
                      value={policyJson}
                      onChange={(e) => setPolicyJson(e.target.value)}
                      placeholder={`{
  "version": 1,
  "policy_id": "example_policy",
  "admin_pubkey": "base64_encoded_public_key",
  "machine_binding": "${machineId}",
  "max_inactive_hours": 168,
  "check_interval_hours": 24,
  "wipe_actions": ["SecureDelete", "ClearCredentials"],
  "emergency_contact": null,
  "created_at": ${Math.floor(Date.now() / 1000)},
  "expires_at": null
}`}
                      className="policy-textarea"
                      rows={12}
                    />
                  </div>

                  <div className="form-group">
                    <label>Policy Signature (Base64)</label>
                    <input
                      type="text"
                      value={policySignature}
                      onChange={(e) => setPolicySignature(e.target.value)}
                      placeholder="Enter Ed25519 signature of the policy JSON"
                      className="signature-input"
                    />
                  </div>

                  <div className="config-actions">
                    <button
                      onClick={verifyDmsPolicy}
                      className="verify-button"
                      disabled={!policyJson || !policySignature || !adminPublicKey}
                    >
                      🔐 Verify Policy
                    </button>

                    {dmsPolicy && (
                      <div className="policy-verified">
                        <h4>✅ Policy Verified</h4>
                        <div className="policy-summary">
                          <p><strong>Policy ID:</strong> {dmsPolicy.policy_id}</p>
                          <p><strong>Max Inactive:</strong> {formatDuration(dmsPolicy.max_inactive_hours)}</p>
                          <p><strong>Check Interval:</strong> {formatDuration(dmsPolicy.check_interval_hours)}</p>
                          <p><strong>Wipe Actions:</strong> {dmsPolicy.wipe_actions.join(', ')}</p>
                        </div>

                        <button
                          onClick={configureDms}
                          className="configure-button"
                        >
                          🔧 Apply DMS Configuration
                        </button>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>

            <div className="dms-info-card">
              <h3>ℹ️ About Dead-Man Switch</h3>
              <div className="info-content">
                <p>
                  The Dead-Man Switch (DMS) is a security feature that monitors user activity and automatically
                  triggers emergency procedures if the user becomes unavailable for an extended period.
                </p>

                <div className="info-section">
                  <h4>🔒 Security Features:</h4>
                  <ul>
                    <li>Policy-based configuration with cryptographic verification</li>
                    <li>Machine-bound policies prevent unauthorized transfer</li>
                    <li>Configurable check-in intervals and inactivity thresholds</li>
                    <li>Multiple wipe actions: secure deletion, credential clearing, memory overwrite</li>
                    <li>Admin override capabilities with signature verification</li>
                    <li>Comprehensive audit logging to removable media</li>
                  </ul>
                </div>

                <div className="info-section">
                  <h4>⚠️ Important Notes:</h4>
                  <ul>
                    <li><strong>OFF by default</strong> - Must be explicitly enabled via Settings</li>
                    <li><strong>Admin approval required</strong> - Policies must be signed by authorized administrators</li>
                    <li><strong>Machine-bound</strong> - Policies are tied to specific hardware identifiers</li>
                    <li><strong>Irreversible</strong> - Emergency wipe actions cannot be undone</li>
                    <li><strong>Failsafe design</strong> - System remains secure even under compromise scenarios</li>
                  </ul>
                </div>

                <div className="scripture-section">
                  <div className="scripture-verse">
                    "Be watchful, stand firm in the faith, act like men, be strong." - 1 Corinthians 16:13
                  </div>
                  <p>
                    God calls us to be vigilant and prepared. The Dead-Man Switch serves as a faithful guardian,
                    ensuring our digital stewardship remains secure even in unforeseen circumstances.
                  </p>
                </div>
              </div>
            </div>
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