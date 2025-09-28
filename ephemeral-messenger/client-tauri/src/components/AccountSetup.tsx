/**
 * Account Setup Component for Ephemeral Messenger
 *
 * Provides a guided account creation flow with options for:
 * 1. Hardware key creation and setup
 * 2. Software-only fallback with strong passphrase
 * 3. Import existing hardware key
 *
 * SECURITY NOTE: This component handles sensitive user credentials.
 * All operations are performed locally with secure key derivation.
 */

import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { keyDetectionService } from '../services/keyDetection';
import type { RemovableDevice, ValidatedKey } from '../services/keyDetection';

export interface AccountSetupProps {
  onComplete: (account: CreatedAccount) => void;
  onCancel?: () => void;
}

export interface CreatedAccount {
  accountType: 'hardware' | 'software';
  userId: string;
  username: string;
  publicKey: string;
  fingerprint: string;
  hardwareKeyPresent?: boolean;
  keyFile?: ValidatedKey;
}

type SetupStep =
  | 'welcome'
  | 'choose-method'
  | 'hardware-setup'
  | 'device-selection'
  | 'key-generation'
  | 'software-setup'
  | 'passphrase-entry'
  | 'import-existing'
  | 'verification'
  | 'complete';

export const AccountSetup: React.FC<AccountSetupProps> = ({ onComplete, onCancel }) => {
  // State management
  const [currentStep, setCurrentStep] = useState<SetupStep>('welcome');
  const [setupMethod, setSetupMethod] = useState<'hardware' | 'software' | 'import' | null>(null);
  const [username, setUsername] = useState('');
  const [passphrase, setPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [agreedToTerms, setAgreedToTerms] = useState(false);

  // Hardware-specific state
  const [removableDevices, setRemovableDevices] = useState<RemovableDevice[]>([]);
  const [selectedDevice, setSelectedDevice] = useState<RemovableDevice | null>(null);
  const [isDetectingDevices, setIsDetectingDevices] = useState(false);
  const [isGeneratingKey, setIsGeneratingKey] = useState(false);
  const [generatedAccount, setGeneratedAccount] = useState<CreatedAccount | null>(null);

  // Import-specific state
  const [importError, setImportError] = useState<string | null>(null);
  const [detectedKey, setDetectedKey] = useState<ValidatedKey | null>(null);

  // Security validation
  const [passphraseStrength, setPassphraseStrength] = useState<'weak' | 'medium' | 'strong'>('weak');
  const [validationErrors, setValidationErrors] = useState<string[]>([]);

  useEffect(() => {
    // Initialize key detection service if hardware method selected
    if (setupMethod === 'hardware' || setupMethod === 'import') {
      initializeKeyDetection();
    }
  }, [setupMethod]);

  useEffect(() => {
    // Validate passphrase strength
    if (passphrase) {
      const strength = calculatePassphraseStrength(passphrase);
      setPassphraseStrength(strength);
    }
  }, [passphrase]);

  const initializeKeyDetection = async () => {
    try {
      await keyDetectionService.initialize();
    } catch (error) {
      console.error('Failed to initialize key detection:', error);
    }
  };

  const detectRemovableDevices = async () => {
    setIsDetectingDevices(true);
    try {
      const devices = await keyDetectionService.scanRemovableDevices();
      setRemovableDevices(devices);

      if (devices.length === 0) {
        setValidationErrors(['No removable devices detected. Please insert a USB drive or SD card.']);
      } else {
        setValidationErrors([]);
      }
    } catch (error) {
      console.error('Device detection failed:', error);
      setValidationErrors(['Device detection failed. Please check USB permissions.']);
    } finally {
      setIsDetectingDevices(false);
    }
  };

  const generateHardwareKey = async () => {
    if (!selectedDevice || !username.trim()) {
      setValidationErrors(['Please select a device and enter a username.']);
      return;
    }

    setIsGeneratingKey(true);
    setValidationErrors([]);

    try {
      // Generate keyfile using the CLI tool via Tauri command
      const result = await invoke<{
        userId: string;
        publicKey: string;
        fingerprint: string;
        keyFilePath: string;
      }>('generate_hardware_key', {
        username: username.trim(),
        devicePath: selectedDevice.path,
        validityDays: 365
      });

      const account: CreatedAccount = {
        accountType: 'hardware',
        userId: result.userId,
        username: username.trim(),
        publicKey: result.publicKey,
        fingerprint: result.fingerprint,
        hardwareKeyPresent: true
      };

      setGeneratedAccount(account);
      setCurrentStep('verification');

    } catch (error) {
      console.error('Key generation failed:', error);
      setValidationErrors([`Key generation failed: ${error}`]);
    } finally {
      setIsGeneratingKey(false);
    }
  };

  const createSoftwareAccount = async () => {
    if (!validateSoftwareInput()) {
      return;
    }

    try {
      // Create software-only account with passphrase-derived keys
      const result = await invoke<{
        userId: string;
        publicKey: string;
        fingerprint: string;
      }>('create_software_account', {
        username: username.trim(),
        passphrase: passphrase
      });

      const account: CreatedAccount = {
        accountType: 'software',
        userId: result.userId,
        username: username.trim(),
        publicKey: result.publicKey,
        fingerprint: result.fingerprint,
        hardwareKeyPresent: false
      };

      setGeneratedAccount(account);
      setCurrentStep('verification');

    } catch (error) {
      console.error('Software account creation failed:', error);
      setValidationErrors([`Account creation failed: ${error}`]);
    }
  };

  const importExistingKey = async () => {
    try {
      // Check for existing hardware key
      const currentKey = await keyDetectionService.getCurrentKey();

      if (!currentKey) {
        setImportError('No hardware key detected. Please insert your key device.');
        return;
      }

      if (!username.trim()) {
        setValidationErrors(['Please enter a username for this account.']);
        return;
      }

      const account: CreatedAccount = {
        accountType: 'hardware',
        userId: currentKey.keyFile.userId,
        username: username.trim(),
        publicKey: currentKey.keyFile.pubIdentityEd,
        fingerprint: currentKey.keyFile.fingerprint,
        hardwareKeyPresent: true,
        keyFile: currentKey
      };

      setDetectedKey(currentKey);
      setGeneratedAccount(account);
      setCurrentStep('verification');

    } catch (error) {
      console.error('Key import failed:', error);
      setImportError(`Key import failed: ${error}`);
    }
  };

  const validateSoftwareInput = (): boolean => {
    const errors: string[] = [];

    if (!username.trim()) {
      errors.push('Username is required.');
    }

    if (username.trim().length < 3) {
      errors.push('Username must be at least 3 characters.');
    }

    if (!passphrase) {
      errors.push('Passphrase is required.');
    }

    if (passphrase !== confirmPassphrase) {
      errors.push('Passphrases do not match.');
    }

    if (passphraseStrength === 'weak') {
      errors.push('Passphrase is too weak. Please use a stronger passphrase.');
    }

    if (!agreedToTerms) {
      errors.push('You must agree to the terms of use.');
    }

    setValidationErrors(errors);
    return errors.length === 0;
  };

  const calculatePassphraseStrength = (password: string): 'weak' | 'medium' | 'strong' => {
    let score = 0;

    // Length check
    if (password.length >= 12) score += 2;
    else if (password.length >= 8) score += 1;

    // Character variety
    if (/[a-z]/.test(password)) score += 1;
    if (/[A-Z]/.test(password)) score += 1;
    if (/\d/.test(password)) score += 1;
    if (/[^a-zA-Z\d]/.test(password)) score += 1;

    // Word count (for passphrases)
    const words = password.split(/\s+/).filter(w => w.length > 2);
    if (words.length >= 4) score += 2;

    if (score >= 6) return 'strong';
    if (score >= 4) return 'medium';
    return 'weak';
  };

  const handleComplete = () => {
    if (generatedAccount) {
      onComplete(generatedAccount);
    }
  };

  const renderStep = () => {
    switch (currentStep) {
      case 'welcome':
        return (
          <div className="account-setup-step">
            <h2>🔐 Welcome to Ephemeral Messenger</h2>
            <p>
              Before you can start using the secure messenger, we need to set up your account.
              This process will create your cryptographic identity and configure security settings.
            </p>
            <div className="security-notice">
              <h3>🛡️ Security Notice</h3>
              <ul>
                <li>Your keys will be generated locally and never transmitted</li>
                <li>Choose hardware keys for maximum security</li>
                <li>Software-only accounts are less secure but more convenient</li>
                <li>All communications are end-to-end encrypted</li>
              </ul>
            </div>
            <div className="step-actions">
              <button
                className="btn-primary"
                onClick={() => setCurrentStep('choose-method')}
              >
                Continue Setup
              </button>
              {onCancel && (
                <button className="btn-secondary" onClick={onCancel}>
                  Cancel
                </button>
              )}
            </div>
          </div>
        );

      case 'choose-method':
        return (
          <div className="account-setup-step">
            <h2>Choose Setup Method</h2>
            <p>Select how you'd like to secure your account:</p>

            <div className="setup-methods">
              <div
                className={`setup-method ${setupMethod === 'hardware' ? 'selected' : ''}`}
                onClick={() => setSetupMethod('hardware')}
              >
                <h3>🔐 Hardware Key (Recommended)</h3>
                <p>
                  Generate a new hardware key on a USB drive or SD card.
                  Provides the highest security level.
                </p>
                <ul>
                  <li>✅ Maximum security</li>
                  <li>✅ Tamper-evident</li>
                  <li>✅ Portable between devices</li>
                  <li>⚠️ Requires removable media</li>
                </ul>
              </div>

              <div
                className={`setup-method ${setupMethod === 'software' ? 'selected' : ''}`}
                onClick={() => setSetupMethod('software')}
              >
                <h3>💻 Software-Only Account</h3>
                <p>
                  Create an account secured with a strong passphrase.
                  More convenient but less secure.
                </p>
                <ul>
                  <li>✅ No additional hardware needed</li>
                  <li>✅ Quick setup</li>
                  <li>⚠️ Less secure than hardware keys</li>
                  <li>⚠️ Vulnerable to device compromise</li>
                </ul>
              </div>

              <div
                className={`setup-method ${setupMethod === 'import' ? 'selected' : ''}`}
                onClick={() => setSetupMethod('import')}
              >
                <h3>📥 Import Existing Key</h3>
                <p>
                  Use an existing hardware key that you've already created.
                </p>
                <ul>
                  <li>✅ Use existing key</li>
                  <li>✅ No new key generation</li>
                  <li>⚠️ Requires existing hardware key</li>
                </ul>
              </div>
            </div>

            <div className="step-actions">
              <button
                className="btn-primary"
                disabled={!setupMethod}
                onClick={() => {
                  if (setupMethod === 'hardware') setCurrentStep('hardware-setup');
                  else if (setupMethod === 'software') setCurrentStep('software-setup');
                  else if (setupMethod === 'import') setCurrentStep('import-existing');
                }}
              >
                Continue
              </button>
              <button
                className="btn-secondary"
                onClick={() => setCurrentStep('welcome')}
              >
                Back
              </button>
            </div>
          </div>
        );

      case 'hardware-setup':
        return (
          <div className="account-setup-step">
            <h2>🔐 Hardware Key Setup</h2>
            <p>We'll create a secure keyfile on removable media.</p>

            <div className="form-group">
              <label htmlFor="username">Username:</label>
              <input
                id="username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                className="form-input"
              />
            </div>

            <div className="form-group">
              <label>Removable Device Selection:</label>
              <button
                className="btn-secondary"
                onClick={detectRemovableDevices}
                disabled={isDetectingDevices}
              >
                {isDetectingDevices ? '🔍 Detecting...' : '🔍 Detect Devices'}
              </button>
            </div>

            {removableDevices.length > 0 && (
              <div className="device-list">
                <h4>Available Devices:</h4>
                {removableDevices.map((device, index) => (
                  <div
                    key={index}
                    className={`device-item ${selectedDevice === device ? 'selected' : ''}`}
                    onClick={() => setSelectedDevice(device)}
                  >
                    <div className="device-info">
                      <strong>{device.name}</strong>
                      <span className="device-path">{device.path}</span>
                      <span className="device-size">{device.size}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {validationErrors.length > 0 && (
              <div className="validation-errors">
                {validationErrors.map((error, index) => (
                  <div key={index} className="error-message">{error}</div>
                ))}
              </div>
            )}

            <div className="step-actions">
              <button
                className="btn-primary"
                disabled={!selectedDevice || !username.trim() || isGeneratingKey}
                onClick={generateHardwareKey}
              >
                {isGeneratingKey ? '🔄 Generating Key...' : '🔐 Generate Hardware Key'}
              </button>
              <button
                className="btn-secondary"
                onClick={() => setCurrentStep('choose-method')}
              >
                Back
              </button>
            </div>
          </div>
        );

      case 'software-setup':
        return (
          <div className="account-setup-step">
            <h2>💻 Software Account Setup</h2>
            <p>Create an account secured with a strong passphrase.</p>

            <div className="form-group">
              <label htmlFor="sw-username">Username:</label>
              <input
                id="sw-username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter your username"
                className="form-input"
              />
            </div>

            <div className="form-group">
              <label htmlFor="passphrase">Master Passphrase:</label>
              <input
                id="passphrase"
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Enter a strong passphrase"
                className="form-input"
              />
              <div className={`passphrase-strength ${passphraseStrength}`}>
                Strength: {passphraseStrength.toUpperCase()}
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="confirm-passphrase">Confirm Passphrase:</label>
              <input
                id="confirm-passphrase"
                type="password"
                value={confirmPassphrase}
                onChange={(e) => setConfirmPassphrase(e.target.value)}
                placeholder="Confirm your passphrase"
                className="form-input"
              />
            </div>

            <div className="passphrase-requirements">
              <h4>Passphrase Requirements:</h4>
              <ul>
                <li>At least 12 characters long</li>
                <li>Mix of uppercase and lowercase letters</li>
                <li>Include numbers and special characters</li>
                <li>Consider using a memorable phrase</li>
              </ul>
            </div>

            <div className="form-group">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={agreedToTerms}
                  onChange={(e) => setAgreedToTerms(e.target.checked)}
                />
                I understand that software-only accounts are less secure than hardware keys
              </label>
            </div>

            {validationErrors.length > 0 && (
              <div className="validation-errors">
                {validationErrors.map((error, index) => (
                  <div key={index} className="error-message">{error}</div>
                ))}
              </div>
            )}

            <div className="step-actions">
              <button
                className="btn-primary"
                onClick={createSoftwareAccount}
              >
                🔐 Create Account
              </button>
              <button
                className="btn-secondary"
                onClick={() => setCurrentStep('choose-method')}
              >
                Back
              </button>
            </div>
          </div>
        );

      case 'import-existing':
        return (
          <div className="account-setup-step">
            <h2>📥 Import Existing Hardware Key</h2>
            <p>Insert your existing hardware key and we'll import your account.</p>

            <div className="form-group">
              <label htmlFor="import-username">Username for this device:</label>
              <input
                id="import-username"
                type="text"
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="Enter username for this device"
                className="form-input"
              />
            </div>

            {detectedKey && (
              <div className="detected-key-info">
                <h4>📱 Detected Hardware Key:</h4>
                <div className="key-details">
                  <div>User ID: {detectedKey.keyFile.userId}</div>
                  <div>Fingerprint: {detectedKey.keyFile.fingerprint}</div>
                  <div>Expires: {new Date(detectedKey.keyFile.expiresAt).toLocaleDateString()}</div>
                  <div>Valid: {detectedKey.keyFile.signatureValid ? '✅' : '❌'}</div>
                </div>
              </div>
            )}

            {importError && (
              <div className="error-message">{importError}</div>
            )}

            {validationErrors.length > 0 && (
              <div className="validation-errors">
                {validationErrors.map((error, index) => (
                  <div key={index} className="error-message">{error}</div>
                ))}
              </div>
            )}

            <div className="step-actions">
              <button
                className="btn-primary"
                onClick={importExistingKey}
              >
                📥 Import Key
              </button>
              <button
                className="btn-secondary"
                onClick={() => setCurrentStep('choose-method')}
              >
                Back
              </button>
            </div>
          </div>
        );

      case 'verification':
        return (
          <div className="account-setup-step">
            <h2>✅ Account Created Successfully</h2>

            {generatedAccount && (
              <div className="account-summary">
                <h3>📋 Account Summary:</h3>
                <div className="account-details">
                  <div><strong>Username:</strong> {generatedAccount.username}</div>
                  <div><strong>Account Type:</strong> {generatedAccount.accountType}</div>
                  <div><strong>User ID:</strong> {generatedAccount.userId}</div>
                  <div><strong>Fingerprint:</strong> {generatedAccount.fingerprint}</div>
                  <div><strong>Hardware Key:</strong> {generatedAccount.hardwareKeyPresent ? '✅ Present' : '❌ Not Present'}</div>
                </div>

                {generatedAccount.accountType === 'hardware' && (
                  <div className="security-notice">
                    <h4>🔐 Important Security Information:</h4>
                    <ul>
                      <li>Keep your hardware key safe - it cannot be recovered if lost</li>
                      <li>Make backup copies of your keyfile if possible</li>
                      <li>Your key will be required each time you start the application</li>
                      <li>Remove the key when finished to enhance security</li>
                    </ul>
                  </div>
                )}

                {generatedAccount.accountType === 'software' && (
                  <div className="security-notice">
                    <h4>💻 Software Account Security:</h4>
                    <ul>
                      <li>Remember your master passphrase - it cannot be recovered</li>
                      <li>Consider upgrading to a hardware key for better security</li>
                      <li>Your passphrase protects your cryptographic keys</li>
                      <li>Use additional security measures on your device</li>
                    </ul>
                  </div>
                )}
              </div>
            )}

            <div className="step-actions">
              <button
                className="btn-primary"
                onClick={handleComplete}
              >
                🚀 Start Using Ephemeral Messenger
              </button>
            </div>
          </div>
        );

      default:
        return <div>Unknown step</div>;
    }
  };

  return (
    <div className="account-setup">
      <div className="setup-progress">
        <div className="progress-indicator">
          Step {
            currentStep === 'welcome' ? 1 :
            currentStep === 'choose-method' ? 2 :
            (currentStep === 'hardware-setup' || currentStep === 'software-setup' || currentStep === 'import-existing') ? 3 :
            currentStep === 'verification' ? 4 : 4
          } of 4
        </div>
      </div>

      <div className="setup-content">
        {renderStep()}
      </div>
    </div>
  );
};