import React, { useState } from 'react';
import { invoke } from '../services/api';
import { Identity } from '../types';
import './IdentityManager.css';

interface IdentityManagerProps {
  onIdentityCreated: (identity: Identity) => void;
  onError: (error: string) => void;
}

const IdentityManager: React.FC<IdentityManagerProps> = ({
  onIdentityCreated,
  onError,
}) => {
  const [passphrase, setPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [isCreating, setIsCreating] = useState(false);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [useHardwareToken, setUseHardwareToken] = useState(false);

  const validatePassphrase = (pass: string): string | null => {
    if (pass.length < 12) {
      return 'Passphrase must be at least 12 characters long';
    }
    if (!/(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])/.test(pass)) {
      return 'Passphrase must contain uppercase, lowercase, number, and special character';
    }
    return null;
  };

  const handleCreateIdentity = async () => {
    if (passphrase !== confirmPassphrase) {
      onError('Passphrases do not match');
      return;
    }

    const validationError = validatePassphrase(passphrase);
    if (validationError) {
      onError(validationError);
      return;
    }

    try {
      setIsCreating(true);

      const identity = await invoke('create_identity', {
        passphrase,
        useHardwareToken,
      });

      onIdentityCreated(identity);

      // Clear sensitive data
      setPassphrase('');
      setConfirmPassphrase('');

    } catch (error) {
      onError(`Failed to create identity: ${error}`);
    } finally {
      setIsCreating(false);
    }
  };

  const handleImportIdentity = async () => {
    try {
      const identity = await invoke('import_identity', {
        passphrase,
      });
      onIdentityCreated(identity);
    } catch (error) {
      onError(`Failed to import identity: ${error}`);
    }
  };

  return (
    <div className="identity-manager">
      <div className="identity-card">
        <h2>Create Secure Identity</h2>
        <p className="identity-description">
          Your identity is encrypted with your passphrase and stored only in memory.
          No data is written to disk.
        </p>

        <div className="form-group">
          <label htmlFor="passphrase">Master Passphrase</label>
          <input
            id="passphrase"
            type="password"
            value={passphrase}
            onChange={(e) => setPassphrase(e.target.value)}
            placeholder="Enter a strong passphrase..."
            className="passphrase-input"
            disabled={isCreating}
          />
          <small className="passphrase-hint">
            Minimum 12 characters with uppercase, lowercase, numbers, and symbols
          </small>
        </div>

        <div className="form-group">
          <label htmlFor="confirm-passphrase">Confirm Passphrase</label>
          <input
            id="confirm-passphrase"
            type="password"
            value={confirmPassphrase}
            onChange={(e) => setConfirmPassphrase(e.target.value)}
            placeholder="Confirm your passphrase..."
            className="passphrase-input"
            disabled={isCreating}
          />
        </div>

        <button
          className="advanced-toggle"
          onClick={() => setShowAdvanced(!showAdvanced)}
          type="button"
        >
          {showAdvanced ? '▼' : '▶'} Advanced Options
        </button>

        {showAdvanced && (
          <div className="advanced-options">
            <div className="checkbox-group">
              <input
                id="hardware-token"
                type="checkbox"
                checked={useHardwareToken}
                onChange={(e) => setUseHardwareToken(e.target.checked)}
                disabled={isCreating}
              />
              <label htmlFor="hardware-token">
                Use Hardware Token (YubiKey/OpenPGP)
              </label>
            </div>
          </div>
        )}

        <div className="button-group">
          <button
            className="create-button primary"
            onClick={handleCreateIdentity}
            disabled={isCreating || !passphrase || !confirmPassphrase}
          >
            {isCreating ? 'Creating...' : 'Create Identity'}
          </button>

          <button
            className="import-button secondary"
            onClick={handleImportIdentity}
            disabled={isCreating || !passphrase}
          >
            Import Existing
          </button>
        </div>

        <div className="security-notice">
          <h3>🔒 Security Notice</h3>
          <ul>
            <li>Your passphrase cannot be recovered if lost</li>
            <li>Identity keys are generated using secure random sources</li>
            <li>All data is encrypted with military-grade algorithms</li>
            <li>No telemetry or tracking is performed</li>
          </ul>
        </div>
      </div>
    </div>
  );
};

export default IdentityManager;