/**
 * Translation Manager Component
 *
 * Handles translation selection and ESV license management
 * Ensures proper licensing compliance
 */

import React, { useState } from 'react';

interface Translation {
  id: string;
  name: string;
  abbreviation: string;
  language: string;
  licenseRequired: boolean;
  available: boolean;
  description: string;
  copyright?: string;
}

interface ESVLicense {
  apiKey: string;
  licenseType: 'api' | 'file';
  filePath?: string;
  validated: boolean;
  expiresAt?: string;
}

interface TranslationManagerProps {
  translations: Translation[];
  selectedTranslation: string;
  onTranslationChange: (translationId: string) => void;
  esvLicense: ESVLicense | null;
  onESVLicenseSetup: (licenseData: Partial<ESVLicense>) => void;
}

export const TranslationManager: React.FC<TranslationManagerProps> = ({
  translations,
  selectedTranslation,
  onTranslationChange,
  esvLicense,
  onESVLicenseSetup
}) => {
  const [showLicenseSetup, setShowLicenseSetup] = useState(false);
  const [licenseType, setLicenseType] = useState<'api' | 'file'>('api');
  const [apiKey, setApiKey] = useState('');
  const [filePath, setFilePath] = useState('');
  const [isValidating, setIsValidating] = useState(false);

  const handleTranslationSelect = (translationId: string) => {
    const translation = translations.find(t => t.id === translationId);

    if (translation?.licenseRequired && translationId === 'esv') {
      if (!esvLicense || !esvLicense.validated) {
        setShowLicenseSetup(true);
        return;
      }
    }

    onTranslationChange(translationId);
  };

  const handleLicenseSubmit = async () => {
    if (licenseType === 'api' && !apiKey.trim()) {
      alert('Please enter your ESV API key');
      return;
    }

    if (licenseType === 'file' && !filePath.trim()) {
      alert('Please select your ESV file');
      return;
    }

    setIsValidating(true);
    try {
      const licenseData: Partial<ESVLicense> = {
        licenseType,
        apiKey: licenseType === 'api' ? apiKey : '',
        filePath: licenseType === 'file' ? filePath : undefined
      };

      await onESVLicenseSetup(licenseData);
      setShowLicenseSetup(false);
      setApiKey('');
      setFilePath('');
    } catch (error) {
      console.error('License setup failed:', error);
    } finally {
      setIsValidating(false);
    }
  };

  const handleFileSelect = async () => {
    try {
      // In real implementation, would use Tauri file dialog
      const selectedFile = await window.showOpenFilePicker?.({
        types: [{
          description: 'ESV files',
          accept: {
            'application/json': ['.json'],
            'application/epub+zip': ['.epub'],
            'application/xml': ['.xml']
          }
        }]
      });

      if (selectedFile?.[0]) {
        setFilePath(selectedFile[0].name);
      }
    } catch (error) {
      console.error('File selection failed:', error);
      // Fallback to text input
      const path = prompt('Enter the full path to your ESV file:');
      if (path) {
        setFilePath(path);
      }
    }
  };

  const availableTranslations = translations.filter(t => t.available);
  const unavailableTranslations = translations.filter(t => !t.available);

  return (
    <div className="card">
      <div className="card-header">
        <h3 className="text-lg font-semibold">Translation</h3>
        <p className="text-sm text-tertiary">Select Bible translation</p>
      </div>

      <div className="card-content">
        {/* Translation Selection */}
        <div className="space-y-sm">
          {availableTranslations.map(translation => (
            <div
              key={translation.id}
              className={`translation-option ${
                selectedTranslation === translation.id ? 'selected' : ''
              }`}
              onClick={() => handleTranslationSelect(translation.id)}
            >
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-sm">
                    <input
                      type="radio"
                      className="form-radio"
                      checked={selectedTranslation === translation.id}
                      onChange={() => {}} // handled by onClick
                    />
                    <div>
                      <div className="font-medium">
                        {translation.name} ({translation.abbreviation})
                      </div>
                      <div className="text-sm text-tertiary">
                        {translation.description}
                      </div>
                      {translation.copyright && (
                        <div className="text-xs text-tertiary mt-1">
                          {translation.copyright}
                        </div>
                      )}
                    </div>
                  </div>
                </div>

                {translation.licenseRequired && (
                  <div className="flex items-center gap-sm">
                    {translation.id === 'esv' && esvLicense?.validated ? (
                      <span className="status-success text-xs">Licensed</span>
                    ) : (
                      <span className="status-warning text-xs">License Required</span>
                    )}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* ESV License Status */}
        {selectedTranslation === 'esv' && (
          <div className="mt-lg">
            {esvLicense?.validated ? (
              <div className="bg-success/10 border border-success/20 rounded-lg p-md">
                <div className="flex items-center gap-sm mb-sm">
                  <span className="text-success">✓</span>
                  <span className="font-medium text-success">ESV License Active</span>
                </div>
                <div className="text-sm text-secondary">
                  License type: {esvLicense.licenseType.toUpperCase()}
                  {esvLicense.expiresAt && (
                    <div>Expires: {new Date(esvLicense.expiresAt).toLocaleDateString()}</div>
                  )}
                </div>
                <button
                  className="btn btn-ghost btn-sm mt-sm"
                  onClick={() => setShowLicenseSetup(true)}
                >
                  Update License
                </button>
              </div>
            ) : (
              <div className="bg-warning/10 border border-warning/20 rounded-lg p-md">
                <div className="flex items-center gap-sm mb-sm">
                  <span className="text-warning">⚠</span>
                  <span className="font-medium text-warning">ESV License Required</span>
                </div>
                <div className="text-sm text-secondary mb-md">
                  The ESV translation requires a license from Crossway. You can use an API key or provide your own ESV file.
                </div>
                <button
                  className="btn btn-warning btn-sm"
                  onClick={() => setShowLicenseSetup(true)}
                >
                  Setup ESV License
                </button>
              </div>
            )}
          </div>
        )}

        {/* Unavailable Translations */}
        {unavailableTranslations.length > 0 && (
          <div className="mt-lg">
            <h4 className="font-medium text-tertiary mb-sm">Additional Translations</h4>
            <div className="space-y-xs">
              {unavailableTranslations.map(translation => (
                <div
                  key={translation.id}
                  className="translation-option disabled"
                >
                  <div className="flex items-center gap-sm">
                    <input
                      type="radio"
                      className="form-radio"
                      disabled
                    />
                    <div className="opacity-60">
                      <div className="font-medium">
                        {translation.name} ({translation.abbreviation})
                      </div>
                      <div className="text-sm text-tertiary">
                        {translation.description} - Not available
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* License Information */}
        <div className="mt-lg pt-lg border-t border-border">
          <h4 className="font-medium mb-sm">License Information</h4>
          <div className="text-sm text-tertiary space-y-2">
            <p>
              • <strong>KJV:</strong> Public domain, freely available
            </p>
            <p>
              • <strong>ESV:</strong> Requires license from Crossway Publishers
            </p>
            <p>
              • <strong>Hebrew/Greek:</strong> Public domain and Creative Commons texts
            </p>
          </div>
        </div>
      </div>

      {/* ESV License Setup Modal */}
      {showLicenseSetup && (
        <div className="fixed inset-0 bg-overlay flex items-center justify-center z-50">
          <div className="card w-full max-w-lg mx-lg">
            <div className="card-header">
              <h3 className="text-lg font-semibold">Setup ESV License</h3>
              <p className="text-sm text-tertiary">
                Enter your Crossway ESV license information
              </p>
            </div>

            <div className="card-content">
              {/* License Type Selection */}
              <div className="form-group">
                <label className="form-label">License Type</label>
                <div className="flex gap-md">
                  <label className="flex items-center gap-sm">
                    <input
                      type="radio"
                      className="form-radio"
                      checked={licenseType === 'api'}
                      onChange={() => setLicenseType('api')}
                    />
                    API Key
                  </label>
                  <label className="flex items-center gap-sm">
                    <input
                      type="radio"
                      className="form-radio"
                      checked={licenseType === 'file'}
                      onChange={() => setLicenseType('file')}
                    />
                    Offline File
                  </label>
                </div>
              </div>

              {/* API Key Input */}
              {licenseType === 'api' && (
                <div className="form-group">
                  <label className="form-label">ESV API Key</label>
                  <input
                    type="password"
                    className="form-input"
                    placeholder="Enter your Crossway API key"
                    value={apiKey}
                    onChange={(e) => setApiKey(e.target.value)}
                  />
                  <p className="text-xs text-tertiary mt-sm">
                    Get your API key from{' '}
                    <a
                      href="https://api.esv.org"
                      target="_blank"
                      rel="noopener noreferrer"
                      className="text-primary underline"
                    >
                      api.esv.org
                    </a>
                  </p>
                </div>
              )}

              {/* File Input */}
              {licenseType === 'file' && (
                <div className="form-group">
                  <label className="form-label">ESV File</label>
                  <div className="flex gap-sm">
                    <input
                      type="text"
                      className="form-input flex-1"
                      placeholder="Select your ESV file..."
                      value={filePath}
                      onChange={(e) => setFilePath(e.target.value)}
                    />
                    <button
                      className="btn btn-secondary"
                      onClick={handleFileSelect}
                    >
                      Browse
                    </button>
                  </div>
                  <p className="text-xs text-tertiary mt-sm">
                    Supported formats: JSON, EPUB, XML
                  </p>
                </div>
              )}

              {/* Legal Notice */}
              <div className="bg-surface-elevated p-md rounded-lg border border-border">
                <h4 className="font-medium mb-sm">📜 Legal Notice</h4>
                <p className="text-sm text-tertiary">
                  The ESV® Bible (The Holy Bible, English Standard Version®) is copyrighted by Crossway.
                  You must have a valid license to use ESV text in this application.
                  The application will never transmit ESV content without proper authorization.
                </p>
              </div>
            </div>

            <div className="card-footer">
              <div className="flex gap-md justify-end">
                <button
                  className="btn btn-ghost"
                  onClick={() => {
                    setShowLicenseSetup(false);
                    setApiKey('');
                    setFilePath('');
                  }}
                  disabled={isValidating}
                >
                  Cancel
                </button>
                <button
                  className="btn btn-primary"
                  onClick={handleLicenseSubmit}
                  disabled={isValidating || (licenseType === 'api' && !apiKey.trim()) || (licenseType === 'file' && !filePath.trim())}
                >
                  {isValidating ? (
                    <>
                      <div className="spinner mr-sm"></div>
                      Validating...
                    </>
                  ) : (
                    'Setup License'
                  )}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Additional CSS styles for translation options
const translationStyles = `
.translation-option {
  padding: 0.75rem;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.translation-option:hover:not(.disabled) {
  background: var(--color-primary-subtle);
  border-color: var(--color-primary);
}

.translation-option.selected {
  background: var(--color-primary-subtle);
  border-color: var(--color-primary);
  box-shadow: 0 0 0 2px var(--color-primary-subtle);
}

.translation-option.disabled {
  opacity: 0.6;
  cursor: not-allowed;
}

.translation-option.disabled:hover {
  background: transparent;
  border-color: var(--color-border);
}
`;