import React, { useState, useEffect } from 'react';
import { hardwareTokenService, HardwareToken, TokenEnrollmentResult, TokenAuthResult } from '../services/hardwareTokenService';
import { yubiKeyService, YubiKeyCard, YubiKeyResponse } from '../services/yubiKeyService';

interface HardwareTokenManagerProps {
  className?: string;
}

const HardwareTokenManager: React.FC<HardwareTokenManagerProps> = ({ className }) => {
  const [tokens, setTokens] = useState<HardwareToken[]>([]);
  const [yubiKeys, setYubiKeys] = useState<YubiKeyCard[]>([]);
  const [isEnrolling, setIsEnrolling] = useState(false);
  const [enrollmentType, setEnrollmentType] = useState<'webauthn' | 'yubikey'>('webauthn');
  const [testingToken, setTestingToken] = useState<string | null>(null);
  const [enrollmentForm, setEnrollmentForm] = useState({
    username: '',
    displayName: '',
    pin: '',
    adminPin: '',
  });

  // YubiKey specific state
  const [yubiKeyConnected, setYubiKeyConnected] = useState(false);
  const [selectedSlot, setSelectedSlot] = useState<'signature' | 'encryption' | 'authentication'>('signature');
  const [keyGenForm, setKeyGenForm] = useState({
    algorithm: 'Ed25519' as 'RSA-2048' | 'RSA-4096' | 'ECC-P256' | 'Ed25519',
    adminPin: '',
  });

  useEffect(() => {
    loadTokens();
    initializeServices();
  }, []);

  const loadTokens = () => {
    const enrolledTokens = hardwareTokenService.getEnrolledTokens();
    setTokens(enrolledTokens);
  };

  const initializeServices = async () => {
    // Initialize YubiKey service
    const yubiKeyInit = await yubiKeyService.initialize();
    setYubiKeyConnected(yubiKeyInit);

    if (yubiKeyInit) {
      const cards = yubiKeyService.getConnectedCards();
      setYubiKeys(cards);
    }
  };

  const handleEnrollToken = async () => {
    if (!enrollmentForm.username || !enrollmentForm.displayName) {
      alert('Please fill in username and display name');
      return;
    }

    setIsEnrolling(true);

    try {
      let result: TokenEnrollmentResult;

      if (enrollmentType === 'webauthn') {
        result = await hardwareTokenService.enrollWebAuthnToken(
          enrollmentForm.username,
          enrollmentForm.displayName
        );
      } else {
        // YubiKey enrollment would go here
        result = { success: false, error: 'YubiKey enrollment not implemented yet' };
      }

      if (result.success) {
        setTokens(prev => [...prev, result.token!]);
        setEnrollmentForm({ username: '', displayName: '', pin: '', adminPin: '' });
        alert('Token enrolled successfully!');
      } else {
        alert(`Enrollment failed: ${result.error}`);
      }
    } catch (error) {
      alert(`Enrollment error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setIsEnrolling(false);
    }
  };

  const handleTestToken = async (tokenId: string) => {
    setTestingToken(tokenId);

    try {
      const result: TokenAuthResult = await hardwareTokenService.authenticateWithWebAuthn(tokenId);

      if (result.success) {
        alert('Token authentication successful!');
      } else {
        alert(`Authentication failed: ${result.error}`);
      }
    } catch (error) {
      alert(`Test error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    } finally {
      setTestingToken(null);
    }
  };

  const handleRevokeToken = (tokenId: string) => {
    if (confirm('Are you sure you want to revoke this token?')) {
      hardwareTokenService.revokeToken(tokenId);
      loadTokens();
    }
  };

  const handleRemoveToken = (tokenId: string) => {
    if (confirm('Are you sure you want to remove this token? This action cannot be undone.')) {
      hardwareTokenService.removeToken(tokenId);
      loadTokens();
    }
  };

  const handleConnectYubiKey = async () => {
    try {
      const connected = await yubiKeyService.requestDevice();
      setYubiKeyConnected(connected);

      if (connected) {
        const cards = yubiKeyService.getConnectedCards();
        setYubiKeys(cards);
      }
    } catch (error) {
      alert(`Failed to connect YubiKey: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  const handleGenerateYubiKeyPair = async () => {
    if (!keyGenForm.adminPin) {
      alert('Admin PIN is required for key generation');
      return;
    }

    try {
      const keyPair = await yubiKeyService.generateKeyPair(
        selectedSlot,
        keyGenForm.algorithm,
        keyGenForm.adminPin
      );

      if (keyPair) {
        alert(`Key pair generated successfully in ${selectedSlot} slot!`);
        // Refresh YubiKey cards
        const cards = yubiKeyService.getConnectedCards();
        setYubiKeys(cards);
      } else {
        alert('Key generation failed');
      }
    } catch (error) {
      alert(`Key generation error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  const handleSignWithYubiKey = async (slot: 'signature' | 'encryption' | 'authentication') => {
    if (!enrollmentForm.pin) {
      alert('PIN is required for signing');
      return;
    }

    try {
      const testData = new TextEncoder().encode('Test message for signing');
      const result: YubiKeyResponse = await yubiKeyService.sign(testData.buffer, slot, enrollmentForm.pin);

      if (result.success) {
        alert('Signing successful!');
      } else {
        alert(`Signing failed: ${result.error}`);
      }
    } catch (error) {
      alert(`Signing error: ${error instanceof Error ? error.message : 'Unknown error'}`);
    }
  };

  const getTokenStatusColor = (status: string) => {
    switch (status) {
      case 'active': return 'text-green-400';
      case 'inactive': return 'text-yellow-400';
      case 'revoked': return 'text-red-400';
      default: return 'text-gray-400';
    }
  };

  const getCapabilityIcon = (capability: string) => {
    switch (capability) {
      case 'authenticate': return '🔐';
      case 'sign': return '✍️';
      case 'encrypt': return '🔒';
      case 'decrypt': return '🔓';
      case 'derive_key': return '🔑';
      case 'resident_key': return '💾';
      case 'user_verification': return '👤';
      default: return '⚙️';
    }
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">Hardware Token Manager</h2>
        <div className="flex space-x-3">
          <span className={`px-3 py-1 rounded text-sm ${
            hardwareTokenService.isSupported() ? 'bg-green-800 text-green-200' : 'bg-red-800 text-red-200'
          }`}>
            {hardwareTokenService.isSupported() ? 'Supported' : 'Not Supported'}
          </span>
        </div>
      </div>

      {/* Enrollment Section */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Enroll New Token</h3>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Token Type Selection */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Token Type
            </label>
            <select
              value={enrollmentType}
              onChange={(e) => setEnrollmentType(e.target.value as 'webauthn' | 'yubikey')}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg
                       text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
            >
              <option value="webauthn">WebAuthn/FIDO2</option>
              <option value="yubikey">YubiKey OpenPGP</option>
            </select>
          </div>

          {/* Username */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Username
            </label>
            <input
              type="text"
              value={enrollmentForm.username}
              onChange={(e) => setEnrollmentForm(prev => ({ ...prev, username: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg
                       text-white placeholder-gray-400 focus:outline-none focus:ring-2
                       focus:ring-blue-500"
              placeholder="Enter username"
            />
          </div>

          {/* Display Name */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Display Name
            </label>
            <input
              type="text"
              value={enrollmentForm.displayName}
              onChange={(e) => setEnrollmentForm(prev => ({ ...prev, displayName: e.target.value }))}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg
                       text-white placeholder-gray-400 focus:outline-none focus:ring-2
                       focus:ring-blue-500"
              placeholder="Enter display name"
            />
          </div>

          {/* PIN (for YubiKey) */}
          {enrollmentType === 'yubikey' && (
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                PIN
              </label>
              <input
                type="password"
                value={enrollmentForm.pin}
                onChange={(e) => setEnrollmentForm(prev => ({ ...prev, pin: e.target.value }))}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg
                         text-white placeholder-gray-400 focus:outline-none focus:ring-2
                         focus:ring-blue-500"
                placeholder="Enter PIN"
              />
            </div>
          )}
        </div>

        <div className="mt-4">
          <button
            onClick={handleEnrollToken}
            disabled={isEnrolling || !hardwareTokenService.isSupported()}
            className="px-6 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700
                     text-white rounded-lg transition-colors"
          >
            {isEnrolling ? 'Enrolling...' : 'Enroll Token'}
          </button>
        </div>
      </div>

      {/* Enrolled Tokens */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">
          Enrolled Tokens ({tokens.length})
        </h3>

        {tokens.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            No tokens enrolled yet. Enroll a token to get started.
          </div>
        ) : (
          <div className="space-y-4">
            {tokens.map((token) => (
              <div
                key={token.id}
                className="flex items-center justify-between p-4 bg-gray-700 rounded-lg"
              >
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <h4 className="font-medium text-white">{token.name}</h4>
                    <span className="px-2 py-1 bg-gray-600 text-gray-300 text-xs rounded uppercase">
                      {token.type}
                    </span>
                    <span className={`text-sm ${getTokenStatusColor(token.status)}`}>
                      {token.status}
                    </span>
                  </div>

                  <div className="flex items-center space-x-4 text-sm text-gray-400">
                    <span>Enrolled: {token.enrolled.toLocaleDateString()}</span>
                    <span>Last used: {token.lastUsed.toLocaleDateString()}</span>
                    {token.metadata.manufacturer && (
                      <span>Manufacturer: {token.metadata.manufacturer}</span>
                    )}
                  </div>

                  <div className="flex items-center space-x-2 mt-2">
                    <span className="text-xs text-gray-400">Capabilities:</span>
                    {token.capabilities.map((cap) => (
                      <span
                        key={cap}
                        title={cap}
                        className="text-sm"
                      >
                        {getCapabilityIcon(cap)}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="flex space-x-2">
                  <button
                    onClick={() => handleTestToken(token.id)}
                    disabled={testingToken === token.id || token.status !== 'active'}
                    className="px-3 py-1 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-600
                             text-white text-sm rounded transition-colors"
                  >
                    {testingToken === token.id ? 'Testing...' : 'Test'}
                  </button>

                  {token.status === 'active' && (
                    <button
                      onClick={() => handleRevokeToken(token.id)}
                      className="px-3 py-1 bg-yellow-600 hover:bg-yellow-700 text-white
                               text-sm rounded transition-colors"
                    >
                      Revoke
                    </button>
                  )}

                  <button
                    onClick={() => handleRemoveToken(token.id)}
                    className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white
                             text-sm rounded transition-colors"
                  >
                    Remove
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* YubiKey Section */}
      <div className="bg-gray-800 rounded-lg p-6">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-white">YubiKey Management</h3>
          <span className={`px-3 py-1 rounded text-sm ${
            yubiKeyConnected ? 'bg-green-800 text-green-200' : 'bg-gray-700 text-gray-300'
          }`}>
            {yubiKeyConnected ? 'Connected' : 'Not Connected'}
          </span>
        </div>

        {!yubiKeyConnected ? (
          <div className="text-center py-8">
            <p className="text-gray-400 mb-4">No YubiKey connected</p>
            <button
              onClick={handleConnectYubiKey}
              className="px-6 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors"
            >
              Connect YubiKey
            </button>
          </div>
        ) : (
          <div className="space-y-6">
            {/* Connected YubiKeys */}
            {yubiKeys.map((card) => (
              <div key={card.serialNumber} className="border border-gray-600 rounded-lg p-4">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="text-white font-medium">
                    YubiKey {card.serialNumber} (v{card.version})
                  </h4>
                  <div className="flex space-x-2">
                    {card.capabilities.map((cap) => (
                      <span key={cap} className="px-2 py-1 bg-gray-600 text-gray-300 text-xs rounded">
                        {cap}
                      </span>
                    ))}
                  </div>
                </div>

                {/* Key Slots */}
                <div className="grid grid-cols-3 gap-4 mb-4">
                  {Object.entries(card.slots).map(([slotName, slot]) => (
                    <div key={slotName} className="text-center">
                      <h5 className="text-sm font-medium text-gray-300 mb-2 capitalize">
                        {slotName}
                      </h5>
                      <div className={`p-3 rounded border-2 ${
                        slot.occupied
                          ? 'border-green-500 bg-green-900/20'
                          : 'border-gray-600 bg-gray-700'
                      }`}>
                        {slot.occupied ? (
                          <div className="space-y-1">
                            <div className="text-green-400 text-xs">🔑 Key Present</div>
                            <div className="text-xs text-gray-400">{slot.algorithm}</div>
                            <button
                              onClick={() => handleSignWithYubiKey(slotName as any)}
                              className="mt-2 px-2 py-1 bg-blue-600 hover:bg-blue-700
                                       text-white text-xs rounded"
                            >
                              Test Sign
                            </button>
                          </div>
                        ) : (
                          <div className="text-gray-400 text-xs">Empty</div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>

                {/* Key Generation */}
                <div className="border-t border-gray-600 pt-4">
                  <h5 className="text-sm font-medium text-gray-300 mb-3">Generate New Key Pair</h5>
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                    <div>
                      <select
                        value={selectedSlot}
                        onChange={(e) => setSelectedSlot(e.target.value as any)}
                        className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded
                                 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        <option value="signature">Signature</option>
                        <option value="encryption">Encryption</option>
                        <option value="authentication">Authentication</option>
                      </select>
                    </div>
                    <div>
                      <select
                        value={keyGenForm.algorithm}
                        onChange={(e) => setKeyGenForm(prev => ({ ...prev, algorithm: e.target.value as any }))}
                        className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded
                                 text-white text-sm focus:outline-none focus:ring-2 focus:ring-blue-500"
                      >
                        <option value="Ed25519">Ed25519</option>
                        <option value="ECC-P256">ECC-P256</option>
                        <option value="RSA-2048">RSA-2048</option>
                        <option value="RSA-4096">RSA-4096</option>
                      </select>
                    </div>
                    <div>
                      <input
                        type="password"
                        value={keyGenForm.adminPin}
                        onChange={(e) => setKeyGenForm(prev => ({ ...prev, adminPin: e.target.value }))}
                        placeholder="Admin PIN"
                        className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded
                                 text-white text-sm placeholder-gray-400 focus:outline-none
                                 focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <button
                        onClick={handleGenerateYubiKeyPair}
                        disabled={!keyGenForm.adminPin}
                        className="w-full px-3 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-600
                                 text-white text-sm rounded transition-colors"
                      >
                        Generate
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

export default HardwareTokenManager;