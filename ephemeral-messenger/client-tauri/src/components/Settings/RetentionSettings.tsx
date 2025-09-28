/**
 * Retention Settings Component
 *
 * Manages data retention policies and burner account creation
 * Provides granular control over data persistence and privacy
 */

import React, { useState, useEffect } from 'react';

interface RetentionPolicy {
  mode: 'memory_only' | 'session_only' | 'bounded' | 'explicit_keep';
  ttl?: number; // seconds
  maxSize?: number; // bytes
  createdAt: string;
  updatedAt: string;
}

interface BurnerAccount {
  id: string;
  onionAddress: string;
  createdAt: string;
  expiresAt: string;
  ttl: string;
  connectionCount: number;
  messagesSent: number;
  messagesReceived: number;
  dataTransferred: number;
  active: boolean;
  destroyed: boolean;
}

interface RetentionStats {
  totalConversations: number;
  memoryOnlyCount: number;
  boundedCount: number;
  persistentCount: number;
  sessionCount: number;
  activeSessions: number;
  totalDataSize: number;
  expiredMessages: number;
}

interface BurnerStats {
  totalCreated: number;
  totalDestroyed: number;
  activeCount: number;
  expiredCount: number;
  totalMessages: number;
  totalDataTransfer: number;
  activeAccounts: Array<{
    id: string;
    createdAt: number;
    expiresAt: number;
    messagesSent: number;
    messagesReceived: number;
    connections: number;
    dataTransferred: number;
  }>;
}

export const RetentionSettings: React.FC = () => {
  const [currentPolicy, setCurrentPolicy] = useState<RetentionPolicy | null>(null);
  const [retentionStats, setRetentionStats] = useState<RetentionStats | null>(null);
  const [burnerStats, setBurnerStats] = useState<BurnerStats | null>(null);
  const [activeBurner, setActiveBurner] = useState<BurnerAccount | null>(null);
  const [isCreatingBurner, setIsCreatingBurner] = useState(false);
  const [isLoading, setIsLoading] = useState(true);

  // Form state
  const [selectedMode, setSelectedMode] = useState<RetentionPolicy['mode']>('bounded');
  const [customTTL, setCustomTTL] = useState<number>(24); // hours
  const [customMaxSize, setCustomMaxSize] = useState<number>(100); // MB
  const [burnerTTL, setBurnerTTL] = useState<number>(6); // hours

  useEffect(() => {
    loadRetentionData();
    const interval = setInterval(loadRetentionData, 30000); // Refresh every 30 seconds
    return () => clearInterval(interval);
  }, []);

  const loadRetentionData = async () => {
    try {
      // Load current retention policy, stats, and burner account info
      // This would be implemented with actual Tauri commands
      setIsLoading(false);
    } catch (error) {
      console.error('Failed to load retention data:', error);
      setIsLoading(false);
    }
  };

  const handleRetentionPolicyChange = async () => {
    try {
      const newPolicy: Partial<RetentionPolicy> = {
        mode: selectedMode,
        ttl: selectedMode === 'bounded' ? customTTL * 3600 : undefined, // Convert hours to seconds
        maxSize: customMaxSize * 1024 * 1024, // Convert MB to bytes
      };

      // Update retention policy via Tauri command
      console.log('Updating retention policy:', newPolicy);

      // Refresh data
      await loadRetentionData();
    } catch (error) {
      console.error('Failed to update retention policy:', error);
    }
  };

  const handleCreateBurnerAccount = async () => {
    setIsCreatingBurner(true);
    try {
      const burnerConfig = {
        ttl: burnerTTL * 3600, // Convert hours to seconds
      };

      // Create burner account via Tauri command
      console.log('Creating burner account:', burnerConfig);

      // Refresh data
      await loadRetentionData();
    } catch (error) {
      console.error('Failed to create burner account:', error);
    } finally {
      setIsCreatingBurner(false);
    }
  };

  const handleDestroyBurnerAccount = async (accountId: string, reason: string) => {
    try {
      // Destroy burner account via Tauri command
      console.log('Destroying burner account:', accountId, reason);

      // Refresh data
      await loadRetentionData();
    } catch (error) {
      console.error('Failed to destroy burner account:', error);
    }
  };

  const formatBytes = (bytes: number): string => {
    const units = ['B', 'KB', 'MB', 'GB'];
    let size = bytes;
    let unitIndex = 0;

    while (size >= 1024 && unitIndex < units.length - 1) {
      size /= 1024;
      unitIndex++;
    }

    return `${size.toFixed(1)} ${units[unitIndex]}`;
  };

  const formatDuration = (seconds: number): string => {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);

    if (hours > 0) {
      return `${hours}h ${minutes}m`;
    }
    return `${minutes}m`;
  };

  if (isLoading) {
    return (
      <div className="card">
        <div className="card-content">
          <div className="flex items-center justify-center py-lg">
            <div className="spinner mr-sm"></div>
            Loading retention settings...
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-lg">
      {/* Retention Policy Settings */}
      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-semibold">📦 Data Retention Policy</h3>
          <p className="text-sm text-tertiary">Control how long conversations are stored</p>
        </div>

        <div className="card-content">
          {/* Current Policy Display */}
          {currentPolicy && (
            <div className="bg-surface-elevated p-md rounded-lg border border-border mb-lg">
              <div className="flex items-center gap-sm mb-sm">
                <span className="text-success">✓</span>
                <span className="font-medium">Current Policy: {currentPolicy.mode.replace('_', ' ').toUpperCase()}</span>
              </div>
              {currentPolicy.mode === 'bounded' && currentPolicy.ttl && (
                <div className="text-sm text-secondary">
                  TTL: {formatDuration(currentPolicy.ttl)}
                </div>
              )}
              {currentPolicy.maxSize && (
                <div className="text-sm text-secondary">
                  Max Size: {formatBytes(currentPolicy.maxSize)}
                </div>
              )}
            </div>
          )}

          {/* Policy Selection */}
          <div className="space-y-md">
            <div className="form-group">
              <label className="form-label">Retention Mode</label>
              <div className="space-y-sm">
                {[
                  {
                    value: 'memory_only' as const,
                    title: 'Memory Only',
                    description: 'Data exists only in memory, never written to disk',
                    icon: '🧠',
                    security: 'Highest Security'
                  },
                  {
                    value: 'session_only' as const,
                    title: 'Session Only',
                    description: 'Data cleared when client disconnects',
                    icon: '🔄',
                    security: 'High Security'
                  },
                  {
                    value: 'bounded' as const,
                    title: 'Time Bounded',
                    description: 'Data expires after configured time limit',
                    icon: '⏰',
                    security: 'Medium Security'
                  },
                  {
                    value: 'explicit_keep' as const,
                    title: 'Explicit Keep',
                    description: 'Data persists until manually deleted',
                    icon: '💾',
                    security: 'Standard Security'
                  }
                ].map((mode) => (
                  <div
                    key={mode.value}
                    className={`retention-mode-option ${selectedMode === mode.value ? 'selected' : ''}`}
                    onClick={() => setSelectedMode(mode.value)}
                  >
                    <div className="flex items-start gap-md">
                      <input
                        type="radio"
                        className="form-radio mt-1"
                        checked={selectedMode === mode.value}
                        onChange={() => {}} // handled by onClick
                      />
                      <div className="flex-1">
                        <div className="flex items-center gap-sm">
                          <span className="text-lg">{mode.icon}</span>
                          <div className="font-medium">{mode.title}</div>
                          <span className={`badge ${mode.security === 'Highest Security' ? 'badge-success' :
                                                      mode.security === 'High Security' ? 'badge-primary' :
                                                      mode.security === 'Medium Security' ? 'badge-warning' : 'badge-secondary'}`}>
                            {mode.security}
                          </span>
                        </div>
                        <div className="text-sm text-tertiary mt-1">
                          {mode.description}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* TTL Configuration for Bounded Mode */}
            {selectedMode === 'bounded' && (
              <div className="form-group">
                <label className="form-label">Time to Live (Hours)</label>
                <input
                  type="number"
                  className="form-input"
                  value={customTTL}
                  onChange={(e) => setCustomTTL(Number(e.target.value))}
                  min="1"
                  max="168" // 1 week
                  placeholder="24"
                />
                <p className="text-xs text-tertiary mt-sm">
                  Data will be automatically deleted after this time period
                </p>
              </div>
            )}

            {/* Size Limit Configuration */}
            <div className="form-group">
              <label className="form-label">Maximum Data Size (MB)</label>
              <input
                type="number"
                className="form-input"
                value={customMaxSize}
                onChange={(e) => setCustomMaxSize(Number(e.target.value))}
                min="1"
                max="1000" // 1GB
                placeholder="100"
              />
              <p className="text-xs text-tertiary mt-sm">
                Maximum total size for stored conversation data
              </p>
            </div>

            <button
              className="btn btn-primary"
              onClick={handleRetentionPolicyChange}
            >
              Update Retention Policy
            </button>
          </div>
        </div>
      </div>

      {/* Retention Statistics */}
      {retentionStats && (
        <div className="card">
          <div className="card-header">
            <h3 className="text-lg font-semibold">📊 Storage Statistics</h3>
          </div>
          <div className="card-content">
            <div className="grid grid-cols-2 gap-md">
              <div className="stat-item">
                <div className="stat-value">{retentionStats.totalConversations}</div>
                <div className="stat-label">Total Conversations</div>
              </div>
              <div className="stat-item">
                <div className="stat-value">{formatBytes(retentionStats.totalDataSize)}</div>
                <div className="stat-label">Total Data Size</div>
              </div>
              <div className="stat-item">
                <div className="stat-value">{retentionStats.memoryOnlyCount}</div>
                <div className="stat-label">Memory Only</div>
              </div>
              <div className="stat-item">
                <div className="stat-value">{retentionStats.sessionCount}</div>
                <div className="stat-label">Session Only</div>
              </div>
              <div className="stat-item">
                <div className="stat-value">{retentionStats.boundedCount}</div>
                <div className="stat-label">Time Bounded</div>
              </div>
              <div className="stat-item">
                <div className="stat-value">{retentionStats.persistentCount}</div>
                <div className="stat-label">Persistent</div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Burner Account Management */}
      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-semibold">🔥 Burner Accounts</h3>
          <p className="text-sm text-tertiary">Ephemeral single-use identities</p>
        </div>

        <div className="card-content">
          {/* Active Burner Account */}
          {activeBurner ? (
            <div className="bg-warning/10 border border-warning/20 rounded-lg p-md mb-lg">
              <div className="flex items-center gap-sm mb-sm">
                <span className="text-warning">🔥</span>
                <span className="font-medium">Active Burner Account</span>
                <span className="badge badge-warning">Ephemeral</span>
              </div>
              <div className="space-y-2 text-sm">
                <div><strong>ID:</strong> {activeBurner.id.slice(0, 8)}...</div>
                <div><strong>Onion:</strong> {activeBurner.onionAddress}</div>
                <div><strong>Expires:</strong> {new Date(activeBurner.expiresAt).toLocaleString()}</div>
                <div><strong>Messages:</strong> {activeBurner.messagesSent + activeBurner.messagesReceived}</div>
                <div><strong>Data:</strong> {formatBytes(activeBurner.dataTransferred)}</div>
              </div>
              <div className="flex gap-sm mt-md">
                <button
                  className="btn btn-warning btn-sm"
                  onClick={() => handleDestroyBurnerAccount(activeBurner.id, 'user_requested')}
                >
                  Destroy Account
                </button>
                <button className="btn btn-ghost btn-sm">
                  Extend TTL
                </button>
              </div>
            </div>
          ) : (
            <div className="bg-surface-elevated p-md rounded-lg border border-border mb-lg">
              <div className="flex items-center gap-sm mb-sm">
                <span>🔥</span>
                <span className="font-medium">No Active Burner Account</span>
              </div>
              <p className="text-sm text-tertiary">
                Create an ephemeral identity with enhanced privacy and automatic destruction
              </p>
            </div>
          )}

          {/* Create Burner Account */}
          {!activeBurner && (
            <div className="space-y-md">
              <div className="form-group">
                <label className="form-label">Burner Account TTL (Hours)</label>
                <input
                  type="number"
                  className="form-input"
                  value={burnerTTL}
                  onChange={(e) => setBurnerTTL(Number(e.target.value))}
                  min="1"
                  max="24" // Max 24 hours for burner accounts
                  placeholder="6"
                />
                <p className="text-xs text-tertiary mt-sm">
                  Account will auto-destruct after this time period
                </p>
              </div>

              <div className="bg-surface-elevated p-md rounded-lg border border-border">
                <h4 className="font-medium mb-sm">🔒 Burner Account Features</h4>
                <ul className="text-sm text-tertiary space-y-1">
                  <li>• Memory-only storage (no disk writes)</li>
                  <li>• Ephemeral Tor v3 onion service</li>
                  <li>• Client authentication required</li>
                  <li>• Tight message and data quotas</li>
                  <li>• Automatic TTL-based destruction</li>
                  <li>• Enhanced rate limiting</li>
                </ul>
              </div>

              <button
                className="btn btn-warning"
                onClick={handleCreateBurnerAccount}
                disabled={isCreatingBurner}
              >
                {isCreatingBurner ? (
                  <>
                    <div className="spinner mr-sm"></div>
                    Creating Burner Account...
                  </>
                ) : (
                  'Create Burner Account'
                )}
              </button>
            </div>
          )}

          {/* Burner Statistics */}
          {burnerStats && (
            <div className="mt-lg pt-lg border-t border-border">
              <h4 className="font-medium mb-md">Burner Account Statistics</h4>
              <div className="grid grid-cols-2 gap-md">
                <div className="stat-item">
                  <div className="stat-value">{burnerStats.totalCreated}</div>
                  <div className="stat-label">Total Created</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{burnerStats.activeCount}</div>
                  <div className="stat-label">Currently Active</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{burnerStats.expiredCount}</div>
                  <div className="stat-label">Expired</div>
                </div>
                <div className="stat-item">
                  <div className="stat-value">{burnerStats.totalMessages}</div>
                  <div className="stat-label">Total Messages</div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Privacy Notice */}
      <div className="card">
        <div className="card-header">
          <h3 className="text-lg font-semibold">🛡️ Privacy Notice</h3>
        </div>
        <div className="card-content">
          <div className="space-y-md text-sm text-tertiary">
            <p>
              <strong>Data Retention:</strong> This application gives you full control over data persistence.
              Memory-only and session-only modes provide the highest security by preventing data from being written to disk.
            </p>
            <p>
              <strong>Burner Accounts:</strong> Ephemeral identities are designed for maximum privacy.
              All cryptographic keys are stored only in locked memory and are securely erased upon destruction.
            </p>
            <p>
              <strong>No Telemetry:</strong> This application does not collect, transmit, or store any usage data or telemetry.
              All statistics shown are local only and never leave your device.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};

// Additional CSS styles
const retentionStyles = `
.retention-mode-option {
  padding: 1rem;
  border: 1px solid var(--color-border);
  border-radius: var(--radius-lg);
  cursor: pointer;
  transition: all var(--transition-fast);
}

.retention-mode-option:hover {
  background: var(--color-primary-subtle);
  border-color: var(--color-primary);
}

.retention-mode-option.selected {
  background: var(--color-primary-subtle);
  border-color: var(--color-primary);
  box-shadow: 0 0 0 2px var(--color-primary-subtle);
}

.stat-item {
  text-align: center;
  padding: 1rem;
  background: var(--color-surface-elevated);
  border-radius: var(--radius-md);
  border: 1px solid var(--color-border);
}

.stat-value {
  font-size: 1.5rem;
  font-weight: 600;
  color: var(--color-primary);
}

.stat-label {
  font-size: 0.875rem;
  color: var(--color-tertiary);
  margin-top: 0.25rem;
}

.badge {
  display: inline-block;
  padding: 0.25rem 0.5rem;
  font-size: 0.75rem;
  font-weight: 500;
  border-radius: var(--radius-sm);
  text-transform: uppercase;
}

.badge-success {
  background: var(--color-success-subtle);
  color: var(--color-success);
}

.badge-primary {
  background: var(--color-primary-subtle);
  color: var(--color-primary);
}

.badge-warning {
  background: var(--color-warning-subtle);
  color: var(--color-warning);
}

.badge-secondary {
  background: var(--color-surface-elevated);
  color: var(--color-secondary);
  border: 1px solid var(--color-border);
}
`;