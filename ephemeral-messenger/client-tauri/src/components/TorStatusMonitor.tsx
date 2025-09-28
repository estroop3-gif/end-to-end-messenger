import React, { useState, useEffect } from 'react';
import { torService, TorStatus, TorConfig } from '../services/torService';

interface TorStatusMonitorProps {
  className?: string;
}

const TorStatusMonitor: React.FC<TorStatusMonitorProps> = ({ className }) => {
  const [status, setStatus] = useState<TorStatus>(torService.getStatus());
  const [config, setConfig] = useState<TorConfig | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [bridgeConfig, setBridgeConfig] = useState({
    enabled: false,
    bridges: [''],
  });

  useEffect(() => {
    // Initialize Tor service
    initializeTor();

    // Set up event listeners
    const handleStatusChanged = (newStatus: TorStatus) => {
      setStatus(newStatus);
    };

    const handleConfigChanged = (newConfig: TorConfig) => {
      setConfig(newConfig);
    };

    const handleBootstrapComplete = () => {
      console.log('Tor bootstrap completed');
    };

    const handleBridgesEnabled = (bridges: string[]) => {
      setBridgeConfig({ enabled: true, bridges });
    };

    torService.on('statusChanged', handleStatusChanged);
    torService.on('configChanged', handleConfigChanged);
    torService.on('bootstrapComplete', handleBootstrapComplete);
    torService.on('bridgesEnabled', handleBridgesEnabled);

    return () => {
      torService.off('statusChanged', handleStatusChanged);
      torService.off('configChanged', handleConfigChanged);
      torService.off('bootstrapComplete', handleBootstrapComplete);
      torService.off('bridgesEnabled', handleBridgesEnabled);
    };
  }, []);

  const initializeTor = async () => {
    try {
      await torService.initialize();
    } catch (error) {
      console.error('Failed to initialize Tor:', error);
    }
  };

  const handleNewCircuit = async () => {
    try {
      await torService.newCircuit();
    } catch (error) {
      console.error('Failed to create new circuit:', error);
    }
  };

  const handleEnableBridges = async () => {
    const bridges = bridgeConfig.bridges.filter(bridge => bridge.trim() !== '');
    if (bridges.length === 0) return;

    try {
      await torService.enableBridges(bridges);
    } catch (error) {
      console.error('Failed to enable bridges:', error);
    }
  };

  const handleBridgeChange = (index: number, value: string) => {
    setBridgeConfig(prev => ({
      ...prev,
      bridges: prev.bridges.map((bridge, i) => i === index ? value : bridge)
    }));
  };

  const addBridgeField = () => {
    setBridgeConfig(prev => ({
      ...prev,
      bridges: [...prev.bridges, '']
    }));
  };

  const removeBridgeField = (index: number) => {
    setBridgeConfig(prev => ({
      ...prev,
      bridges: prev.bridges.filter((_, i) => i !== index)
    }));
  };

  const getStatusColor = () => {
    if (!status.connected) return 'text-red-400';
    if (!status.bootstrapped) return 'text-yellow-400';
    return 'text-green-400';
  };

  const getStatusText = () => {
    if (!status.connected) return 'Disconnected';
    if (!status.bootstrapped) return `Bootstrapping... ${Math.round(status.bootstrapProgress)}%`;
    return 'Connected';
  };

  const getConnectionIcon = () => {
    if (!status.connected) return '🔴';
    if (!status.bootstrapped) return '🟡';
    return '🟢';
  };

  return (
    <div className={`bg-gray-800 rounded-lg p-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-xl font-bold text-white flex items-center space-x-2">
          <span>Tor Status</span>
          <span className="text-2xl">{getConnectionIcon()}</span>
        </h2>
        <button
          onClick={() => setShowAdvanced(!showAdvanced)}
          className="px-3 py-1 bg-gray-700 hover:bg-gray-600 text-white text-sm
                   rounded transition-colors"
        >
          {showAdvanced ? 'Hide Advanced' : 'Show Advanced'}
        </button>
      </div>

      {/* Status Overview */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="text-center">
          <div className={`text-2xl font-bold ${getStatusColor()}`}>
            {getStatusText()}
          </div>
          <div className="text-sm text-gray-400">Connection Status</div>
        </div>

        <div className="text-center">
          <div className="text-2xl font-bold text-white">
            {status.circuitCount}
          </div>
          <div className="text-sm text-gray-400">Active Circuits</div>
        </div>

        <div className="text-center">
          <div className="text-2xl font-bold text-white">
            {status.socksPort}
          </div>
          <div className="text-sm text-gray-400">SOCKS Port</div>
        </div>

        <div className="text-center">
          <div className="text-2xl font-bold text-white">
            {status.controlPort}
          </div>
          <div className="text-sm text-gray-400">Control Port</div>
        </div>
      </div>

      {/* Bootstrap Progress */}
      {status.connected && !status.bootstrapped && (
        <div className="mb-6">
          <div className="flex items-center justify-between mb-2">
            <span className="text-white font-medium">Bootstrap Progress</span>
            <span className="text-yellow-400">{Math.round(status.bootstrapProgress)}%</span>
          </div>
          <div className="w-full bg-gray-700 rounded-full h-2">
            <div
              className="bg-yellow-400 h-2 rounded-full transition-all duration-300"
              style={{ width: `${status.bootstrapProgress}%` }}
            />
          </div>
        </div>
      )}

      {/* Onion Address */}
      {status.onionAddress && (
        <div className="mb-6">
          <div className="text-sm font-medium text-gray-300 mb-2">Your Onion Address</div>
          <div className="flex items-center space-x-2">
            <code className="flex-1 px-3 py-2 bg-gray-700 rounded text-sm text-green-400 font-mono">
              {status.onionAddress}
            </code>
            <button
              onClick={() => navigator.clipboard.writeText(status.onionAddress!)}
              className="px-3 py-2 bg-blue-600 hover:bg-blue-700 text-white text-sm
                       rounded transition-colors"
            >
              Copy
            </button>
          </div>
        </div>
      )}

      {/* Error Display */}
      {status.error && (
        <div className="mb-6 p-3 bg-red-900/50 border border-red-700 rounded">
          <div className="text-red-400 font-medium">Error</div>
          <div className="text-red-300 text-sm">{status.error}</div>
        </div>
      )}

      {/* Actions */}
      <div className="flex space-x-3 mb-6">
        <button
          onClick={handleNewCircuit}
          disabled={!status.bootstrapped}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-700
                   text-white rounded transition-colors"
        >
          New Circuit
        </button>
        <button
          onClick={initializeTor}
          disabled={status.connected}
          className="px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-700
                   text-white rounded transition-colors"
        >
          Reconnect
        </button>
      </div>

      {/* Advanced Configuration */}
      {showAdvanced && (
        <div className="space-y-6 pt-6 border-t border-gray-700">
          <h3 className="text-lg font-semibold text-white">Advanced Configuration</h3>

          {/* Bridge Configuration */}
          <div>
            <h4 className="text-md font-medium text-white mb-3">Bridge Configuration</h4>
            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="enableBridges"
                  checked={bridgeConfig.enabled}
                  onChange={(e) => setBridgeConfig(prev => ({ ...prev, enabled: e.target.checked }))}
                  className="rounded bg-gray-700 border-gray-600 text-blue-600
                           focus:ring-blue-500 focus:ring-offset-gray-800"
                />
                <label htmlFor="enableBridges" className="text-white">
                  Enable Bridges (for censorship resistance)
                </label>
              </div>

              {bridgeConfig.enabled && (
                <div className="space-y-2">
                  {bridgeConfig.bridges.map((bridge, index) => (
                    <div key={index} className="flex items-center space-x-2">
                      <input
                        type="text"
                        value={bridge}
                        onChange={(e) => handleBridgeChange(index, e.target.value)}
                        placeholder="obfs4 IP:PORT fingerprint cert=CERT iat-mode=0"
                        className="flex-1 px-3 py-2 bg-gray-700 border border-gray-600 rounded
                                 text-white placeholder-gray-400 focus:outline-none focus:ring-2
                                 focus:ring-blue-500"
                      />
                      {bridgeConfig.bridges.length > 1 && (
                        <button
                          onClick={() => removeBridgeField(index)}
                          className="px-2 py-2 bg-red-600 hover:bg-red-700 text-white
                                   rounded transition-colors"
                        >
                          ×
                        </button>
                      )}
                    </div>
                  ))}

                  <div className="flex space-x-2">
                    <button
                      onClick={addBridgeField}
                      className="px-3 py-1 bg-gray-600 hover:bg-gray-500 text-white
                               text-sm rounded transition-colors"
                    >
                      Add Bridge
                    </button>
                    <button
                      onClick={handleEnableBridges}
                      className="px-3 py-1 bg-blue-600 hover:bg-blue-700 text-white
                               text-sm rounded transition-colors"
                    >
                      Apply Bridges
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Current Configuration */}
          {config && (
            <div>
              <h4 className="text-md font-medium text-white mb-3">Current Configuration</h4>
              <div className="bg-gray-700 rounded p-4">
                <pre className="text-sm text-gray-300 overflow-x-auto">
                  {JSON.stringify(config, null, 2)}
                </pre>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default TorStatusMonitor;