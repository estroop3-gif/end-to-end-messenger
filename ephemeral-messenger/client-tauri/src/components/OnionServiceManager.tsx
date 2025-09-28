import React, { useState, useEffect } from 'react';
import { torService, OnionService, CircuitInfo } from '../services/torService';

interface OnionServiceManagerProps {
  className?: string;
}

const OnionServiceManager: React.FC<OnionServiceManagerProps> = ({ className }) => {
  const [services, setServices] = useState<OnionService[]>([]);
  const [circuits, setCircuits] = useState<CircuitInfo[]>([]);
  const [isDiscovering, setIsDiscovering] = useState(false);
  const [newServiceName, setNewServiceName] = useState('');
  const [newServicePort, setNewServicePort] = useState(8443);
  const [testingService, setTestingService] = useState<string | null>(null);

  useEffect(() => {
    // Initialize services
    loadServices();

    // Set up event listeners
    const handleServicesDiscovered = (discoveredServices: OnionService[]) => {
      setServices(discoveredServices);
      setIsDiscovering(false);
    };

    const handleHiddenServiceCreated = (service: OnionService) => {
      setServices(prev => [...prev, service]);
    };

    const handleCircuitBuilt = (circuit: CircuitInfo) => {
      setCircuits(prev => [...prev, circuit]);
    };

    const handleServiceTestComplete = (result: { address: string; reachable: boolean }) => {
      setServices(prev => prev.map(service =>
        service.address === result.address
          ? { ...service, reachable: result.reachable, lastSeen: new Date() }
          : service
      ));
      setTestingService(null);
    };

    torService.on('servicesDiscovered', handleServicesDiscovered);
    torService.on('hiddenServiceCreated', handleHiddenServiceCreated);
    torService.on('circuitBuilt', handleCircuitBuilt);
    torService.on('serviceTestComplete', handleServiceTestComplete);

    return () => {
      torService.off('servicesDiscovered', handleServicesDiscovered);
      torService.off('hiddenServiceCreated', handleHiddenServiceCreated);
      torService.off('circuitBuilt', handleCircuitBuilt);
      torService.off('serviceTestComplete', handleServiceTestComplete);
    };
  }, []);

  const loadServices = async () => {
    const existingServices = torService.getOnionServices();
    setServices(existingServices);

    const existingCircuits = torService.getCircuits();
    setCircuits(existingCircuits);
  };

  const handleDiscoverServices = async () => {
    setIsDiscovering(true);
    try {
      await torService.discoverOnionServices();
    } catch (error) {
      console.error('Failed to discover services:', error);
      setIsDiscovering(false);
    }
  };

  const handleCreateService = async () => {
    if (!newServiceName.trim()) return;

    try {
      await torService.createHiddenService(newServiceName, newServicePort);
      setNewServiceName('');
      setNewServicePort(8443);
    } catch (error) {
      console.error('Failed to create hidden service:', error);
    }
  };

  const handleTestService = async (address: string) => {
    setTestingService(address);
    try {
      await torService.testOnionService(address);
    } catch (error) {
      console.error('Failed to test service:', error);
      setTestingService(null);
    }
  };

  const formatOnionAddress = (address: string) => {
    if (address.length > 20) {
      return `${address.substring(0, 16)}...${address.substring(address.length - 10)}`;
    }
    return address;
  };

  const getServiceStatusColor = (service: OnionService) => {
    if (service.reachable) {
      const timeSinceLastSeen = Date.now() - service.lastSeen.getTime();
      if (timeSinceLastSeen < 60000) return 'text-green-400'; // < 1 minute
      if (timeSinceLastSeen < 300000) return 'text-yellow-400'; // < 5 minutes
    }
    return 'text-red-400';
  };

  const getCircuitStatusColor = (status: string) => {
    switch (status) {
      case 'BUILT': return 'text-green-400';
      case 'BUILDING': return 'text-yellow-400';
      case 'FAILED': return 'text-red-400';
      case 'CLOSED': return 'text-gray-400';
      default: return 'text-gray-400';
    }
  };

  return (
    <div className={`space-y-6 ${className}`}>
      {/* Header */}
      <div className="flex items-center justify-between">
        <h2 className="text-2xl font-bold text-white">Onion Services</h2>
        <div className="flex space-x-3">
          <button
            onClick={handleDiscoverServices}
            disabled={isDiscovering}
            className="px-4 py-2 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800
                     text-white rounded-lg transition-colors"
          >
            {isDiscovering ? 'Discovering...' : 'Discover Services'}
          </button>
        </div>
      </div>

      {/* Create New Service */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">Create Hidden Service</h3>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Service Name
            </label>
            <input
              type="text"
              value={newServiceName}
              onChange={(e) => setNewServiceName(e.target.value)}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg
                       text-white placeholder-gray-400 focus:outline-none focus:ring-2
                       focus:ring-blue-500"
              placeholder="my-service"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Local Port
            </label>
            <input
              type="number"
              value={newServicePort}
              onChange={(e) => setNewServicePort(parseInt(e.target.value) || 8443)}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-lg
                       text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              min="1"
              max="65535"
            />
          </div>
          <div className="flex items-end">
            <button
              onClick={handleCreateService}
              disabled={!newServiceName.trim()}
              className="w-full px-4 py-2 bg-green-600 hover:bg-green-700 disabled:bg-gray-700
                       text-white rounded-lg transition-colors"
            >
              Create Service
            </button>
          </div>
        </div>
      </div>

      {/* Services List */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">
          Discovered Services ({services.length})
        </h3>

        {services.length === 0 ? (
          <div className="text-center py-8 text-gray-400">
            No onion services discovered yet. Click "Discover Services" to start scanning.
          </div>
        ) : (
          <div className="space-y-3">
            {services.map((service) => (
              <div
                key={service.address}
                className="flex items-center justify-between p-4 bg-gray-700 rounded-lg"
              >
                <div className="flex-1">
                  <div className="flex items-center space-x-3">
                    <div className="flex-1">
                      <h4 className="font-medium text-white">{service.name}</h4>
                      <p className="text-sm text-gray-300 font-mono">
                        {formatOnionAddress(service.address)}
                      </p>
                      <div className="flex items-center space-x-4 mt-1">
                        <span className="text-xs text-gray-400">
                          Port: {service.port}
                        </span>
                        <span className={`text-xs ${getServiceStatusColor(service)}`}>
                          {service.reachable ? 'Reachable' : 'Unreachable'}
                        </span>
                        <span className="text-xs text-gray-400">
                          Last seen: {service.lastSeen.toLocaleTimeString()}
                        </span>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="flex space-x-2">
                  <button
                    onClick={() => handleTestService(service.address)}
                    disabled={testingService === service.address}
                    className="px-3 py-1 bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800
                             text-white text-sm rounded transition-colors"
                  >
                    {testingService === service.address ? 'Testing...' : 'Test'}
                  </button>
                  <button
                    onClick={() => navigator.clipboard.writeText(service.address)}
                    className="px-3 py-1 bg-gray-600 hover:bg-gray-500 text-white
                             text-sm rounded transition-colors"
                  >
                    Copy
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Circuits */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h3 className="text-lg font-semibold text-white mb-4">
          Active Circuits ({circuits.length})
        </h3>

        {circuits.length === 0 ? (
          <div className="text-center py-4 text-gray-400">
            No active circuits
          </div>
        ) : (
          <div className="space-y-2">
            {circuits.slice(-5).map((circuit) => (
              <div
                key={circuit.id}
                className="flex items-center justify-between p-3 bg-gray-700 rounded"
              >
                <div className="flex-1">
                  <div className="flex items-center space-x-3">
                    <span className="text-sm font-mono text-gray-300">
                      {circuit.id}
                    </span>
                    <span className={`text-sm ${getCircuitStatusColor(circuit.status)}`}>
                      {circuit.status}
                    </span>
                    <span className="text-sm text-gray-400">
                      {circuit.purpose}
                    </span>
                  </div>
                  {circuit.path.length > 0 && (
                    <div className="text-xs text-gray-400 mt-1">
                      Path: {circuit.path.join(' → ')}
                    </div>
                  )}
                </div>
                <div className="text-xs text-gray-400">
                  {circuit.timeCreated.toLocaleTimeString()}
                </div>
              </div>
            ))}
            {circuits.length > 5 && (
              <div className="text-center text-sm text-gray-400 pt-2">
                ... and {circuits.length - 5} more circuits
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default OnionServiceManager;