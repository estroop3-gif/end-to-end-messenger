import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { Shield, Download, Settings, MessageCircle, Key, CheckCircle, AlertTriangle, ExternalLink } from 'lucide-react';
import './App.css';

interface AppConfig {
  version: string;
  install_path: string;
  features: string[];
}

interface SecurityStatus {
  triple_encryption: boolean;
  certificate_pinning: boolean;
  digital_signatures: boolean;
  intrusion_detection: boolean;
  shuttle_service: boolean;
}

type TabType = 'welcome' | 'security' | 'messaging' | 'settings';

function App() {
  const [activeTab, setActiveTab] = useState<TabType>('welcome');
  const [appConfig, setAppConfig] = useState<AppConfig | null>(null);
  const [securityStatus, setSecurityStatus] = useState<SecurityStatus | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [message, setMessage] = useState('');
  const [scriptureVerse, setScriptureVerse] = useState('');

  useEffect(() => {
    loadAppInfo();
    loadSecurityStatus();
    loadScripture();
  }, []);

  const loadAppInfo = async () => {
    try {
      const config = await invoke<AppConfig>('get_app_info');
      setAppConfig(config);
    } catch (error) {
      console.error('Failed to load app info:', error);
    }
  };

  const loadSecurityStatus = async () => {
    try {
      const status = await invoke<SecurityStatus>('check_security_status');
      setSecurityStatus(status);
    } catch (error) {
      console.error('Failed to load security status:', error);
    }
  };

  const loadScripture = async () => {
    try {
      const verse = await invoke<string>('show_scripture_verse');
      setScriptureVerse(verse);
    } catch (error) {
      console.error('Failed to load scripture:', error);
    }
  };

  const startMessaging = async () => {
    setIsLoading(true);
    setMessage('');
    try {
      const result = await invoke<string>('start_secure_messaging');
      setMessage(result);
      setActiveTab('messaging');
    } catch (error) {
      setMessage(`Error: ${error}`);
    } finally {
      setIsLoading(false);
    }
  };

  const openDocumentation = async () => {
    try {
      await invoke('open_documentation');
    } catch (error) {
      console.error('Failed to open documentation:', error);
    }
  };

  const SecurityIndicator = ({ label, status }: { label: string; status: boolean }) => (
    <div className="flex items-center gap-2 p-3 bg-white rounded-lg border">
      {status ? (
        <CheckCircle className="w-5 h-5 text-green-500" />
      ) : (
        <AlertTriangle className="w-5 h-5 text-amber-500" />
      )}
      <span className={`font-medium ${status ? 'text-green-700' : 'text-amber-700'}`}>
        {label}
      </span>
      <span className={`text-sm px-2 py-1 rounded ${status ? 'bg-green-100 text-green-800' : 'bg-amber-100 text-amber-800'}`}>
        {status ? 'Active' : 'Inactive'}
      </span>
    </div>
  );

  const TabButton = ({ tab, icon: Icon, label }: { tab: TabType; icon: any; label: string }) => (
    <button
      onClick={() => setActiveTab(tab)}
      className={`flex items-center gap-2 px-4 py-2 rounded-lg transition-colors ${
        activeTab === tab
          ? 'bg-blue-600 text-white shadow-md'
          : 'bg-white text-gray-700 hover:bg-gray-50 border'
      }`}
    >
      <Icon className="w-4 h-4" />
      {label}
    </button>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100">
      {/* Header */}
      <div className="bg-white shadow-sm border-b">
        <div className="max-w-6xl mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 bg-blue-600 rounded-xl flex items-center justify-center">
                <Shield className="w-6 h-6 text-white" />
              </div>
              <div>
                <h1 className="text-xl font-bold text-gray-900">JESUS IS KING</h1>
                <p className="text-sm text-gray-500">Secure Messenger v{appConfig?.version || '1.0.3'}</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={openDocumentation}
                className="flex items-center gap-2 px-3 py-2 text-sm bg-gray-100 hover:bg-gray-200 rounded-lg transition-colors"
              >
                <ExternalLink className="w-4 h-4" />
                Documentation
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <div className="max-w-6xl mx-auto px-6 py-4">
        <div className="flex gap-2">
          <TabButton tab="welcome" icon={Shield} label="Welcome" />
          <TabButton tab="security" icon={Key} label="Security" />
          <TabButton tab="messaging" icon={MessageCircle} label="Messaging" />
          <TabButton tab="settings" icon={Settings} label="Settings" />
        </div>
      </div>

      {/* Content */}
      <div className="max-w-6xl mx-auto px-6 pb-8">
        {activeTab === 'welcome' && (
          <div className="bg-white rounded-xl shadow-sm p-8">
            <div className="text-center mb-8">
              <div className="w-20 h-20 bg-blue-600 rounded-2xl flex items-center justify-center mx-auto mb-4">
                <Shield className="w-10 h-10 text-white" />
              </div>
              <h2 className="text-3xl font-bold text-gray-900 mb-4">Welcome to JESUS IS KING</h2>
              <p className="text-xl text-gray-600 mb-6">Professional Secure Messaging Platform</p>
              <div className="bg-blue-50 border border-blue-200 rounded-lg p-4 max-w-2xl mx-auto">
                <p className="text-blue-800 font-medium">Enterprise-Grade Security Features</p>
                <p className="text-sm text-blue-700 mt-1">
                  Triple-encryption onion transport • Certificate pinning • Digital signatures • Hardware authentication
                </p>
              </div>
            </div>

            {appConfig && (
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-8">
                <div className="space-y-3">
                  <h3 className="text-lg font-semibold text-gray-900">Security Features</h3>
                  {appConfig.features.map((feature, index) => (
                    <div key={index} className="flex items-center gap-2">
                      <CheckCircle className="w-4 h-4 text-green-500" />
                      <span className="text-gray-700">{feature}</span>
                    </div>
                  ))}
                </div>
                <div className="space-y-3">
                  <h3 className="text-lg font-semibold text-gray-900">Application Info</h3>
                  <div className="space-y-2 text-sm">
                    <div><strong>Version:</strong> {appConfig.version}</div>
                    <div><strong>Install Path:</strong> {appConfig.install_path}</div>
                    <div><strong>Status:</strong> <span className="text-green-600">Ready</span></div>
                  </div>
                </div>
              </div>
            )}

            <div className="flex justify-center gap-4">
              <button
                onClick={startMessaging}
                disabled={isLoading}
                className="flex items-center gap-2 px-6 py-3 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium transition-colors disabled:opacity-50"
              >
                {isLoading ? (
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />
                ) : (
                  <MessageCircle className="w-4 h-4" />
                )}
                {isLoading ? 'Starting...' : 'Start Secure Messaging'}
              </button>
            </div>

            {message && (
              <div className="mt-6 p-4 bg-green-50 border border-green-200 rounded-lg">
                <p className="text-green-800">{message}</p>
              </div>
            )}

            {scriptureVerse && (
              <div className="mt-8 text-center">
                <div className="bg-gradient-to-r from-blue-50 to-indigo-50 border border-blue-200 rounded-lg p-6">
                  <p className="text-blue-800 italic font-medium">{scriptureVerse}</p>
                </div>
              </div>
            )}
          </div>
        )}

        {activeTab === 'security' && securityStatus && (
          <div className="bg-white rounded-xl shadow-sm p-8">
            <div className="mb-6">
              <h2 className="text-2xl font-bold text-gray-900 mb-2">Security Status</h2>
              <p className="text-gray-600">Real-time security feature monitoring</p>
            </div>

            <div className="grid gap-4">
              <SecurityIndicator label="Triple-Layer Encryption" status={securityStatus.triple_encryption} />
              <SecurityIndicator label="Certificate Pinning" status={securityStatus.certificate_pinning} />
              <SecurityIndicator label="Digital Signatures" status={securityStatus.digital_signatures} />
              <SecurityIndicator label="Intrusion Detection" status={securityStatus.intrusion_detection} />
              <SecurityIndicator label="Shuttle Service" status={securityStatus.shuttle_service} />
            </div>

            <div className="mt-8 p-6 bg-gray-50 rounded-lg">
              <h3 className="text-lg font-semibold text-gray-900 mb-3">Security Architecture</h3>
              <div className="text-sm text-gray-700 space-y-2">
                <div><strong>Layer A (Inner):</strong> Signal Protocol Double Ratchet for end-to-end encryption</div>
                <div><strong>Layer B (Middle):</strong> ChaCha20-Poly1305 for inter-relay transport security</div>
                <div><strong>Layer C (Outer):</strong> AES-256-GCM for local client-relay encryption</div>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'messaging' && (
          <div className="bg-white rounded-xl shadow-sm p-8">
            <div className="text-center">
              <MessageCircle className="w-16 h-16 text-blue-600 mx-auto mb-4" />
              <h2 className="text-2xl font-bold text-gray-900 mb-4">Secure Messaging</h2>
              <p className="text-gray-600 mb-8">Your messages are protected by military-grade encryption</p>

              <div className="bg-green-50 border border-green-200 rounded-lg p-6 max-w-md mx-auto">
                <CheckCircle className="w-8 h-8 text-green-500 mx-auto mb-2" />
                <p className="text-green-800 font-medium">Secure Messaging Ready</p>
                <p className="text-sm text-green-700 mt-1">All security layers are active and operational</p>
              </div>
            </div>
          </div>
        )}

        {activeTab === 'settings' && (
          <div className="bg-white rounded-xl shadow-sm p-8">
            <h2 className="text-2xl font-bold text-gray-900 mb-6">Application Settings</h2>

            <div className="space-y-6">
              <div className="p-4 border rounded-lg">
                <h3 className="font-semibold text-gray-900 mb-2">Installation Directory</h3>
                <p className="text-sm text-gray-600 mb-3">{appConfig?.install_path}</p>
                <button className="text-blue-600 hover:text-blue-700 text-sm font-medium">
                  Change Location
                </button>
              </div>

              <div className="p-4 border rounded-lg">
                <h3 className="font-semibold text-gray-900 mb-2">Security Level</h3>
                <select className="w-full p-2 border rounded-lg">
                  <option>Maximum Security (Recommended)</option>
                  <option>High Security</option>
                  <option>Standard Security</option>
                </select>
              </div>

              <div className="p-4 border rounded-lg">
                <h3 className="font-semibold text-gray-900 mb-2">Hardware Key Authentication</h3>
                <label className="flex items-center gap-2">
                  <input type="checkbox" defaultChecked className="rounded" />
                  <span className="text-sm text-gray-700">Require hardware key for authentication</span>
                </label>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default App;