import React, { useState, useEffect } from 'react';
import { invoke } from '../services/api';
import QRCode from 'qrcode.react';
import './SessionManager.css';

interface SessionInfo {
  session_id: string;
  label: string;
  algorithm_type: string;
  participants: string[];
  message_count: number;
  remaining_seconds: number;
  is_expired: boolean;
}

interface CipherCodeRequest {
  def_id: string;
  label: string;
  algorithm: string;
  algorithm_params: any;
  ttl_minutes?: number;
  recipient_pubkey?: string;
  embed_secret: boolean;
  confirm_danger?: boolean;
}

interface CipherCodeResponse {
  cipher_code: any;
  short_code: string;
  qr_code_png: number[];
}

interface SessionManagerProps {
  onError: (error: string) => void;
  onSessionCreated?: (sessionId: string) => void;
  onSessionJoined?: (sessionId: string) => void;
  activeSession?: string | null;
  sessionMessages?: {[sessionId: string]: any[]};
  onSendMessage?: (sessionId: string, message: string) => void;
}

const SessionManager: React.FC<SessionManagerProps> = ({
  onError,
  onSessionCreated,
  onSessionJoined,
  activeSession,
  sessionMessages,
  onSendMessage
}) => {
  const [activeTab, setActiveTab] = useState<'create' | 'join' | 'active'>('create');
  const [activeSessions, setActiveSessions] = useState<SessionInfo[]>([]);
  const [loading, setLoading] = useState(false);

  // Create session state
  const [createForm, setCreateForm] = useState({
    label: '',
    algorithm: 'aead',
    shift: 3,
    keyword: '',
    ttl_minutes: 60,
    participants: [''],
    embedSecret: false,
    confirmDanger: false
  });

  // Join session state
  const [joinForm, setJoinForm] = useState({
    cipherCode: '',
    passphrase: ''
  });

  // Generated cipher code
  const [generatedCode, setGeneratedCode] = useState<{
    code: CipherCodeResponse;
    qrDataUrl: string;
  } | null>(null);

  const [showDangerWarning, setShowDangerWarning] = useState(false);

  useEffect(() => {
    loadActiveSessions();
    const interval = setInterval(loadActiveSessions, 5000); // Update every 5 seconds
    return () => clearInterval(interval);
  }, []);

  const loadActiveSessions = async () => {
    try {
      const response = await invoke('list_active_sessions') as any;
      if (response.success && response.data) {
        setActiveSessions(response.data.sessions || []);
      }
    } catch (err) {
      console.error('Failed to load active sessions:', err);
    }
  };

  const handleCreateSession = async () => {
    if (!createForm.label.trim()) {
      onError?.('Session label is required');
      return;
    }

    if (createForm.embedSecret && !createForm.confirmDanger) {
      setShowDangerWarning(true);
      return;
    }

    setLoading(true);

    try {
      // First generate cipher code
      const algorithmParams = createForm.algorithm === 'caesar'
        ? { shift: createForm.shift }
        : createForm.algorithm === 'vigenere'
        ? { keyword: createForm.keyword }
        : createForm.algorithm === 'aead'
        ? { memory_cost: 65536, time_cost: 3, parallelism: 1 }
        : {};

      const cipherCodeRequest: CipherCodeRequest = {
        def_id: `session_${Date.now()}`,
        label: createForm.label,
        algorithm: createForm.algorithm,
        algorithm_params: algorithmParams,
        ttl_minutes: createForm.ttl_minutes,
        embed_secret: createForm.embedSecret,
        confirm_danger: createForm.confirmDanger
      };

      const codeResponse = await invoke('generate_cipher_code', cipherCodeRequest) as any;

      if (!codeResponse.success) {
        throw new Error(codeResponse.error || 'Failed to generate cipher code');
      }

      const codeData = codeResponse.data as CipherCodeResponse;

      // Convert PNG bytes to data URL for display
      const blob = new Blob([new Uint8Array(codeData.qr_code_png)], { type: 'image/png' });
      const qrDataUrl = URL.createObjectURL(blob);

      setGeneratedCode({
        code: codeData,
        qrDataUrl
      });

      // Start the session
      const sessionRequest = {
        cipher_code: codeData.cipher_code,
        participants: createForm.participants.filter(p => p.trim()),
        options: {
          ttl_minutes: createForm.ttl_minutes
        }
      };

      const sessionResponse = await invoke('start_cipher_session', sessionRequest) as any;

      if (!sessionResponse.success) {
        throw new Error(sessionResponse.error || 'Failed to start session');
      }

      const sessionId = sessionResponse.data.session_id;
      onSessionCreated?.(sessionId);
      loadActiveSessions();

    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error occurred';
      onError?.(message);
    } finally {
      setLoading(false);
    }
  };

  const handleJoinSession = async () => {
    if (!joinForm.cipherCode.trim()) {
      onError?.('Cipher code is required');
      return;
    }

    setLoading(true);

    try {
      // First validate the cipher code
      const validateResponse = await invoke('validate_cipher_code_input', joinForm.cipherCode) as any;

      if (!validateResponse.success) {
        throw new Error('Invalid cipher code format');
      }

      // Join the session
      const joinRequest = {
        session_id: `joined_${Date.now()}`, // In real implementation, get from code
        cipher_code_string: joinForm.cipherCode,
        passphrase: joinForm.passphrase || undefined
      };

      const response = await invoke('join_cipher_session', joinRequest) as any;

      if (!response.success) {
        throw new Error(response.error || 'Failed to join session');
      }

      onSessionJoined?.(joinRequest.session_id);
      loadActiveSessions();

      // Clear form
      setJoinForm({ cipherCode: '', passphrase: '' });

    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unknown error occurred';
      onError?.(message);
    } finally {
      setLoading(false);
    }
  };

  const handleEndSession = async (sessionId: string) => {
    if (!confirm('Are you sure you want to end this session? This cannot be undone.')) {
      return;
    }

    try {
      await invoke('end_cipher_session', sessionId, true); // true = re-envelope messages
      loadActiveSessions();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to end session';
      onError?.(message);
    }
  };

  const formatTimeRemaining = (seconds: number): string => {
    if (seconds <= 0) return 'EXPIRED';

    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;

    if (hours > 0) {
      return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    } else {
      return `${minutes}:${secs.toString().padStart(2, '0')}`;
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      // Show toast or notification
    });
  };

  const addParticipant = () => {
    setCreateForm(prev => ({
      ...prev,
      participants: [...prev.participants, '']
    }));
  };

  const removeParticipant = (index: number) => {
    setCreateForm(prev => ({
      ...prev,
      participants: prev.participants.filter((_, i) => i !== index)
    }));
  };

  const updateParticipant = (index: number, value: string) => {
    setCreateForm(prev => ({
      ...prev,
      participants: prev.participants.map((p, i) => i === index ? value : p)
    }));
  };

  return (
    <div className="session-manager">
      <div className="session-header">
        <h2>🔐 Cipher Sessions</h2>
        <p>Create or join encrypted messaging sessions with cipher codes</p>
      </div>

      <div className="session-tabs">
        <button
          className={`tab ${activeTab === 'create' ? 'active' : ''}`}
          onClick={() => setActiveTab('create')}
        >
          Create Session
        </button>
        <button
          className={`tab ${activeTab === 'join' ? 'active' : ''}`}
          onClick={() => setActiveTab('join')}
        >
          Join Session
        </button>
        <button
          className={`tab ${activeTab === 'active' ? 'active' : ''}`}
          onClick={() => setActiveTab('active')}
        >
          Active Sessions ({activeSessions.length})
        </button>
      </div>

      {activeTab === 'create' && (
        <div className="tab-content">
          <div className="form-section">
            <h3>Create New Cipher Session</h3>

            <div className="form-group">
              <label>Session Label</label>
              <input
                type="text"
                value={createForm.label}
                onChange={(e) => setCreateForm(prev => ({ ...prev, label: e.target.value }))}
                placeholder="e.g., Project Alpha Discussion"
              />
            </div>

            <div className="form-group">
              <label>Cipher Algorithm</label>
              <select
                value={createForm.algorithm}
                onChange={(e) => setCreateForm(prev => ({ ...prev, algorithm: e.target.value }))}
              >
                <option value="aead">AEAD (ChaCha20-Poly1305) - Recommended</option>
                <option value="caesar">Caesar Cipher - Classic</option>
                <option value="vigenere">Vigenère Cipher - Classic</option>
                <option value="otp">One-Time Pad - Maximum Security</option>
              </select>
            </div>

            {createForm.algorithm === 'caesar' && (
              <div className="form-group">
                <label>Caesar Shift</label>
                <input
                  type="number"
                  value={createForm.shift}
                  onChange={(e) => setCreateForm(prev => ({ ...prev, shift: parseInt(e.target.value) || 0 }))}
                  min="-25"
                  max="25"
                />
              </div>
            )}

            {createForm.algorithm === 'vigenere' && (
              <div className="form-group">
                <label>Keyword</label>
                <input
                  type="text"
                  value={createForm.keyword}
                  onChange={(e) => setCreateForm(prev => ({ ...prev, keyword: e.target.value }))}
                  placeholder="Secret keyword"
                />
              </div>
            )}

            <div className="form-group">
              <label>Session Duration (minutes)</label>
              <input
                type="number"
                value={createForm.ttl_minutes}
                onChange={(e) => setCreateForm(prev => ({ ...prev, ttl_minutes: parseInt(e.target.value) || 60 }))}
                min="5"
                max="1440"
              />
            </div>

            <div className="form-group">
              <label>Participants</label>
              {createForm.participants.map((participant, index) => (
                <div key={index} className="participant-input">
                  <input
                    type="text"
                    value={participant}
                    onChange={(e) => updateParticipant(index, e.target.value)}
                    placeholder="Identity fingerprint or email"
                  />
                  {createForm.participants.length > 1 && (
                    <button
                      type="button"
                      onClick={() => removeParticipant(index)}
                      className="remove-btn"
                    >
                      ×
                    </button>
                  )}
                </div>
              ))}
              <button type="button" onClick={addParticipant} className="add-participant">
                + Add Participant
              </button>
            </div>

            <div className="form-group danger-section">
              <label className="checkbox-label">
                <input
                  type="checkbox"
                  checked={createForm.embedSecret}
                  onChange={(e) => setCreateForm(prev => ({
                    ...prev,
                    embedSecret: e.target.checked,
                    confirmDanger: false
                  }))}
                />
                ⚠️ Embed secret in cipher code (DANGEROUS)
              </label>
              <p className="warning-text">
                Only check this if you understand the security risks. The secret will be included
                in plaintext in the cipher code.
              </p>
            </div>

            <button
              onClick={handleCreateSession}
              disabled={loading}
              className="primary-btn"
            >
              {loading ? 'Creating...' : 'Create Session & Generate Code'}
            </button>
          </div>

          {generatedCode && (
            <div className="generated-code-section">
              <h3>🎯 Session Created Successfully!</h3>

              <div className="code-display">
                <div className="qr-section">
                  <h4>QR Code</h4>
                  <img
                    src={generatedCode.qrDataUrl}
                    alt="Session QR Code"
                    className="qr-code"
                  />
                </div>

                <div className="text-code-section">
                  <h4>Cipher Code</h4>
                  <div className="code-text">
                    <code>{generatedCode.code.short_code}</code>
                    <button
                      onClick={() => copyToClipboard(generatedCode.code.short_code)}
                      className="copy-btn"
                    >
                      📋 Copy
                    </button>
                  </div>
                </div>
              </div>

              <div className="sharing-instructions">
                <h4>📤 How to Share</h4>
                <ul>
                  <li>Share the QR code or text code with participants</li>
                  <li>Participants scan the QR or enter the code to join</li>
                  <li>Keep the code secure - anyone with it can read session messages</li>
                  <li>The session will expire in {createForm.ttl_minutes} minutes</li>
                </ul>
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'join' && (
        <div className="tab-content">
          <div className="form-section">
            <h3>Join Cipher Session</h3>

            <div className="form-group">
              <label>Cipher Code</label>
              <textarea
                value={joinForm.cipherCode}
                onChange={(e) => setJoinForm(prev => ({ ...prev, cipherCode: e.target.value }))}
                placeholder="Enter cipher code or scan QR code"
                rows={4}
              />
            </div>

            <div className="form-group">
              <label>Passphrase (if required)</label>
              <input
                type="password"
                value={joinForm.passphrase}
                onChange={(e) => setJoinForm(prev => ({ ...prev, passphrase: e.target.value }))}
                placeholder="Enter passphrase if cipher requires it"
              />
            </div>

            <button
              onClick={handleJoinSession}
              disabled={loading}
              className="primary-btn"
            >
              {loading ? 'Joining...' : 'Join Session'}
            </button>
          </div>
        </div>
      )}

      {activeTab === 'active' && (
        <div className="tab-content">
          <h3>Active Sessions</h3>

          {activeSessions.length === 0 ? (
            <div className="empty-state">
              <p>No active cipher sessions</p>
              <p>Create a new session or join an existing one to get started.</p>
            </div>
          ) : (
            <div className="sessions-list">
              {activeSessions.map((session) => (
                <div
                  key={session.session_id}
                  className={`session-card ${session.is_expired ? 'expired' : ''}`}
                >
                  <div className="session-header">
                    <h4>{session.label}</h4>
                    <div className="session-status">
                      <span className={`algorithm-badge ${session.algorithm_type.toLowerCase()}`}>
                        {session.algorithm_type}
                      </span>
                      <span className="time-remaining">
                        ⏱️ {formatTimeRemaining(session.remaining_seconds)}
                      </span>
                    </div>
                  </div>

                  <div className="session-details">
                    <p>Participants: {session.participants.length}</p>
                    <p>Messages: {session.message_count}</p>
                    <p>Session ID: <code>{session.session_id.slice(0, 8)}...</code></p>
                  </div>

                  <div className="session-actions">
                    <button
                      onClick={() => handleEndSession(session.session_id)}
                      className="danger-btn"
                      disabled={session.is_expired}
                    >
                      🔥 End Session
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Danger Warning Modal */}
      {showDangerWarning && (
        <div className="modal-overlay">
          <div className="danger-modal">
            <h3>⚠️ SECURITY WARNING ⚠️</h3>
            <div className="warning-content">
              <p><strong>You are about to embed secrets in the cipher code!</strong></p>
              <p>This means:</p>
              <ul>
                <li>🚨 The secret will be stored in PLAINTEXT in the code</li>
                <li>🚨 Anyone who sees the code can read ALL session messages</li>
                <li>🚨 The code becomes extremely sensitive material</li>
                <li>🚨 This defeats the purpose of cipher security</li>
              </ul>
              <p><strong>Only proceed if you understand these risks and have no alternative!</strong></p>

              <div className="confirmation-section">
                <label className="checkbox-label">
                  <input
                    type="checkbox"
                    checked={createForm.confirmDanger}
                    onChange={(e) => setCreateForm(prev => ({ ...prev, confirmDanger: e.target.checked }))}
                  />
                  I understand the security risks and choose to proceed anyway
                </label>
              </div>
            </div>

            <div className="modal-actions">
              <button
                onClick={() => setShowDangerWarning(false)}
                className="secondary-btn"
              >
                Cancel
              </button>
              <button
                onClick={() => {
                  setShowDangerWarning(false);
                  if (createForm.confirmDanger) {
                    handleCreateSession();
                  }
                }}
                disabled={!createForm.confirmDanger}
                className="danger-btn"
              >
                Proceed with Danger
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SessionManager;