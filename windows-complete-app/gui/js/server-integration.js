// JESUS IS KING - Server Integration
// Connects GUI to Go server for triple encryption messaging

class SecureMessagingClient {
    constructor() {
        this.serverUrl = 'http://localhost:8080';
        this.wsUrl = 'ws://localhost:8080';
        this.sessionId = null;
        this.websocket = null;
        this.authKey = null;
        this.isAuthenticated = false;
        this.messageHandlers = new Map();

        this.initializeEventHandlers();
    }

    initializeEventHandlers() {
        // Add message handlers
        this.messageHandlers.set('new_message', this.handleNewMessage.bind(this));
        this.messageHandlers.set('session_created', this.handleSessionCreated.bind(this));
        this.messageHandlers.set('authentication_required', this.handleAuthRequired.bind(this));
        this.messageHandlers.set('error', this.handleError.bind(this));
    }

    // Hardware Key Authentication
    async authenticateWithHardwareKey(keyId, passphrase) {
        try {
            // Request authentication challenge
            const challengeResponse = await fetch(`${this.serverUrl}/api/handshake`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    user_id: keyId,
                    public_key: await this.getStoredPublicKey(keyId),
                    signature: await this.signChallenge(keyId, passphrase),
                    timestamp: Math.floor(Date.now() / 1000)
                })
            });

            if (challengeResponse.ok) {
                const authData = await challengeResponse.json();
                this.authKey = authData.session_key;
                this.isAuthenticated = true;
                this.updateUI('authenticated', { user_id: keyId });
                return true;
            } else {
                throw new Error('Authentication failed');
            }
        } catch (error) {
            console.error('Hardware key authentication error:', error);
            this.updateUI('auth_error', { error: error.message });
            return false;
        }
    }

    // Create secure messaging session
    async createSession(userA, userB) {
        if (!this.isAuthenticated) {
            throw new Error('Authentication required before creating session');
        }

        try {
            const sessionResponse = await fetch(`${this.serverUrl}/api/session/create`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.authKey}`
                },
                body: JSON.stringify({
                    user_a: userA,
                    user_b: userB,
                    key_a: await this.generateSessionKey(),
                    key_b: await this.generateSessionKey(),
                    signature: await this.signSessionRequest(userA, userB)
                })
            });

            if (sessionResponse.ok) {
                const sessionData = await sessionResponse.json();
                this.sessionId = sessionData.session_id;
                await this.connectWebSocket();
                this.updateUI('session_created', sessionData);
                return sessionData;
            } else {
                throw new Error('Session creation failed');
            }
        } catch (error) {
            console.error('Session creation error:', error);
            this.updateUI('session_error', { error: error.message });
            throw error;
        }
    }

    // Send message with triple encryption
    async sendMessage(toUser, message, deadManTime = null) {
        if (!this.sessionId) {
            throw new Error('No active session');
        }

        try {
            // Layer 1: User encryption (local)
            const layer1Data = await this.encryptMessage(message);

            const messagePayload = {
                session_id: this.sessionId,
                to_user: toUser,
                layer1_data: layer1Data,
                signature: await this.signMessage(layer1Data),
                dead_man_time: deadManTime ? Math.floor(deadManTime.getTime() / 1000) : null
            };

            const response = await fetch(`${this.serverUrl}/api/message/send`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${this.authKey}`
                },
                body: JSON.stringify(messagePayload)
            });

            if (response.ok) {
                const result = await response.json();
                this.updateUI('message_sent', result);
                return result;
            } else {
                throw new Error('Message sending failed');
            }
        } catch (error) {
            console.error('Message sending error:', error);
            this.updateUI('send_error', { error: error.message });
            throw error;
        }
    }

    // Retrieve messages from session
    async getMessages() {
        if (!this.sessionId) {
            throw new Error('No active session');
        }

        try {
            const response = await fetch(`${this.serverUrl}/api/messages/${this.sessionId}`, {
                headers: {
                    'Authorization': `Bearer ${this.authKey}`
                }
            });

            if (response.ok) {
                const data = await response.json();
                this.updateUI('messages_loaded', data);
                return data.messages;
            } else {
                throw new Error('Failed to retrieve messages');
            }
        } catch (error) {
            console.error('Message retrieval error:', error);
            this.updateUI('retrieve_error', { error: error.message });
            throw error;
        }
    }

    // WebSocket connection for real-time updates
    async connectWebSocket() {
        if (!this.sessionId) {
            throw new Error('No session ID for WebSocket connection');
        }

        try {
            this.websocket = new WebSocket(`${this.wsUrl}/ws/${this.sessionId}`);

            this.websocket.onopen = () => {
                console.log('WebSocket connected');
                this.updateUI('websocket_connected');
                this.startHeartbeat();
            };

            this.websocket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleWebSocketMessage(data);
                } catch (error) {
                    console.error('WebSocket message parsing error:', error);
                }
            };

            this.websocket.onclose = () => {
                console.log('WebSocket disconnected');
                this.updateUI('websocket_disconnected');
                this.stopHeartbeat();
                this.attemptReconnection();
            };

            this.websocket.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.updateUI('websocket_error', { error });
            };

        } catch (error) {
            console.error('WebSocket connection error:', error);
            throw error;
        }
    }

    // Handle WebSocket messages
    handleWebSocketMessage(data) {
        const handler = this.messageHandlers.get(data.type);
        if (handler) {
            handler(data);
        } else {
            console.warn('Unknown WebSocket message type:', data.type);
        }
    }

    // Message handlers
    handleNewMessage(data) {
        this.updateUI('new_message_received', data);
        // Automatically refresh messages
        this.getMessages();
    }

    handleSessionCreated(data) {
        this.updateUI('session_established', data);
    }

    handleAuthRequired(data) {
        this.updateUI('authentication_required', data);
    }

    handleError(data) {
        this.updateUI('server_error', data);
    }

    // Heartbeat for WebSocket keepalive
    startHeartbeat() {
        this.heartbeatInterval = setInterval(() => {
            if (this.websocket && this.websocket.readyState === WebSocket.OPEN) {
                this.websocket.send(JSON.stringify({ type: 'ping' }));
            }
        }, 30000); // 30 seconds
    }

    stopHeartbeat() {
        if (this.heartbeatInterval) {
            clearInterval(this.heartbeatInterval);
            this.heartbeatInterval = null;
        }
    }

    // Reconnection logic
    attemptReconnection() {
        if (this.sessionId && !this.reconnectionTimeout) {
            this.reconnectionTimeout = setTimeout(() => {
                console.log('Attempting WebSocket reconnection...');
                this.connectWebSocket().catch(() => {
                    this.reconnectionTimeout = null;
                    this.attemptReconnection();
                });
            }, 5000); // 5 seconds
        }
    }

    // Cryptographic functions (simplified for demonstration)
    async encryptMessage(message) {
        // In real implementation, this would use the crypto library
        const encoder = new TextEncoder();
        const data = encoder.encode(message);
        const encrypted = btoa(String.fromCharCode(...data));
        return encrypted;
    }

    async generateSessionKey() {
        // Generate random session key
        const array = new Uint8Array(32);
        crypto.getRandomValues(array);
        return btoa(String.fromCharCode(...array));
    }

    async signMessage(message) {
        // In real implementation, this would use Ed25519 signing
        const timestamp = Date.now();
        const signatureData = `${message}:${timestamp}`;
        return btoa(signatureData);
    }

    async signChallenge(keyId, passphrase) {
        // In real implementation, this would use hardware key signing
        const timestamp = Date.now();
        const challengeData = `${keyId}:${timestamp}`;
        return btoa(challengeData);
    }

    async signSessionRequest(userA, userB) {
        // In real implementation, this would sign the session request
        const sessionData = `${userA}:${userB}:${Date.now()}`;
        return btoa(sessionData);
    }

    async getStoredPublicKey(keyId) {
        // In real implementation, this would retrieve from hardware key storage
        return 'simulated_public_key_' + keyId;
    }

    // UI update interface
    updateUI(eventType, data = {}) {
        // Dispatch custom events for UI components to handle
        const event = new CustomEvent('secure-messaging-event', {
            detail: { type: eventType, data }
        });
        document.dispatchEvent(event);
    }

    // Cleanup
    disconnect() {
        this.stopHeartbeat();
        if (this.websocket) {
            this.websocket.close();
            this.websocket = null;
        }
        if (this.reconnectionTimeout) {
            clearTimeout(this.reconnectionTimeout);
            this.reconnectionTimeout = null;
        }
        this.sessionId = null;
        this.isAuthenticated = false;
        this.authKey = null;
    }

    // Server health check
    async checkServerHealth() {
        try {
            const response = await fetch(`${this.serverUrl}/health`);
            return response.ok;
        } catch (error) {
            console.error('Server health check failed:', error);
            return false;
        }
    }

    // Dead-Man Switch functionality
    setDeadManSwitch(messageId, expirationTime) {
        const timeUntilExpiration = expirationTime.getTime() - Date.now();
        if (timeUntilExpiration > 0) {
            setTimeout(() => {
                this.updateUI('message_expired', { message_id: messageId });
            }, timeUntilExpiration);
        }
    }
}

// Initialize global messaging client
window.secureMessagingClient = new SecureMessagingClient();

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecureMessagingClient;
}