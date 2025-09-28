# Ephemeral Messenger Developer Guide

## Project Architecture

Ephemeral Messenger is built as a hybrid application with a Go backend server and a Tauri-based frontend client, designed for secure messaging and document sharing.

### Technology Stack

#### Backend (Go)
- **Framework**: Gorilla WebSocket, Gin HTTP router
- **Cryptography**: Libsodium bindings (go-sodium)
- **Networking**: Tor integration via control protocol
- **Security**: Rate limiting, input validation, secure headers

#### Frontend (Tauri + TypeScript)
- **Framework**: Tauri (Rust + WebView)
- **UI**: HTML5, CSS3, TypeScript
- **Cryptography**: WebCrypto API, WebAssembly for heavy operations
- **Storage**: Secure memory management, no persistent storage

### Directory Structure

```
ephemeral-messenger/
├── server/                     # Go backend server
│   ├── main.go                # Server entry point
│   ├── handlers/              # HTTP/WebSocket handlers
│   ├── crypto/                # Cryptographic functions
│   ├── tor/                   # Tor integration
│   └── models/                # Data structures
├── client-tauri/              # Tauri frontend
│   ├── src/                   # TypeScript source
│   │   ├── services/          # Core services
│   │   ├── components/        # UI components
│   │   └── utils/             # Utility functions
│   ├── src-tauri/             # Rust backend
│   └── public/                # Static assets
├── crypto/                    # Shared crypto library
│   ├── identity.py            # Identity management
│   ├── messages.py            # Message encryption
│   └── documents.py           # Document operations
├── tests/                     # Test suites
├── docs/                      # Documentation
└── scripts/                   # Build and deployment scripts
```

## Core Components

### Cryptographic Services

#### Identity Service
Manages user identities and key pairs.

```typescript
interface Identity {
  privateKey: Uint8Array;      // Ed25519 private key
  publicKey: Uint8Array;       // Ed25519 public key
  fingerprint: string;         // SHA-256 hash of public key
  curve25519Private: Uint8Array; // X25519 private key
  curve25519Public: Uint8Array;  // X25519 public key
}

class IdentityService {
  /**
   * Generate a new cryptographic identity
   * @param passphrase User passphrase for key derivation
   * @returns Promise<Identity>
   */
  async generateIdentity(passphrase: string): Promise<Identity>;

  /**
   * Load identity from encrypted storage
   * @param passphrase User passphrase
   * @returns Promise<Identity | null>
   */
  async loadIdentity(passphrase: string): Promise<Identity | null>;

  /**
   * Export identity for backup
   * @param passphrase Encryption passphrase
   * @returns Promise<Uint8Array>
   */
  async exportIdentity(passphrase: string): Promise<Uint8Array>;
}
```

#### Message Service
Handles message encryption and decryption.

```typescript
interface EncryptedMessage {
  salt: Uint8Array;            // Random salt (32 bytes)
  nonce: Uint8Array;           // Encryption nonce (24 bytes)
  ciphertext: Uint8Array;      // Encrypted content
  mac: Uint8Array;             // Authentication tag
  ephemeralPublicKey: Uint8Array; // Sender's ephemeral public key
}

class MessageService {
  /**
   * Encrypt a message for a recipient
   * @param message Plaintext message
   * @param recipientPublicKey Recipient's public key
   * @returns Promise<EncryptedMessage>
   */
  async encryptMessage(
    message: string,
    recipientPublicKey: Uint8Array
  ): Promise<EncryptedMessage>;

  /**
   * Decrypt a received message
   * @param encryptedMessage Encrypted message data
   * @param privateKey Recipient's private key
   * @returns Promise<string>
   */
  async decryptMessage(
    encryptedMessage: EncryptedMessage,
    privateKey: Uint8Array
  ): Promise<string>;
}
```

#### Document Service
Manages secure document creation and access.

```typescript
interface SecureDocument {
  header: DocumentHeader;
  content: Uint8Array;
  signature: Uint8Array;
}

interface DocumentHeader {
  version: number;
  algorithm: string;
  recipients: RecipientInfo[];
  policy: SecurityPolicy;
  metadata: DocumentMetadata;
}

class DocumentService {
  /**
   * Create a new secure document
   * @param options Document creation options
   * @returns Promise<SecureDocument>
   */
  async createDocument(options: {
    title: string;
    content: string;
    recipients: Uint8Array[];
    policy: SecurityPolicy;
    passphrase: string;
  }): Promise<SecureDocument>;

  /**
   * Open and decrypt a secure document
   * @param documentData Encrypted document
   * @param passphrase Document passphrase
   * @returns Promise<DocumentContent>
   */
  async openDocument(
    documentData: Uint8Array,
    passphrase: string
  ): Promise<DocumentContent>;
}
```

### Network Services

#### WebSocket Client
Manages real-time communication with the server.

```typescript
interface WebSocketMessage {
  id: string;
  from: string;
  to: string;
  content: string;
  timestamp: string;
  expiresAt?: string;
  deliveryType: 'direct' | 'store-forward';
}

class WebSocketService {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private messageHandlers: Map<string, Function> = new Map();

  /**
   * Connect to the ephemeral messenger server
   * @param fingerprint Client's fingerprint
   * @param serverUrl Server WebSocket URL
   */
  async connect(fingerprint: string, serverUrl: string): Promise<void>;

  /**
   * Send an encrypted message
   * @param message Message to send
   */
  async sendMessage(message: WebSocketMessage): Promise<void>;

  /**
   * Register a message handler
   * @param type Message type
   * @param handler Handler function
   */
  onMessage(type: string, handler: (message: WebSocketMessage) => void): void;

  /**
   * Disconnect from server
   */
  disconnect(): void;
}
```

#### Tor Service
Manages Tor integration and hidden services.

```typescript
interface TorStatus {
  connected: boolean;
  bootstrapped: boolean;
  onionAddress: string;
  circuitCount: number;
}

class TorService {
  /**
   * Initialize Tor connection
   */
  async initialize(): Promise<void>;

  /**
   * Get current Tor status
   * @returns Promise<TorStatus>
   */
  async getStatus(): Promise<TorStatus>;

  /**
   * Create a new Tor circuit
   * @returns Promise<string> Circuit ID
   */
  async newCircuit(): Promise<string>;

  /**
   * Create hidden service
   * @param name Service name
   * @param port Target port
   * @returns Promise<string> Onion address
   */
  async createHiddenService(name: string, port: number): Promise<string>;
}
```

### Hardware Token Services

#### Hardware Token Service
Manages hardware security tokens.

```typescript
interface HardwareToken {
  id: string;
  type: 'webauthn' | 'yubikey' | 'u2f';
  name: string;
  publicKey: Uint8Array;
  capabilities: string[];
  status: 'active' | 'revoked' | 'expired';
  enrolledAt: Date;
}

class HardwareTokenService {
  /**
   * Check if hardware tokens are supported
   * @returns boolean
   */
  isSupported(): boolean;

  /**
   * Enroll a new WebAuthn token
   * @param username User identifier
   * @param displayName Human-readable name
   * @returns Promise<EnrollmentResult>
   */
  async enrollWebAuthnToken(
    username: string,
    displayName: string
  ): Promise<EnrollmentResult>;

  /**
   * Authenticate using WebAuthn
   * @param tokenId Token identifier
   * @param challenge Authentication challenge
   * @returns Promise<AuthenticationResult>
   */
  async authenticateWithWebAuthn(
    tokenId: string,
    challenge: ArrayBuffer
  ): Promise<AuthenticationResult>;

  /**
   * Get list of enrolled tokens
   * @returns HardwareToken[]
   */
  getEnrolledTokens(): HardwareToken[];
}
```

## Backend Implementation

### Server Architecture

The Go server implements a zero-knowledge architecture where plaintext messages never touch persistent storage.

#### Main Server Structure

```go
type Server struct {
    clients    map[string]*Client
    messages   map[string]*Message  // Temporary message store
    tor        *TorManager
    config     *Config
    mu         sync.RWMutex
}

type Client struct {
    Fingerprint string
    Connection  *websocket.Conn
    LastSeen    time.Time
    Send        chan []byte
}

type Message struct {
    ID        string    `json:"id"`
    From      string    `json:"from"`
    To        string    `json:"to"`
    Content   string    `json:"content"`
    Timestamp time.Time `json:"timestamp"`
    ExpiresAt time.Time `json:"expires_at"`
}
```

#### WebSocket Handler

```go
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
    // Upgrade connection
    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        log.Printf("WebSocket upgrade failed: %v", err)
        return
    }
    defer conn.Close()

    // Extract fingerprint
    fingerprint := r.URL.Query().Get("fingerprint")
    if !isValidFingerprint(fingerprint) {
        conn.WriteMessage(websocket.TextMessage, []byte("Invalid fingerprint"))
        return
    }

    // Create client
    client := &Client{
        Fingerprint: fingerprint,
        Connection:  conn,
        LastSeen:    time.Now(),
        Send:        make(chan []byte, 256),
    }

    // Register client
    s.registerClient(client)
    defer s.unregisterClient(client)

    // Handle messages
    go s.handleClientMessages(client)
    s.handleClientSend(client)
}
```

#### Message Processing

```go
func (s *Server) processMessage(client *Client, data []byte) error {
    var msg Message
    if err := json.Unmarshal(data, &msg); err != nil {
        return fmt.Errorf("invalid message format: %v", err)
    }

    // Validate message
    if err := s.validateMessage(&msg, client.Fingerprint); err != nil {
        return fmt.Errorf("message validation failed: %v", err)
    }

    // Set metadata
    msg.ID = generateMessageID()
    msg.From = client.Fingerprint
    msg.Timestamp = time.Now()
    msg.ExpiresAt = time.Now().Add(24 * time.Hour)

    // Deliver message
    if err := s.deliverMessage(&msg); err != nil {
        return fmt.Errorf("message delivery failed: %v", err)
    }

    return nil
}
```

### Tor Integration

#### Tor Manager

```go
type TorManager struct {
    controlConn net.Conn
    config      *TorConfig
    services    map[string]*HiddenService
}

func (tm *TorManager) CreateHiddenService(name string, port int) (*HiddenService, error) {
    // Generate service key
    serviceKey, err := generateServiceKey()
    if err != nil {
        return nil, err
    }

    // Configure hidden service
    config := fmt.Sprintf("ADD_ONION NEW:ED25519-V3 Port=%d,127.0.0.1:%d", port, port)
    response, err := tm.sendCommand(config)
    if err != nil {
        return nil, err
    }

    // Parse onion address
    onionAddress := parseOnionAddress(response)

    service := &HiddenService{
        Name:         name,
        OnionAddress: onionAddress,
        PrivateKey:   serviceKey,
        Port:         port,
    }

    tm.services[name] = service
    return service, nil
}
```

### Security Implementation

#### Rate Limiting

```go
type RateLimiter struct {
    clients map[string]*ClientRate
    mu      sync.RWMutex
}

type ClientRate struct {
    Messages  int
    LastReset time.Time
    Blocked   bool
}

func (rl *RateLimiter) CheckRate(fingerprint string) bool {
    rl.mu.Lock()
    defer rl.mu.Unlock()

    rate, exists := rl.clients[fingerprint]
    if !exists {
        rate = &ClientRate{
            Messages:  0,
            LastReset: time.Now(),
            Blocked:   false,
        }
        rl.clients[fingerprint] = rate
    }

    // Reset if minute has passed
    if time.Since(rate.LastReset) > time.Minute {
        rate.Messages = 0
        rate.LastReset = time.Now()
        rate.Blocked = false
    }

    // Check limit
    if rate.Messages >= 10 {
        rate.Blocked = true
        return false
    }

    rate.Messages++
    return true
}
```

#### Input Validation

```go
func validateMessage(msg *Message, senderFingerprint string) error {
    // Check required fields
    if msg.To == "" || msg.Content == "" {
        return errors.New("missing required fields")
    }

    // Validate fingerprint format
    if !isValidFingerprint(msg.To) {
        return errors.New("invalid recipient fingerprint")
    }

    // Check message size
    if len(msg.Content) > MaxMessageSize {
        return errors.New("message too large")
    }

    // Verify sender matches connection
    if msg.From != senderFingerprint {
        return errors.New("sender fingerprint mismatch")
    }

    return nil
}

func isValidFingerprint(fingerprint string) bool {
    if len(fingerprint) != 64 {
        return false
    }

    for _, char := range fingerprint {
        if !isHexChar(char) {
            return false
        }
    }

    return true
}
```

## Frontend Implementation

### Tauri Configuration

#### tauri.conf.json

```json
{
  "build": {
    "beforeDevCommand": "npm run dev",
    "beforeBuildCommand": "npm run build",
    "devPath": "http://localhost:3000",
    "distDir": "../dist"
  },
  "package": {
    "productName": "Ephemeral Messenger",
    "version": "1.0.0"
  },
  "tauri": {
    "allowlist": {
      "fs": {
        "all": false,
        "readFile": true,
        "writeFile": true,
        "createDir": true
      },
      "shell": {
        "all": false,
        "execute": true,
        "sidecar": true
      },
      "protocol": {
        "all": false,
        "asset": true
      }
    },
    "security": {
      "csp": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'"
    },
    "windows": [
      {
        "fullscreen": false,
        "height": 800,
        "resizable": true,
        "title": "Ephemeral Messenger",
        "width": 1200,
        "minWidth": 800,
        "minHeight": 600
      }
    ]
  }
}
```

### Service Integration

#### Dependency Injection

```typescript
// Service container for dependency injection
class ServiceContainer {
  private services: Map<string, any> = new Map();

  register<T>(name: string, service: T): void {
    this.services.set(name, service);
  }

  get<T>(name: string): T {
    const service = this.services.get(name);
    if (!service) {
      throw new Error(`Service ${name} not found`);
    }
    return service as T;
  }
}

// Service initialization
const container = new ServiceContainer();

// Register core services
container.register('identity', new IdentityService());
container.register('message', new MessageService());
container.register('document', new DocumentService());
container.register('websocket', new WebSocketService());
container.register('tor', new TorService());
container.register('hardwareToken', new HardwareTokenService());
container.register('yubiKey', new YubiKeyService());
container.register('challengeResponse', new ChallengeResponseAuthService());

export { container };
```

#### Service Lifecycle

```typescript
class Application {
  private container: ServiceContainer;
  private initialized = false;

  constructor() {
    this.container = new ServiceContainer();
  }

  async initialize(): Promise<void> {
    if (this.initialized) return;

    try {
      // Initialize core services
      await this.container.get<TorService>('tor').initialize();
      await this.container.get<HardwareTokenService>('hardwareToken').initialize();

      // Set up event handlers
      this.setupEventHandlers();

      // Mark as initialized
      this.initialized = true;

      console.log('Application initialized successfully');
    } catch (error) {
      console.error('Application initialization failed:', error);
      throw error;
    }
  }

  private setupEventHandlers(): void {
    // WebSocket message handler
    const wsService = this.container.get<WebSocketService>('websocket');
    wsService.onMessage('user_message', this.handleUserMessage.bind(this));
    wsService.onMessage('delivery_confirmation', this.handleDeliveryConfirmation.bind(this));

    // Hardware token events
    const tokenService = this.container.get<HardwareTokenService>('hardwareToken');
    tokenService.on('token_enrolled', this.handleTokenEnrolled.bind(this));
    tokenService.on('authentication_required', this.handleAuthRequired.bind(this));
  }

  private async handleUserMessage(message: WebSocketMessage): Promise<void> {
    try {
      // Decrypt message
      const messageService = this.container.get<MessageService>('message');
      const identity = this.container.get<IdentityService>('identity').getCurrentIdentity();

      const decryptedContent = await messageService.decryptMessage(
        JSON.parse(message.content),
        identity.privateKey
      );

      // Update UI
      this.displayMessage({
        from: message.from,
        content: decryptedContent,
        timestamp: new Date(message.timestamp)
      });
    } catch (error) {
      console.error('Failed to handle user message:', error);
      this.showError('Failed to decrypt message');
    }
  }
}
```

## Testing Framework

### Unit Testing

#### Cryptographic Tests

```typescript
describe('IdentityService', () => {
  let identityService: IdentityService;

  beforeEach(() => {
    identityService = new IdentityService();
  });

  test('should generate unique identities', async () => {
    const identity1 = await identityService.generateIdentity('passphrase1');
    const identity2 = await identityService.generateIdentity('passphrase2');

    expect(identity1.fingerprint).not.toBe(identity2.fingerprint);
    expect(identity1.publicKey).not.toEqual(identity2.publicKey);
  });

  test('should derive same identity from same passphrase', async () => {
    const passphrase = 'test_passphrase_12345';

    const identity1 = await identityService.generateIdentity(passphrase);
    const identity2 = await identityService.generateIdentity(passphrase);

    expect(identity1.fingerprint).toBe(identity2.fingerprint);
    expect(identity1.publicKey).toEqual(identity2.publicKey);
  });
});

describe('MessageService', () => {
  let messageService: MessageService;
  let senderIdentity: Identity;
  let recipientIdentity: Identity;

  beforeEach(async () => {
    messageService = new MessageService();
    const identityService = new IdentityService();

    senderIdentity = await identityService.generateIdentity('sender_pass');
    recipientIdentity = await identityService.generateIdentity('recipient_pass');
  });

  test('should encrypt and decrypt messages correctly', async () => {
    const originalMessage = 'This is a test message';

    const encrypted = await messageService.encryptMessage(
      originalMessage,
      recipientIdentity.curve25519Public
    );

    const decrypted = await messageService.decryptMessage(
      encrypted,
      recipientIdentity.curve25519Private
    );

    expect(decrypted).toBe(originalMessage);
  });

  test('should produce different ciphertext for same message', async () => {
    const message = 'Same message';

    const encrypted1 = await messageService.encryptMessage(
      message,
      recipientIdentity.curve25519Public
    );

    const encrypted2 = await messageService.encryptMessage(
      message,
      recipientIdentity.curve25519Public
    );

    expect(encrypted1.ciphertext).not.toEqual(encrypted2.ciphertext);
    expect(encrypted1.nonce).not.toEqual(encrypted2.nonce);
  });
});
```

### Integration Testing

#### End-to-End Message Flow

```typescript
describe('End-to-End Message Flow', () => {
  let server: TestServer;
  let client1: TestClient;
  let client2: TestClient;

  beforeAll(async () => {
    server = new TestServer();
    await server.start();
  });

  afterAll(async () => {
    await server.stop();
  });

  beforeEach(async () => {
    client1 = new TestClient('client1');
    client2 = new TestClient('client2');

    await client1.connect(server.getWebSocketUrl());
    await client2.connect(server.getWebSocketUrl());
  });

  afterEach(async () => {
    await client1.disconnect();
    await client2.disconnect();
  });

  test('should deliver message between clients', async () => {
    const message = 'Hello from client1';

    // Client1 sends message to client2
    await client1.sendMessage({
      to: client2.getFingerprint(),
      content: message
    });

    // Client2 should receive the message
    const receivedMessage = await client2.waitForMessage();
    expect(receivedMessage.content).toBe(message);
    expect(receivedMessage.from).toBe(client1.getFingerprint());
  });

  test('should handle message expiration', async () => {
    // Send message with short expiration
    await client1.sendMessage({
      to: client2.getFingerprint(),
      content: 'Short-lived message',
      expiresAt: new Date(Date.now() + 1000) // 1 second
    });

    // Wait for expiration
    await new Promise(resolve => setTimeout(resolve, 1500));

    // Message should be gone
    const messages = await server.getPendingMessages(client2.getFingerprint());
    expect(messages).toHaveLength(0);
  });
});
```

### Security Testing

#### Penetration Testing Automation

```python
class SecurityTestSuite:
    def __init__(self, base_url="http://localhost:8443"):
        self.base_url = base_url
        self.session = requests.Session()

    def test_injection_attacks(self):
        """Test for various injection vulnerabilities"""
        injection_payloads = [
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "{{7*7}}",
            "${7*7}",
            "../../../etc/passwd"
        ]

        for payload in injection_payloads:
            response = self.session.post(f"{self.base_url}/api/messages", json={
                "to": payload,
                "content": payload
            })

            # Should return 400 for invalid input
            self.assertEqual(response.status_code, 400)

    def test_rate_limiting(self):
        """Test rate limiting effectiveness"""
        fingerprint = "a" * 64  # Valid fingerprint format

        # Send messages rapidly
        for i in range(15):  # Above the 10 message/minute limit
            response = self.session.post(f"{self.base_url}/api/messages", json={
                "to": fingerprint,
                "content": f"Message {i}"
            })

            if i >= 10:
                # Should be rate limited
                self.assertEqual(response.status_code, 429)

    def test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        # Try accessing protected endpoints without proper auth
        protected_endpoints = [
            "/api/stats",
            "/api/tor/config",
            "/api/tor/services"
        ]

        for endpoint in protected_endpoints:
            response = self.session.get(f"{self.base_url}{endpoint}")
            # Should require authentication
            self.assertIn(response.status_code, [401, 403])
```

## Build and Deployment

### Development Environment

#### Prerequisites

```bash
# Go development
go version  # >= 1.19

# Node.js and npm
node --version  # >= 16.0
npm --version   # >= 8.0

# Rust and Tauri
rustc --version  # >= 1.60
cargo --version

# System dependencies
sudo apt install libgtk-3-dev libwebkit2gtk-4.0-dev libappindicator3-dev librsvg2-dev
```

#### Development Setup

```bash
# Clone repository
git clone https://github.com/your-org/ephemeral-messenger.git
cd ephemeral-messenger

# Install dependencies
npm install                    # Frontend dependencies
cd server && go mod download   # Backend dependencies

# Development mode
npm run dev                    # Start frontend dev server
cd server && go run main.go    # Start backend server

# Build for production
npm run build                  # Build frontend
cd server && go build -o ephemeral-messenger  # Build backend
```

### Production Build

#### Docker Configuration

```dockerfile
# Multi-stage build for Go server
FROM golang:1.19-alpine AS server-builder
WORKDIR /app
COPY server/ .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server .

# Build frontend
FROM node:16-alpine AS frontend-builder
WORKDIR /app
COPY client-tauri/ .
RUN npm ci --only=production
RUN npm run build

# Final production image
FROM alpine:latest
RUN apk --no-cache add ca-certificates tor
WORKDIR /root/

# Copy binaries
COPY --from=server-builder /app/server .
COPY --from=frontend-builder /app/dist ./public/

# Copy configuration
COPY configs/torrc /etc/tor/torrc
COPY scripts/entrypoint.sh .

# Set permissions
RUN chmod +x entrypoint.sh

# Expose port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8443/health || exit 1

CMD ["./entrypoint.sh"]
```

#### Build Script

```bash
#!/bin/bash
# build.sh - Production build script

set -e

echo "Building Ephemeral Messenger..."

# Clean previous builds
rm -rf dist/
mkdir -p dist/

# Build server
echo "Building Go server..."
cd server
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o ../dist/server .
cd ..

# Build client
echo "Building Tauri client..."
cd client-tauri
npm run build
cd ..

# Copy additional files
cp -r configs/ dist/
cp -r scripts/ dist/
cp docs/ dist/ -r

# Create archive
echo "Creating distribution archive..."
cd dist
tar -czf ephemeral-messenger-linux-amd64.tar.gz *
cd ..

echo "Build complete! Archive: dist/ephemeral-messenger-linux-amd64.tar.gz"
```

### Security Hardening

#### Production Configuration

```yaml
# config/production.yaml
server:
  port: 8443
  tls:
    cert_file: "/etc/ssl/certs/server.crt"
    key_file: "/etc/ssl/private/server.key"
    min_version: "1.3"

security:
  rate_limit:
    requests_per_minute: 60
    websocket_connections_per_minute: 10

  headers:
    strict_transport_security: "max-age=31536000; includeSubDomains; preload"
    content_security_policy: "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'"
    x_frame_options: "DENY"
    x_content_type_options: "nosniff"

tor:
  control_port: 9051
  socks_port: 9050
  data_directory: "/var/lib/tor"
  log_level: "info"

logging:
  level: "info"
  format: "json"
  output: "/var/log/ephemeral-messenger/app.log"
  max_size_mb: 100
  max_backups: 5
```

## Contributing Guidelines

### Code Standards

#### Go Code Style

```go
// Use gofmt for formatting
// Follow effective Go guidelines

// Good: Clear naming and error handling
func (s *Server) registerClient(client *Client) error {
    if client == nil {
        return errors.New("client cannot be nil")
    }

    s.mu.Lock()
    defer s.mu.Unlock()

    if _, exists := s.clients[client.Fingerprint]; exists {
        return errors.New("client already registered")
    }

    s.clients[client.Fingerprint] = client
    log.Printf("Client registered: %s", client.Fingerprint)
    return nil
}

// Bad: Poor naming and error handling
func (s *Server) regClient(c *Client) {
    s.mu.Lock()
    s.clients[c.Fingerprint] = c
    s.mu.Unlock()
}
```

#### TypeScript Code Style

```typescript
// Use TypeScript strict mode
// Follow ESLint and Prettier configuration

// Good: Type safety and error handling
interface MessageHandler {
  handleMessage(message: WebSocketMessage): Promise<void>;
}

class SecureMessageHandler implements MessageHandler {
  constructor(
    private readonly cryptoService: CryptoService,
    private readonly identityService: IdentityService
  ) {}

  async handleMessage(message: WebSocketMessage): Promise<void> {
    try {
      const identity = this.identityService.getCurrentIdentity();
      if (!identity) {
        throw new Error('No identity available');
      }

      const decryptedContent = await this.cryptoService.decrypt(
        message.content,
        identity.privateKey
      );

      this.displayMessage(message.from, decryptedContent);
    } catch (error) {
      console.error('Message handling failed:', error);
      throw error;
    }
  }
}

// Bad: No type safety or error handling
class MessageHandler {
  handleMessage(message) {
    const content = decrypt(message.content);
    display(content);
  }
}
```

### Testing Requirements

All code contributions must include:

1. **Unit Tests**: Cover all public methods and edge cases
2. **Integration Tests**: Test component interactions
3. **Security Tests**: Validate security properties
4. **Performance Tests**: Ensure acceptable performance

#### Test Coverage Requirements

- **Minimum Coverage**: 80% line coverage
- **Critical Components**: 95% coverage (crypto, auth, network)
- **Security Functions**: 100% coverage

#### Pull Request Process

1. Fork the repository
2. Create feature branch from `main`
3. Implement changes with tests
4. Run full test suite
5. Update documentation
6. Submit pull request with description

### Security Review Process

#### Security-Critical Changes

Changes affecting the following require security review:

- Cryptographic implementations
- Authentication and authorization
- Network protocol handling
- Input validation and sanitization
- Memory management
- Hardware token integration

#### Review Checklist

- [ ] Cryptographic primitives properly used
- [ ] Input validation comprehensive
- [ ] Error handling doesn't leak information
- [ ] Memory management secure
- [ ] No hardcoded secrets
- [ ] Timing attack resistance
- [ ] Side-channel resistance
- [ ] Thread safety maintained

Remember: Security is everyone's responsibility. When in doubt, ask for a security review.