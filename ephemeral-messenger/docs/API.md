# Ephemeral Messenger API Documentation

## Overview

The Ephemeral Messenger API provides secure, end-to-end encrypted messaging and document sharing capabilities. The system is designed for maximum security with zero persistence, Tor integration, and hardware token support.

## Base URLs

- **Local Development**: `http://localhost:8443`
- **Production**: Configure with your Tor hidden service address

## Authentication

All WebSocket connections require a client fingerprint for identification:

```
ws://localhost:8443/ws?fingerprint=<64-char-hex-fingerprint>
```

## HTTP Endpoints

### Health Check

```http
GET /health
```

Returns server health status and basic metrics.

**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z",
  "clients": 5,
  "pending_messages": 12,
  "version": "1.0.0"
}
```

### Server Statistics

```http
GET /stats
```

Returns detailed server statistics.

**Response:**
```json
{
  "server": {
    "uptime": "1h30m",
    "total_clients": 25,
    "pending_messages": 8,
    "message_ttl": "24h0m0s"
  },
  "clients": [
    {
      "fingerprint": "abcd1234...",
      "last_seen": "2024-01-01T12:00:00Z",
      "connected": true
    }
  ]
}
```

### Tor Management

#### Get Tor Status

```http
GET /tor/status
```

Returns current Tor connection status.

**Response:**
```json
{
  "connected": true,
  "bootstrapped": true,
  "onion_address": "example.onion",
  "control_port": 9051,
  "socks_port": 9050,
  "circuit_count": 3,
  "hidden_services": 1
}
```

#### Get Tor Circuits

```http
GET /tor/circuits
```

Returns information about active Tor circuits.

**Response:**
```json
[
  {
    "id": "circuit_001",
    "status": "BUILT",
    "path": ["Guard", "Middle", "Exit"],
    "purpose": "GENERAL",
    "time_built": "2024-01-01 12:00:00"
  }
]
```

#### Create New Circuit

```http
POST /tor/newcircuit?purpose=GENERAL
```

Creates a new Tor circuit.

**Response:**
```json
{
  "id": "circuit_002",
  "status": "BUILDING",
  "path": [],
  "purpose": "GENERAL",
  "time_built": "2024-01-01 12:05:00"
}
```

#### Get Tor Configuration

```http
GET /tor/config
```

Returns current Tor configuration.

#### Update Tor Configuration

```http
PUT /tor/config
```

Updates Tor configuration settings.

**Request Body:**
```json
{
  "log_level": "info",
  "circuit_timeout": 15,
  "bridge_mode": false
}
```

#### Get Hidden Services

```http
GET /tor/services
```

Returns configured hidden services.

**Response:**
```json
[
  {
    "name": "ephemeral-messenger",
    "onion_address": "example.onion",
    "ports": [
      {
        "virtual_port": 80,
        "target_host": "127.0.0.1",
        "target_port": "8443"
      }
    ],
    "client_auth": true
  }
]
```

#### Create Hidden Service

```http
POST /tor/services
```

Creates a new hidden service.

**Request Body:**
```json
{
  "name": "my-service",
  "virtual_port": 80,
  "target_host": "127.0.0.1",
  "target_port": "8443",
  "version": 3
}
```

#### Delete Hidden Service

```http
DELETE /tor/services?name=my-service
```

Removes a hidden service.

#### Test Tor Connection

```http
GET /tor/test?url=https://check.torproject.org/api/ip
```

Tests connectivity through Tor.

**Response:**
```json
{
  "url": "https://check.torproject.org/api/ip",
  "success": true,
  "response": "{\"IsTor\":true}",
  "latency": 2500,
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## WebSocket API

### Connection

Connect to WebSocket endpoint with fingerprint:

```javascript
const ws = new WebSocket('ws://localhost:8443/ws?fingerprint=your_64_char_fingerprint');
```

### Message Format

All WebSocket messages use JSON format:

```json
{
  "id": "unique_message_id",
  "from": "sender_fingerprint",
  "to": "recipient_fingerprint",
  "content": "encrypted_message_content",
  "timestamp": "2024-01-01T12:00:00Z",
  "expires_at": "2024-01-02T12:00:00Z",
  "delivery_type": "direct"
}
```

### Sending Messages

Send a message to another client:

```javascript
const message = {
  to: "recipient_fingerprint_64_chars",
  content: "Your encrypted message content here"
};

ws.send(JSON.stringify(message));
```

### Receiving Messages

Listen for incoming messages:

```javascript
ws.onmessage = function(event) {
  const message = JSON.parse(event.data);

  if (message.from === 'server') {
    // Server notification (delivery confirmation, etc.)
    console.log('Server notification:', message.content);
  } else {
    // User message
    console.log('Message from:', message.from);
    console.log('Content:', message.content);
  }
};
```

### Delivery Confirmations

The server sends delivery confirmations:

```json
{
  "id": "confirmation_id",
  "from": "server",
  "to": "sender_fingerprint",
  "content": "{\"type\":\"delivery_status\",\"message_id\":\"original_msg_id\",\"delivered\":true}",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## Client-Side Services

### Identity Management

Generate and manage cryptographic identities:

```typescript
import { identityService } from './services/identityService';

// Generate new identity
const identity = await identityService.generateIdentity("strong_passphrase");

// Get current identity
const currentIdentity = identityService.getCurrentIdentity();

// Clear identity
identityService.clearIdentity();
```

### Message Encryption

Encrypt and decrypt messages:

```typescript
import { messageService } from './services/messageService';

// Encrypt message
const encrypted = await messageService.encryptMessage(
  "Hello World",
  recipientPublicKey
);

// Decrypt message
const decrypted = await messageService.decryptMessage(encryptedData);
```

### Document Operations

Create and manage secure documents:

```typescript
import { documentService } from './services/documentService';

// Create document
const document = await documentService.createDocument({
  title: "Secret Document",
  content: "Document content here",
  recipients: [recipientKey1, recipientKey2],
  policy: { expiration: 3600 },
  passphrase: "document_passphrase"
});

// Save document
await documentService.saveDocument(document, "/path/to/file.securedoc");

// Load document
const loadedDoc = await documentService.loadDocument("/path/to/file.securedoc");
```

### Hardware Token Support

Manage hardware tokens:

```typescript
import { hardwareTokenService } from './services/hardwareTokenService';

// Check support
const isSupported = hardwareTokenService.isSupported();

// Enroll token
const result = await hardwareTokenService.enrollWebAuthnToken(
  "username",
  "Display Name"
);

// Authenticate
const authResult = await hardwareTokenService.authenticateWithWebAuthn();

// Sign data
const signature = await hardwareTokenService.signWithToken(
  tokenId,
  dataToSign
);
```

### YubiKey Integration

Work with YubiKey devices:

```typescript
import { yubiKeyService } from './services/yubiKeyService';

// Initialize
await yubiKeyService.initialize();

// Request device access
await yubiKeyService.requestDevice();

// Generate key pair
const keyPair = await yubiKeyService.generateKeyPair(
  'signature',
  'Ed25519',
  adminPin
);

// Sign data
const result = await yubiKeyService.sign(data, 'signature', userPin);
```

### Security Validation

Validate security before sending:

```typescript
import { securityValidator } from './services/securityValidator';

// Validate message
const result = await securityValidator.validateMessage(
  messageContent,
  recipientFingerprint
);

if (!result.passed) {
  console.error('Security validation failed:', result.errors);
} else {
  console.log('Security score:', result.score);
  // Proceed with sending
}
```

### Memory Protection

Use secure memory handling:

```typescript
import { memoryProtection } from './services/memoryProtection';

// Allocate secure buffer
const bufferId = memoryProtection.allocateSecureBuffer(1024, "sensitive_data");

// Write data
memoryProtection.writeSecureBuffer(bufferId, sensitiveData);

// Read data
const data = memoryProtection.readSecureBuffer(bufferId);

// Secure wipe
memoryProtection.wipeSecureBuffer(bufferId);

// Create secure string
const secureStr = memoryProtection.createSecureString("secret");
const value = secureStr.getValue();
secureStr.wipe(); // Always wipe when done
```

### Tor Integration

Monitor and control Tor:

```typescript
import { torService } from './services/torService';

// Initialize
await torService.initialize();

// Get status
const status = torService.getStatus();

// Create hidden service
const service = await torService.createHiddenService("my-service", 8443);

// Test connection
const isReachable = await torService.testOnionService("example.onion");

// Create new circuit
const circuitId = await torService.newCircuit();
```

### Input Sanitization

Sanitize user inputs:

```typescript
import { inputSanitizer } from './services/inputSanitizer';

// Sanitize text
const result = inputSanitizer.sanitizeText(userInput);
if (!result.safe) {
  console.warn('Input sanitization issues:', result.issues);
}

// Validate JSON
const jsonResult = inputSanitizer.sanitizeJSON(jsonString);

// Validate file
const fileResult = inputSanitizer.validateFile(uploadedFile);
```

### Challenge-Response Authentication

Authenticate with hardware tokens:

```typescript
import { challengeResponseAuth } from './services/challengeResponseAuth';

// Create authentication session
const session = challengeResponseAuth.createAuthenticationSession(
  tokenId,
  "message_signing"
);

// Authenticate session
const authenticated = await challengeResponseAuth.authenticateSession(
  session.sessionId,
  userPin
);

// Sign with authenticated session
const signature = await challengeResponseAuth.signWithSession(
  session.sessionId,
  dataToSign,
  "document_signature"
);
```

## Error Handling

All API endpoints return standard HTTP status codes:

- `200 OK` - Success
- `400 Bad Request` - Invalid request
- `401 Unauthorized` - Authentication required
- `403 Forbidden` - Access denied
- `404 Not Found` - Resource not found
- `429 Too Many Requests` - Rate limit exceeded
- `500 Internal Server Error` - Server error
- `503 Service Unavailable` - Service temporarily unavailable

Error responses include details:

```json
{
  "error": "Invalid fingerprint format",
  "code": "INVALID_FINGERPRINT",
  "details": "Fingerprint must be 64 hexadecimal characters"
}
```

## Rate Limiting

API endpoints are rate limited:

- WebSocket connections: 10 per minute per IP
- Tor endpoints: 30 requests per minute per IP
- General endpoints: 60 requests per minute per IP

Rate limit headers are included in responses:

```
X-RateLimit-Limit: 60
X-RateLimit-Remaining: 45
X-RateLimit-Reset: 1641024000
```

## Security Headers

All responses include security headers:

```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
Strict-Transport-Security: max-age=31536000; includeSubDomains
Content-Security-Policy: default-src 'self'
```

## Best Practices

### Client Development

1. **Always validate inputs** before sending to server
2. **Use secure memory** for sensitive data
3. **Implement proper error handling** for network failures
4. **Respect rate limits** to avoid blocking
5. **Clear sensitive data** from memory when done
6. **Use hardware tokens** when available for enhanced security

### Security

1. **Never log sensitive data** (keys, passphrases, plaintext)
2. **Validate all server responses** before processing
3. **Use HTTPS/WSS** in production
4. **Implement proper session management**
5. **Regular security audits** and penetration testing
6. **Keep dependencies updated**

### Performance

1. **Reuse WebSocket connections** when possible
2. **Implement exponential backoff** for retries
3. **Cache non-sensitive data** appropriately
4. **Monitor memory usage** and clean up regularly
5. **Use compression** for large messages

## Examples

### Complete Message Flow

```typescript
// 1. Generate identity
const identity = await identityService.generateIdentity("my_passphrase");

// 2. Connect to server
const ws = new WebSocket(`ws://localhost:8443/ws?fingerprint=${identity.fingerprint}`);

// 3. Set up message handler
ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  // Handle incoming message
};

// 4. Send encrypted message
const encryptedMessage = await messageService.encryptMessage(
  "Hello, secure world!",
  recipientPublicKey
);

ws.send(JSON.stringify({
  to: recipientFingerprint,
  content: encryptedMessage
}));
```

### Secure Document Creation

```typescript
// 1. Create document with security validation
const securityResult = await securityValidator.validateMessage(
  documentContent,
  recipientFingerprint
);

if (securityResult.passed) {
  // 2. Create secure document
  const document = await documentService.createDocument({
    title: "Confidential Report",
    content: documentContent,
    recipients: [recipientKey],
    policy: { expiration: 86400 }, // 24 hours
    passphrase: "strong_document_passphrase"
  });

  // 3. Save with secure memory
  const bufferId = memoryProtection.allocateSecureBuffer(document.size);
  await documentService.saveDocument(document, "report.securedoc");
  memoryProtection.releaseSecureBuffer(bufferId);
}
```

### Hardware Token Authentication

```typescript
// 1. Check hardware token support
if (hardwareTokenService.isSupported()) {
  // 2. Enroll token
  const enrollment = await hardwareTokenService.enrollWebAuthnToken(
    "alice",
    "Alice's Security Key"
  );

  if (enrollment.success) {
    // 3. Create authentication session
    const session = challengeResponseAuth.createAuthenticationSession(
      enrollment.token.id,
      "secure_messaging"
    );

    // 4. Authenticate with hardware token
    const authenticated = await challengeResponseAuth.authenticateSession(
      session.sessionId
    );

    if (authenticated) {
      // 5. Use session for signing
      const signature = await challengeResponseAuth.signWithSession(
        session.sessionId,
        messageData,
        "message_signature"
      );
    }
  }
}
```

## Support

For additional support and examples, refer to:

- [User Guide](./USER_GUIDE.md)
- [Security Guide](./SECURITY.md)
- [Developer Guide](./DEVELOPER.md)
- [Deployment Guide](./DEPLOYMENT.md)