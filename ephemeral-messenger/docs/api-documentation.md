# API Documentation - Ephemeral Messenger

This document describes the internal APIs for both the server and client components of Ephemeral Messenger.

## Server API

### Base URL
```
http://localhost:8080
```

### Authentication
All requests except `/health` require the `X-Session-ID` header with a valid session ID.

### Rate Limiting
- **Message endpoints**: 10 requests per minute per session
- **Session endpoints**: 5 requests per minute per IP
- **Health endpoint**: 100 requests per minute per IP

### Error Responses
All endpoints return errors in JSON format:
```json
{
  "error": "Error description",
  "code": "ERROR_CODE",
  "details": "Additional details if available"
}
```

### Endpoints

#### Health Check
```http
GET /health
```

Check server health and status.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": 3600,
  "tor_status": "connected",
  "memory_usage": "45MB",
  "active_sessions": 3
}
```

#### Create Session
```http
POST /session
```

Create a new messaging session.

**Request Body:**
```json
{
  "client_version": "1.0.0",
  "supported_features": ["chunking", "compression"]
}
```

**Response (201 Created):**
```json
{
  "id": "sess_abc123def456",
  "expires_at": "2024-01-01T12:00:00Z",
  "buffer_limit": 10485760,
  "chunk_size": 1048576,
  "session_timeout": 300
}
```

**Error Responses:**
- `400 Bad Request`: Invalid request format
- `429 Too Many Requests`: Rate limit exceeded
- `503 Service Unavailable`: Server overloaded

#### Send Message
```http
POST /message
```

Send an encrypted message.

**Headers:**
```
X-Session-ID: sess_abc123def456
Content-Type: application/json
```

**Request Body:**
```json
{
  "session_id": "sess_abc123def456",
  "ciphertext": "base64-encoded-encrypted-data",
  "signature": "base64-encoded-signature",
  "timestamp": 1704067200,
  "metadata": {
    "content_type": "text",
    "chunk_index": 0,
    "total_chunks": 1,
    "content_length": 1024
  }
}
```

**Response (200 OK):**
```json
{
  "buffer_id": "buf_xyz789abc123",
  "stored_at": "2024-01-01T12:00:00Z",
  "expires_at": "2024-01-01T12:05:00Z",
  "checksum": "sha256:abcd1234..."
}
```

**Error Responses:**
- `400 Bad Request`: Invalid message format or size
- `401 Unauthorized`: Invalid or expired session
- `413 Payload Too Large`: Message exceeds size limit
- `429 Too Many Requests`: Rate limit exceeded

#### Send Chunk
```http
POST /chunk
```

Send a file chunk (for large file transfers).

**Headers:**
```
X-Session-ID: sess_abc123def456
Content-Type: application/json
```

**Request Body:**
```json
{
  "session_id": "sess_abc123def456",
  "chunk_id": "chunk_001",
  "chunk_index": 0,
  "total_chunks": 5,
  "ciphertext": "base64-encoded-chunk-data",
  "signature": "base64-encoded-signature",
  "checksum": "sha256:chunk-hash"
}
```

**Response (200 OK):**
```json
{
  "buffer_id": "buf_chunk_001",
  "received_chunks": [0, 1, 2],
  "missing_chunks": [3, 4],
  "completion_status": "partial"
}
```

#### Retrieve Message
```http
GET /retrieve/{buffer_id}
```

Retrieve a stored message.

**Headers:**
```
X-Session-ID: sess_abc123def456
```

**Path Parameters:**
- `buffer_id`: The buffer ID returned from message/chunk submission

**Response (200 OK):**
```json
{
  "buffer_id": "buf_xyz789abc123",
  "ciphertext": "base64-encoded-encrypted-data",
  "signature": "base64-encoded-signature",
  "timestamp": 1704067200,
  "metadata": {
    "content_type": "text",
    "chunk_index": 0,
    "total_chunks": 1,
    "content_length": 1024
  },
  "retrieved_at": "2024-01-01T12:01:00Z"
}
```

**Error Responses:**
- `401 Unauthorized`: Invalid or expired session
- `404 Not Found`: Buffer ID not found or expired
- `410 Gone`: Message already retrieved (single-use)

#### List Buffers
```http
GET /buffers
```

List all available buffers for the session.

**Headers:**
```
X-Session-ID: sess_abc123def456
```

**Response (200 OK):**
```json
{
  "buffers": [
    {
      "buffer_id": "buf_xyz789abc123",
      "stored_at": "2024-01-01T12:00:00Z",
      "expires_at": "2024-01-01T12:05:00Z",
      "size": 1024,
      "content_type": "text",
      "chunks": 1
    }
  ],
  "total_count": 1,
  "total_size": 1024
}
```

#### Delete Session
```http
DELETE /session/{session_id}
```

Delete a session and all associated buffers.

**Headers:**
```
X-Session-ID: sess_abc123def456
```

**Response (200 OK):**
```json
{
  "message": "Session deleted successfully",
  "buffers_deleted": 3,
  "data_wiped": "5.2MB"
}
```

## Client API (IPC)

The Electron client uses Inter-Process Communication (IPC) between the main process and renderer.

### Security Manager API

#### Run Pre-Send Checks
```typescript
interface PreSendCheckRequest {
  recipientId: string;
  recipientOnion: string;
  requireHardwareToken?: boolean;
}

interface PreSendCheckResponse {
  torReachability: SecurityCheckResult;
  swapStatus: SecurityCheckResult;
  memoryLock: SecurityCheckResult;
  hardwareToken: SecurityCheckResult;
  fingerprintVerification: SecurityCheckResult;
  clientCertificate: SecurityCheckResult;
  binarySignature: SecurityCheckResult;
  timeWindow: SecurityCheckResult;
  overallPassed: boolean;
}

// Usage
const result = await ipcRenderer.invoke('security:pre-send-checks', {
  recipientId: 'user123',
  recipientOnion: 'abc123...xyz.onion',
  requireHardwareToken: true
});
```

### Crypto Manager API

#### Generate Identity
```typescript
interface GenerateIdentityRequest {
  passphrase?: string;
  useHardwareToken?: boolean;
}

interface Identity {
  publicIdentity: string;
  fingerprint: string;
}

// Usage
const identity = await ipcRenderer.invoke('crypto:generate-identity', {
  passphrase: 'optional-passphrase',
  useHardwareToken: true
});
```

#### Encrypt Message
```typescript
interface EncryptMessageRequest {
  plaintext: string;
  recipientPublicIdentity: string;
}

interface EncryptedMessage {
  layerA: string;
  layerB: string;
  layerC: string;
  nonce: string;
  ephemeralKey: string;
  timestamp: number;
  signature: string;
}

// Usage
const encrypted = await ipcRenderer.invoke('crypto:encrypt-message', {
  plaintext: 'Hello, world!',
  recipientPublicIdentity: 'base64-encoded-public-key'
});
```

#### Decrypt Message
```typescript
interface DecryptMessageRequest {
  encryptedMessage: EncryptedMessage;
}

// Usage
const plaintext = await ipcRenderer.invoke('crypto:decrypt-message', {
  encryptedMessage: encryptedData
});
```

### Tor Manager API

#### Create Onion Service
```typescript
interface CreateOnionRequest {
  localPort: number;
  onionPort?: number;
  clientAuthKey?: string;
}

interface OnionServiceResponse {
  address: string;
  privateKey: string;
  clientAuthKey?: string;
}

// Usage
const onion = await ipcRenderer.invoke('tor:create-onion', {
  localPort: 8080,
  onionPort: 80
});
```

#### Check Tor Status
```typescript
interface TorStatusResponse {
  connected: boolean;
  version: string;
  controlPort: number;
  socksPort: number;
  circuitCount: number;
}

// Usage
const status = await ipcRenderer.invoke('tor:status');
```

### Storage Manager API

#### Store Encrypted Data
```typescript
interface StoreEncryptedRequest {
  key: string;
  data: string;
  encrypt?: boolean;
}

// Usage
await ipcRenderer.invoke('storage:store-encrypted', {
  key: 'user-settings',
  data: JSON.stringify(settings),
  encrypt: true
});
```

#### Retrieve Encrypted Data
```typescript
interface RetrieveEncryptedRequest {
  key: string;
}

// Usage
const data = await ipcRenderer.invoke('storage:retrieve-encrypted', {
  key: 'user-settings'
});
```

## Error Codes

### Server Error Codes
- `INVALID_SESSION`: Session ID is invalid or expired
- `RATE_LIMITED`: Request rate limit exceeded
- `BUFFER_NOT_FOUND`: Requested buffer does not exist
- `BUFFER_EXPIRED`: Buffer has expired and been purged
- `PAYLOAD_TOO_LARGE`: Message exceeds maximum size
- `INVALID_SIGNATURE`: Message signature verification failed
- `SERVER_OVERLOADED`: Server is at capacity
- `TOR_UNAVAILABLE`: Tor connection is not available

### Client Error Codes
- `CRYPTO_INIT_FAILED`: Failed to initialize cryptographic components
- `IDENTITY_GENERATION_FAILED`: Failed to generate new identity
- `ENCRYPTION_FAILED`: Message encryption failed
- `DECRYPTION_FAILED`: Message decryption failed
- `HARDWARE_TOKEN_NOT_FOUND`: Required hardware token not detected
- `SECURITY_CHECK_FAILED`: One or more security checks failed
- `TOR_CONNECTION_FAILED`: Failed to connect to Tor
- `ONION_CREATION_FAILED`: Failed to create onion service

## Security Considerations

### Request Authentication
All API requests are authenticated using session-based tokens. Sessions expire after 5 minutes of inactivity.

### Rate Limiting
Rate limits are enforced per session for messaging operations and per IP for session management to prevent abuse.

### Input Validation
All inputs are validated for:
- Size limits (messages < 10MB, chunks < 1MB)
- Format validation (base64 encoding, JSON structure)
- Signature verification for all message content

### Memory Security
- All sensitive data is stored in secure buffers
- Memory is wiped after use
- No plaintext data is logged or persisted

### Error Information
Error messages are designed to provide sufficient information for debugging while avoiding information disclosure that could aid attackers.

## Rate Limits

### Server Endpoints
| Endpoint | Limit | Window |
|----------|-------|--------|
| `/health` | 100 requests | 1 minute |
| `/session` | 5 requests | 1 minute |
| `/message` | 10 requests | 1 minute |
| `/chunk` | 50 requests | 1 minute |
| `/retrieve/*` | 20 requests | 1 minute |
| `/buffers` | 10 requests | 1 minute |

### Client IPC
| Operation | Limit | Window |
|-----------|-------|--------|
| `crypto:*` | 20 requests | 1 minute |
| `security:*` | 10 requests | 1 minute |
| `tor:*` | 15 requests | 1 minute |
| `storage:*` | 30 requests | 1 minute |

## Message Size Limits

### Server Limits
- **Single message**: 10MB maximum
- **File chunk**: 1MB maximum
- **Total session data**: 100MB maximum
- **Concurrent buffers**: 50 maximum per session

### Client Limits
- **Plaintext message**: 10MB maximum (before encryption)
- **File attachment**: 1GB maximum (chunked automatically)
- **Memory usage**: 500MB maximum for crypto operations

## Session Management

### Session Lifecycle
1. **Creation**: Client creates session via `/session` endpoint
2. **Active**: Session remains active while being used
3. **Idle**: Session becomes idle after 60 seconds of inactivity
4. **Expired**: Session expires after 5 minutes of inactivity
5. **Cleanup**: All session data is securely wiped on expiration

### Session Security
- Sessions are tied to IP address for basic security
- Session IDs are cryptographically random (256 bits)
- All session data is encrypted at rest
- Sessions automatically expire to limit exposure

---

This API documentation provides complete reference for integrating with Ephemeral Messenger components. For additional implementation details, refer to the source code and security model documentation.