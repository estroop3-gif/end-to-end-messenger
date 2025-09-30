# Local Relay for Triple-Encryption Onion Transport

This is the local relay component that handles Layer C (AES-256-GCM) decryption and forwards messages to the shuttle service.

## Architecture

```
CLIENT (Tauri Rust) → LOCAL RELAY (Go) → SHUTTLE (Go) → RECEIVER RELAY → RECEIVER CLIENT
                     ↑ THIS COMPONENT
```

## Features

- **Layer C Decryption**: AES-256-GCM with X25519 key agreement
- **WebSocket Server**: Real-time communication with clients
- **Shuttle Integration**: Forwards messages via offer/claim API
- **Circuit Breaker**: Resilient shuttle communication
- **Key Rotation**: Automatic cryptographic key rotation
- **Health Monitoring**: Health checks and metrics
- **Session Management**: Multiple concurrent client sessions

## Configuration

The relay uses a JSON configuration file (`config.json`):

```json
{
  "server": {
    "port": 8080,
    "cors_origins": ["http://localhost:3000", "tauri://localhost"]
  },
  "crypto": {
    "layer_c_private_key_hex": "",  // Auto-generated if empty
    "layer_c_public_key_hex": "",   // Auto-generated if empty
    "key_rotation_interval": "30m",
    "session_timeout": "24h"
  },
  "shuttle": {
    "url": "https://shuttle.example.com",
    "api_key": "your-api-key",
    "timeout": "30s",
    "retry_attempts": 3
  }
}
```

## Building

```bash
go mod tidy
go build -o local-relay .
```

## Running

```bash
# With default config
./local-relay

# With custom config and port
./local-relay -config custom.json -port 9090

# With debug logging
./local-relay -log debug
```

## API Endpoints

### WebSocket
- `ws://localhost:8080/ws` - Client connections

### HTTP API
- `GET /api/v1/health` - Health check
- `GET /api/v1/stats` - Server statistics
- `GET /api/v1/sessions` - Active sessions
- `GET /api/v1/config` - Configuration (sanitized)

## Client Protocol

### WebSocket Messages

**Binary Messages** (Onion Frames):
```
[Wire Version: 1 byte][Length: 4 bytes][Frame Data: N bytes]
```

**Text Messages** (Control):
```json
{"type": "ping"}
{"type": "status"}
```

### Frame Format

```json
{
  "c_envelope": {
    "v": 1,
    "route": {
      "session_id": "uuid",
      "dst_hint": "recipient-id"
    },
    "aad": {
      "size_orig": 1024,
      "bucket": 4096,
      "t_bucket": 1640995200
    },
    "ct": "base64-encrypted-data",
    "nonce_c": "base64-nonce"
  }
}
```

## Security

- X25519 key agreement for Layer C
- AES-256-GCM authenticated encryption
- Constant-time operations
- Secure key zeroization
- Frame size limits (2MB max)
- Session timeouts
- Rate limiting

## Logging

Structured JSON logging with configurable levels:
- `debug` - Verbose debugging
- `info` - General information (default)
- `warn` - Warnings
- `error` - Errors only

## Monitoring

The relay provides metrics for:
- Active sessions
- Messages processed
- Bytes transferred
- Error counts
- Shuttle health status
- Key rotation events

## Development

### Project Structure
```
local-relay/
├── main.go                    # Entry point
├── internal/
│   ├── config/               # Configuration management
│   ├── crypto/               # Layer C crypto operations
│   ├── relay/                # WebSocket server & session handling
│   ├── shuttle/              # Shuttle client with circuit breaker
│   └── wire/                 # Wire format serialization
└── config.json               # Default configuration
```

### Testing

```bash
go test ./...
go test -race ./...
go test -cover ./...
```

### Docker

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod tidy && go build -o local-relay .

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/local-relay .
COPY --from=builder /app/config.json .
CMD ["./local-relay"]
```