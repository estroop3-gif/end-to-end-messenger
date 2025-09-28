# Ephemeral Messenger Server

A secure, ephemeral messaging server built in Go with WebSocket support, rate limiting, and Tor integration.

## Features

### Core Functionality
- **Ephemeral Transport**: Messages are temporarily stored and automatically expire
- **WebSocket Communication**: Real-time bidirectional messaging
- **Zero Persistence**: No long-term storage of message content
- **Rate Limiting**: Protection against abuse and DoS attacks
- **Security Middleware**: IP blocking, origin validation, and security headers

### Security Features
- **Fingerprint-based Authentication**: Client identification using cryptographic fingerprints
- **Message Sanitization**: Content validation and cleaning
- **Security Event Logging**: Comprehensive audit trail
- **Configurable TTL**: Automatic message expiration
- **Origin Validation**: WebSocket origin checking

### Network Features
- **Tor Integration**: Hidden service support for anonymous communication
- **CORS Support**: Cross-origin resource sharing configuration
- **Health Monitoring**: Built-in health checks and statistics
- **Graceful Shutdown**: Clean server termination with connection cleanup

## Quick Start

### Prerequisites
- Go 1.21 or later
- Docker (optional)

### Installation

1. **Clone and setup:**
   ```bash
   cd server-go
   go mod tidy
   ```

2. **Run directly:**
   ```bash
   go run .
   ```

3. **Build and run:**
   ```bash
   go build -o ephemeral-server
   ./ephemeral-server
   ```

4. **Docker deployment:**
   ```bash
   docker-compose up -d
   ```

### Configuration

Set environment variables:

```bash
export PORT=8443
export LOG_LEVEL=info
export TOR_ENABLED=true
```

## API Endpoints

### WebSocket Connection
- **Endpoint**: `ws://localhost:8443/ws?fingerprint=<client_fingerprint>`
- **Protocol**: WebSocket with JSON message format

### HTTP Endpoints
- **Health Check**: `GET /health`
- **Statistics**: `GET /stats`

## Message Format

```json
{
  "id": "unique-message-id",
  "from": "sender-fingerprint",
  "to": "recipient-fingerprint",
  "content": "encrypted-message-content",
  "timestamp": "2023-01-01T12:00:00Z",
  "expires_at": "2023-01-02T12:00:00Z",
  "delivery_type": "direct"
}
```

## Security Configuration

### Rate Limiting
- Default: 100 requests per minute per IP
- Burst limit: 10 requests
- Configurable per deployment

### Message Expiration
- Default TTL: 24 hours
- Automatic cleanup every hour
- No persistent storage

### IP Blocking
- Automatic blocking for abuse
- Configurable block duration
- Security event logging

## Deployment

### Docker Deployment

The server includes a complete Docker setup with:
- Multi-stage build for minimal image size
- Non-root user execution
- Health checks
- Security hardening

```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f ephemeral-server

# Scale if needed
docker-compose up -d --scale ephemeral-server=3
```

### Tor Integration

For anonymous communication:

1. **Enable Tor in configuration**
2. **Configure hidden service**
3. **Use .onion address for connections**

The server automatically generates Tor keys and provides setup instructions.

### Production Considerations

1. **TLS/SSL**: Configure HTTPS in production
2. **Reverse Proxy**: Use Nginx for load balancing
3. **Monitoring**: Implement log aggregation
4. **Firewall**: Restrict network access
5. **Updates**: Regular security updates

## Monitoring

### Health Checks
```bash
curl http://localhost:8443/health
```

### Statistics
```bash
curl http://localhost:8443/stats
```

### Security Events
Monitor security events through the stats endpoint for:
- Rate limit violations
- Blocked IP attempts
- Invalid origins
- Authentication failures

## Development

### Testing
```bash
go test ./...
```

### Linting
```bash
golangci-lint run
```

### Building
```bash
# For current platform
go build -o ephemeral-server

# For Linux (from other platforms)
GOOS=linux GOARCH=amd64 go build -o ephemeral-server-linux

# For Windows
GOOS=windows GOARCH=amd64 go build -o ephemeral-server.exe
```

## Architecture

### Core Components

1. **Hub**: Manages client connections and message routing
2. **Security Manager**: Handles authentication and rate limiting
3. **WebSocket Handler**: Manages real-time connections
4. **Message Store**: Temporary message storage with TTL
5. **Cleanup Service**: Automatic expired message removal

### Message Flow

1. Client connects via WebSocket with fingerprint
2. Server registers client and delivers pending messages
3. Messages are routed directly to online recipients
4. Offline recipient messages are stored temporarily
5. Messages expire and are cleaned up automatically

### Security Model

- **No trust in clients**: All validation on server
- **Minimal data retention**: Ephemeral storage only
- **Defense in depth**: Multiple security layers
- **Audit trail**: Comprehensive logging
- **Graceful degradation**: Service continues under attack

## Troubleshooting

### Common Issues

1. **Connection refused**: Check port and firewall
2. **Rate limit errors**: Reduce request frequency
3. **WebSocket failures**: Verify origin configuration
4. **Message delivery fails**: Check recipient fingerprint

### Debug Mode
```bash
LOG_LEVEL=debug go run .
```

### Port Configuration
```bash
PORT=9000 go run .
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes with tests
4. Submit pull request

## License

This project is part of the Ephemeral Messenger secure communication system.

## Security Reporting

Report security issues privately to the development team.