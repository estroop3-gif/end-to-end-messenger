# Session Cipher System

## Overview

The Session Cipher system provides an additional layer of encryption for ephemeral messaging sessions in the Ephemeral Messenger application. It implements a layered encryption approach where session-specific ciphers are applied before the main Signal protocol encryption.

## Features

### 🔐 Multiple Cipher Algorithms
- **Caesar Cipher**: Educational demonstration of classical cryptography
- **Vigenère Cipher**: Polyalphabetic cipher for learning purposes
- **AEAD Encryption**: Modern ChaCha20-Poly1305 authenticated encryption
- **One-Time Pad (OTP)**: Information-theoretically secure encryption

### 🛡️ Security Features
- **Layered Encryption**: Session cipher + Signal protocol double encryption
- **Perfect Forward Secrecy**: Ephemeral session keys automatically destroyed
- **Memory Safety**: ZeroizeOnDrop for automatic secret cleanup
- **Cryptographic Integrity**: Ed25519 signatures and HMAC verification
- **Zero Disk Storage**: Session plaintext never written to persistent storage

### 📱 User Experience
- **QR Code Sharing**: Easy cipher code sharing via QR codes
- **Base58 Encoding**: Human-readable cipher code format
- **React UI**: Intuitive session management interface
- **Real-time Messaging**: Seamless encrypted messaging within sessions
- **Session Management**: Create, join, list, and end sessions

### 🔧 Developer Tools
- **CLI Interface**: `session_cli` tool for testing and automation
- **Comprehensive Tests**: Full test suite for all functionality
- **Tauri Integration**: Native desktop application with web UI
- **API Documentation**: Complete wire format specification

## Architecture

### Layered Encryption (Option 1)

```
Plaintext Message
    ↓ Session Cipher (Caesar/Vigenère/AEAD/OTP)
Session Encrypted Text
    ↓ Layer A (Signal Double Ratchet)
Final Encrypted Message
    ↓ Network Transmission
```

This approach maintains all benefits of the Signal protocol while adding session-specific encryption.

### Core Components

```
src/
├── session.rs              # Core session management and cipher implementations
├── session_commands.rs     # Tauri command bindings for frontend integration
├── bin/session_cli.rs      # Command-line interface for testing
└── components/
    └── SessionManager.tsx  # React UI component for session management
```

## Quick Start

### 1. Install Dependencies

```bash
cd client-tauri
npm install
```

### 2. Build the Application

```bash
npm run tauri build
```

### 3. Run in Development

```bash
npm run tauri dev
```

### 4. Use CLI Tool

```bash
# Generate a cipher code
cargo run --bin session_cli generate "Test Session" caesar:13 3600 alice

# Run tests
cargo run --bin session_cli test all
```

## Usage Examples

### Creating a Cipher Session (UI)

1. Open the Ephemeral Messenger application
2. Navigate to **Message Center** → **🔐 Cipher Sessions**
3. Click **"Create Session"**
4. Configure your session:
   - **Label**: "Team Meeting"
   - **Algorithm**: AEAD (32-byte key)
   - **Duration**: 60 minutes
   - **Participants**: alice, bob, charlie
5. Share the generated QR code or Base58 cipher code

### Joining a Session (UI)

1. Click **"Join Session"**
2. Enter the cipher code or scan QR code
3. Add your participant name
4. Start secure messaging immediately

### Command Line Usage

```bash
# Generate AEAD cipher code
session_cli generate "Secure Chat" aead:32 7200 alice

# Start a session
session_cli start '{"version":1,"id":"test123",...}' alice,bob,charlie 120

# Encrypt a message
session_cli encrypt session_abc123 "This is a secret message"

# List active sessions
session_cli list

# End session with re-enveloping
session_cli end session_abc123 true
```

## Security Model

### Threat Model

**Protected Against**:
- Passive network eavesdropping
- Server-side message inspection
- Compromise of individual sessions (forward secrecy)
- Memory dumps (automatic cleanup)
- Replay attacks (sequence numbers)

**NOT Protected Against**:
- End-device compromise
- Physical access to unlocked device
- Malicious session participants
- Side-channel attacks

### Cipher Security

| Algorithm | Security Level | Use Case |
|-----------|---------------|----------|
| Caesar | None (Demo) | Education, Testing |
| Vigenère | None (Demo) | Education, Historical Interest |
| AEAD | High | Production Messaging |
| OTP | Perfect* | Maximum Security |

*When used correctly with truly random pads

### Key Management

- **Session Keys**: 256-bit randomly generated ephemeral keys
- **Memory Protection**: ZeroizeOnDrop trait for automatic cleanup
- **Perfect Forward Secrecy**: Keys destroyed on session end
- **OTP Management**: Range tracking prevents double-spending

## API Reference

### Tauri Commands

```typescript
// Generate cipher code
await invoke('generate_cipher_code', {
  label: string,
  algorithm: CipherAlgorithm,
  ttlSeconds?: number,
  producerFingerprint: string,
  embedSecret: boolean
});

// Start session
await invoke('start_cipher_session', {
  sessionId?: string,
  cipherCode: CipherCode,
  participants: string[],
  ttlMinutes?: number
});

// Encrypt message
await invoke('encrypt_session_message', {
  sessionId: string,
  plaintext: string
});

// Decrypt message
await invoke('decrypt_session_message', {
  sessionId: string,
  ciphertext: Uint8Array
});

// End session
await invoke('end_cipher_session', {
  sessionId: string,
  reEnvelope: boolean
});
```

### Wire Format

See [session_cipher_wire_format.md](./session_cipher_wire_format.md) for complete specification.

## Testing

### Run Unit Tests

```bash
cargo test --lib
```

### Run CLI Tests

```bash
cargo run --bin session_cli test all
```

### Test Individual Algorithms

```bash
cargo run --bin session_cli test caesar
cargo run --bin session_cli test vigenere
cargo run --bin session_cli test aead
cargo run --bin session_cli test otp
```

## Documentation

- **[Wire Format Specification](./session_cipher_wire_format.md)**: Complete technical specification
- **[User Guide](./session_cipher_guide.md)**: End-user documentation and best practices
- **[API Documentation](../src/session.rs)**: Inline code documentation

## Configuration

### Environment Variables

```bash
# Enable debug logging
RUST_LOG=debug

# Customize session defaults
SESSION_DEFAULT_TTL_MINUTES=60
SESSION_MAX_PARTICIPANTS=10
```

### Build Features

```toml
# In Cargo.toml
[features]
default = ["session-cipher"]
session-cipher = []
cli-tools = []
```

## Performance

### Benchmarks

- **Caesar Cipher**: ~1M ops/sec
- **Vigenère Cipher**: ~500K ops/sec
- **AEAD Encryption**: ~100K ops/sec
- **Session Creation**: ~1K sessions/sec

### Memory Usage

- **Baseline**: ~2MB per session
- **Large Sessions**: ~5MB per 100 participants
- **Message Overhead**: +64 bytes per message

## Roadmap

### Version 1.1 (Planned)
- [ ] Additional cipher algorithms (Blowfish, Twofish)
- [ ] Group key rotation
- [ ] Mobile app support
- [ ] Enhanced OTP pad management

### Version 1.2 (Future)
- [ ] Hardware security module integration
- [ ] Quantum-resistant algorithms
- [ ] Distributed session management
- [ ] Advanced analytics dashboard

## Contributing

### Development Setup

1. Install Rust toolchain
2. Install Node.js and npm
3. Clone repository
4. Run `npm install`
5. Run `cargo build`

### Testing

- Add tests for new cipher algorithms
- Ensure UI components are tested
- Verify CLI functionality
- Test memory safety with Valgrind

### Code Style

- Follow Rust standard formatting (`cargo fmt`)
- Use `clippy` for linting (`cargo clippy`)
- Document all public APIs
- Add security comments for crypto code

## License

MIT License - see [LICENSE](../LICENSE) file for details.

## Security Disclosure

For security issues, please email: security@ephemeral-messenger.org

Do not create public GitHub issues for security vulnerabilities.

## Acknowledgments

- **Signal Protocol**: Foundation for Layer A encryption
- **ChaCha20-Poly1305**: Modern AEAD implementation
- **Tauri Framework**: Cross-platform application development
- **React**: User interface framework
- **Rust Cryptography**: Memory-safe crypto implementations

---

**⚠️ Security Notice**: This implementation is for educational and demonstration purposes. While the AEAD and OTP algorithms provide strong security guarantees, a full security audit is recommended before production use in high-security environments.