# Secure Messaging & Document Suite

A comprehensive zero-persistence system providing secure messaging, file transfer, and encrypted document editing designed for TailsOS and high-security environments. No backdoors, no telemetry, auditable components only.

## ⚠️ SECURITY ADVISORY ⚠️

This software protects messages in transit and at-rest under the stated threat model but **CANNOT** protect compromised endpoints. Users must follow proper operational security (OpSec) practices. This software should **NOT** be used to commit illegal acts. This project is intended for legitimate privacy and secure communications only.

## Architecture Overview

```
┌─────────────────┐    Tor Hidden Service    ┌─────────────────┐
│     Sender      │◄──────────────────────────►│    Receiver     │
│                 │                            │                 │
│ ┌─────────────┐ │                            │ ┌─────────────┐ │
│ │   Layer A   │ │  Triple Encryption:        │ │   Layer A   │ │
│ │Signal Ratchet│ │  A → B → C (send)         │ │Signal Ratchet│ │
│ └─────────────┘ │  C → B → A (receive)       │ └─────────────┘ │
│ ┌─────────────┐ │                            │ ┌─────────────┐ │
│ │   Layer B   │ │                            │ │   Layer B   │ │
│ │Identity ECDH │ │                            │ │Identity ECDH │ │
│ └─────────────┘ │                            │ └─────────────┘ │
│ ┌─────────────┐ │                            │ ┌─────────────┐ │
│ │   Layer C   │ │                            │ │   Layer C   │ │
│ │ Age/Passkey │ │                            │ │ Age/Passkey │ │
│ └─────────────┘ │                            │ └─────────────┘ │
└─────────────────┘                            └─────────────────┘
```

## Core Capabilities

### 1. Secure Messaging & File Transfer
- **Zero Persistence**: No plaintext ever written to disk (memfd anonymous files)
- **Triple Encryption**: Signal Double Ratchet + Identity ECDH + Age/Passphrase
- **Tor Hidden Services**: Ephemeral v3 onion services with client authorization
- **Hardware Token Support**: YubiKey/OpenPGP preferred, Argon2id secure memory fallback
- **Pre-Send Authentication**: Comprehensive security checklist before every send
- **Chunked File Transfer**: AEAD per chunk with integrity manifests and resumable uploads

### 2. Secure Document Editor (.securedoc format)
- **Rich Text Editor**: Word-like editor with ProseMirror (headings, bold, italic, lists, tables, images)
- **Encrypted Document Format**: Single .securedoc files with triple encryption
- **Multi-Recipient Support**: Per-recipient sealed envelopes with age key wrapping
- **Detached Signatures**: Ed25519 signatures over document manifest
- **Pre-Open Security Checks**: Full security validation before any decryption
- **Zero Disk Persistence**: All editing in locked memory, secure wipe on close

### 3. Security & Hardening
- **No Backdoors Policy**: Reproducible builds, signed commits, mandatory code review
- **No Telemetry**: Zero analytics, no hidden network calls during document operations
- **Hardware Security**: Hardware token preferred for identity keys (Ed25519 + X25519)
- **Secure Memory**: libsodium secure memory, mlockall, swap detection and prevention
- **Binary Verification**: Signature verification required before encrypt/decrypt operations

## Threat Model

**Protects Against:**
- Network surveillance and traffic analysis
- Server compromise (ephemeral, no persistence)
- Message interception and modification
- Metadata leakage
- Forward secrecy compromise

**Does NOT Protect Against:**
- Compromised endpoints (sender/receiver devices)
- Side-channel attacks on compromised hardware
- Physical device seizure with active sessions
- Social engineering or coercion
- Implementation bugs (requires code audit)

## Quick Start

### Prerequisites
- TailsOS or Linux with Tor installed
- Hardware security token (YubiKey recommended)
- Out-of-band secure channel for key exchange

### Installation on Tails
```bash
# See docs/tails-runbook.md for detailed instructions
./tools/install-tails.sh
```

### Basic Usage
```bash
# Generate identity (receiver)
./ephemeral-messenger generate-identity

# Start receiver
./ephemeral-messenger receive

# Send message (from another machine)
./ephemeral-messenger send --recipient <onion-address> --message "Hello"
```

## Repository Structure

```
├── server/          # Go server (ephemeral transport)
├── client/          # Electron + React client
├── tools/           # Tor control, key management scripts
├── demo/            # Demo scripts and examples
├── docs/            # Documentation and runbooks
├── tests/           # Unit and integration tests
└── README.md        # This file
```

## Documentation

- [Security Model](docs/security-model.md) - Detailed threat model and cryptographic choices
- [Tails Runbook](docs/tails-runbook.md) - Step-by-step instructions for TailsOS
- [OpSec Checklist](docs/opsec-checklist.md) - Operational security best practices
- [API Documentation](docs/api.md) - Server and client API reference
- [Build Instructions](docs/build.md) - Reproducible build process

## License

MIT License - See LICENSE file for details.

## Contributing

Security-critical code requires careful review. Please see CONTRIBUTING.md for guidelines.

## Audit Status

**⚠️ DEVELOPMENT VERSION - NOT YET AUDITED**

This software has not yet undergone a professional security audit. Use at your own risk.