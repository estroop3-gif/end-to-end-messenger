# Session Cipher Wire Format Specification

## Overview

This document specifies the wire format for the Session Cipher system, which provides an additional layer of encryption for ephemeral messaging sessions. The system supports both classic ciphers (Caesar, Vigenère, OTP) and modern AEAD encryption.

## Version History

- **Version 1.0**: Initial implementation with Caesar, Vigenère, AEAD, and OTP support

## Core Data Structures

### CipherCode

The `CipherCode` is the primary data structure that defines a cipher configuration and is shared between session participants.

```rust
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CipherCode {
    pub version: u32,                    // Format version (currently 1)
    pub id: String,                      // Unique identifier
    pub label: String,                   // Human-readable label
    pub algorithm: CipherAlgorithm,      // Cipher algorithm specification
    pub created_at: u64,                 // Unix timestamp of creation
    pub expires_at: Option<u64>,         // Optional expiration timestamp
    pub producer_pubkey: Vec<u8>,        // Producer's public key (32 bytes Ed25519)
    pub signature: Vec<u8>,              // Ed25519 signature (64 bytes)
    pub payload: CipherPayload,          // Algorithm-specific data
}
```

### CipherAlgorithm

Specifies the cipher algorithm and its parameters:

```rust
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum CipherAlgorithm {
    Caesar { shift: i32 },
    Vigenere { keyword: String },
    AEAD { key_size: usize },
    OTP {
        pad_id: String,
        offset: u64,
        length: u64
    },
}
```

### CipherPayload

Contains algorithm-specific encrypted data:

```rust
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CipherPayload {
    pub data: Vec<u8>,                   // Algorithm-specific data
    pub integrity_check: Vec<u8>,        // HMAC or similar (32 bytes)
}
```

## Encoding Format

### Base58 Encoding

Cipher codes are encoded using Base58 for human readability and reduced error rates:

1. **Serialization**: CipherCode → JSON → bytes
2. **Compression**: bytes → compressed bytes (optional)
3. **Encoding**: compressed bytes → Base58 string

Example encoded cipher code:
```
5HueCGU8rMjxEXxiPuD5BDku4MkFqeZyd4dZ1jvhTVqvbTLvyTJ
```

### QR Code Generation

For easy sharing, cipher codes can be encoded as QR codes:

- **Error Correction**: Medium (15% recovery)
- **Module Size**: Auto-detected based on data size
- **Format**: Binary PNG data

## Message Wire Format

### Session Message Structure

Messages encrypted with session ciphers follow this format:

```
+------------------+------------------+------------------+
|   Session ID     |   Sequence No.   |   Encrypted Data |
|   (16 bytes)     |   (8 bytes)      |   (variable)     |
+------------------+------------------+------------------+
```

### Encryption Layers

The system implements **Option 1: Layered Encryption** where session cipher is applied before Layer A:

```
Plaintext
    ↓ Session Cipher (Caesar/Vigenère/AEAD/OTP)
Session Encrypted Text
    ↓ Layer A (Double Ratchet)
Final Encrypted Message
```

## Algorithm Specifications

### Caesar Cipher

**Parameters**:
- `shift`: Integer shift value (-25 to +25)

**Format**:
```json
{
  "algorithm": {
    "Caesar": {
      "shift": 13
    }
  }
}
```

**Security Note**: For demonstration only; not cryptographically secure.

### Vigenère Cipher

**Parameters**:
- `keyword`: String keyword (ASCII letters only)

**Format**:
```json
{
  "algorithm": {
    "Vigenere": {
      "keyword": "SECRET"
    }
  }
}
```

**Security Note**: For demonstration only; vulnerable to frequency analysis.

### AEAD (ChaCha20-Poly1305)

**Parameters**:
- `key_size`: Key size in bytes (typically 32)

**Format**:
```json
{
  "algorithm": {
    "AEAD": {
      "key_size": 32
    }
  }
}
```

**Security**: Cryptographically secure authenticated encryption.

### OTP (One-Time Pad)

**Parameters**:
- `pad_id`: Identifier for the OTP pad
- `offset`: Starting offset in the pad
- `length`: Number of bytes to consume

**Format**:
```json
{
  "algorithm": {
    "OTP": {
      "pad_id": "pad_001",
      "offset": 1000,
      "length": 256
    }
  }
}
```

**Security**: Information-theoretically secure when used correctly.

## Security Considerations

### Cryptographic Integrity

All cipher codes include:

1. **Ed25519 Signature**: 64-byte signature over serialized data
2. **HMAC Integrity**: 32-byte HMAC of payload data
3. **Producer Verification**: Public key of cipher code creator

### Memory Safety

- **ZeroizeOnDrop**: Session keys automatically cleared from memory
- **Secure Random**: Cryptographically secure random number generation
- **No Plaintext Disk Storage**: Session plaintext never written to disk

### OTP Range Tracking

To prevent double-spending of OTP pad ranges:

```rust
pub struct SessionState {
    // ...
    pub otp_consumed_ranges: Vec<(u64, u64)>,  // (start, end) ranges
}
```

Ranges are permanently marked as consumed when sessions end.

## Session Lifecycle

### 1. Cipher Code Generation

```
User Input → Algorithm Selection → Key Generation → Signing → Base58 Encoding
```

### 2. Session Start

```
Cipher Code → Validation → Ephemeral Key Generation → Session Registration
```

### 3. Message Exchange

```
Plaintext → Session Cipher → Layer A Encryption → Network Transmission
```

### 4. Session End

```
Session Termination → Re-enveloping (optional) → OTP Range Marking → Cleanup
```

## Re-enveloping Process

When a session ends with `re_envelope_messages: true`:

1. **Decrypt**: Messages decrypted with session ephemeral key
2. **Re-encrypt**: Messages re-encrypted with user's long-term key
3. **Store**: Updated messages written to persistent storage
4. **Cleanup**: Session-encrypted versions securely deleted

## Protocol Extensions

### Future Algorithm Support

The wire format supports easy addition of new algorithms:

```rust
pub enum CipherAlgorithm {
    // Existing algorithms...
    NewAlgorithm {
        param1: String,
        param2: u64,
    },
}
```

### Versioning

The `version` field in `CipherCode` allows for protocol evolution while maintaining backwards compatibility.

## Example Usage

### Generate Caesar Cipher Code

```bash
session_cli generate "Test Session" caesar:13 3600 alice
```

### Start Session

```bash
session_cli start '{"version":1,"id":"test123",...}' alice,bob 60
```

### Encrypt Message

```bash
session_cli encrypt session_id "Hello, World!"
```

## Reference Implementation

The complete implementation is available in:

- `src/session.rs` - Core session management
- `src/session_commands.rs` - Tauri command bindings
- `src/bin/session_cli.rs` - Command-line interface
- `src/components/SessionManager.tsx` - React UI component

## Compliance

This specification ensures:

- **No Plaintext Storage**: Session plaintext never written to disk
- **Ephemeral Keys**: Session keys exist only in secure memory
- **Perfect Forward Secrecy**: Session termination destroys all ephemeral secrets
- **Cryptographic Integrity**: All data structures signed and verified
- **Memory Safety**: Automatic cleanup of sensitive data