# Triple-Encryption Onion Transport Wire Format Specification

## Overview

This document specifies the wire format for the triple-encryption ("onion") transport system used in the JESUS IS KING secure messenger. The system implements three independent AEAD (Authenticated Encryption with Associated Data) layers for end-to-end security across the following architecture:

```
SENDER CLIENT → LOCAL RELAY → SHUTTLE SERVICE → RECEIVER RELAY → RECEIVER CLIENT
```

## Encryption Layers

### Layer A (Inner): Signal Protocol
- **Purpose**: End-to-end encryption between sender and receiver clients
- **Algorithm**: Signal Protocol Double Ratchet
- **Key Management**: X3DH key agreement with curve25519
- **Implementation**: Existing Signal Protocol library

### Layer B (Middle): Inter-Relay Transport
- **Purpose**: Encryption between local relay and shuttle service
- **Algorithm**: ChaCha20-Poly1305 AEAD
- **Key Management**: X25519 ECDH with HKDF-SHA3-256 key derivation
- **Session**: Bidirectional (client→shuttle, shuttle→receiver)

### Layer C (Outer): Local Transport
- **Purpose**: Encryption between client and local relay
- **Algorithm**: AES-256-GCM AEAD
- **Key Management**: X25519 ECDH with HKDF-SHA3-256 key derivation
- **Session**: Per-connection with key rotation

## Message Flow

```
1. Client creates Signal envelope (Layer A)
2. Client applies bucketized padding
3. Client encrypts with Layer B (ChaCha20-Poly1305)
4. Client encrypts with Layer C (AES-256-GCM)
5. Client sends to Local Relay via WebSocket
6. Local Relay decrypts Layer C
7. Local Relay forwards Layer B envelope to Shuttle
8. Shuttle queues encrypted Layer B envelope
9. Receiver Relay claims Layer B envelope from Shuttle
10. Receiver Relay decrypts Layer B
11. Receiver Relay encrypts with receiver's Layer C
12. Receiver Relay sends to Receiver Client
13. Receiver Client decrypts Layer C
14. Receiver Client decrypts Signal envelope (Layer A)
```

## Wire Format Structures

### 1. OnionFrame (Outermost Container)

```rust
struct OnionFrame {
    c_envelope: LayerCEnvelope,
}
```

**Binary Layout:**
```
[LayerCEnvelope] (variable length)
```

### 2. LayerCEnvelope (AES-256-GCM)

```rust
struct LayerCEnvelope {
    session_id: [u8; 16],           // 16 bytes
    sequence: u64,                  // 8 bytes (big-endian)
    ciphertext: Vec<u8>,            // variable length
    tag: [u8; 16],                  // 16 bytes GCM tag
}
```

**Binary Layout:**
```
Offset | Size | Field
-------|------|-------
0      | 16   | session_id
16     | 8    | sequence (big-endian)
24     | N    | ciphertext
24+N   | 16   | tag
```

**Plaintext:** LayerBEnvelope

### 3. LayerBEnvelope (ChaCha20-Poly1305)

```rust
struct LayerBEnvelope {
    session_id: [u8; 16],           // 16 bytes
    sequence: u64,                  // 8 bytes (big-endian)
    direction: u8,                  // 1 byte (0=client→shuttle, 1=shuttle→receiver)
    ciphertext: Vec<u8>,            // variable length
    tag: [u8; 16],                  // 16 bytes Poly1305 tag
}
```

**Binary Layout:**
```
Offset | Size | Field
-------|------|-------
0      | 16   | session_id
16     | 8    | sequence (big-endian)
24     | 1    | direction
25     | N    | ciphertext
25+N   | 16   | tag
```

**Plaintext:** PaddedSignalEnvelope

### 4. PaddedSignalEnvelope

```rust
struct PaddedSignalEnvelope {
    original_size: u32,             // 4 bytes (big-endian)
    bucket_size: u32,               // 4 bytes (big-endian)
    signal_data: Vec<u8>,           // original_size bytes
    padding: Vec<u8>,               // (bucket_size - original_size - 16) bytes
    padding_hmac: [u8; 32],         // 32 bytes SHA3-256 HMAC
}
```

**Binary Layout:**
```
Offset | Size | Field
-------|------|-------
0      | 4    | original_size (big-endian)
4      | 4    | bucket_size (big-endian)
8      | OS   | signal_data (original_size bytes)
8+OS   | PS   | padding (bucket_size - original_size - 16 bytes)
8+BS-8 | 32   | padding_hmac
```

Where:
- OS = original_size
- PS = padding_size = bucket_size - original_size - 16
- BS = bucket_size

### 5. SignalEnvelope (Layer A)

```rust
struct SignalEnvelope {
    sender_id: [u8; 32],            // 32 bytes
    receiver_id: [u8; 32],          // 32 bytes
    message_id: [u8; 16],           // 16 bytes
    timestamp: u64,                 // 8 bytes (big-endian)
    signal_message: Vec<u8>,        // variable length
}
```

**Binary Layout:**
```
Offset | Size | Field
-------|------|-------
0      | 32   | sender_id
32     | 32   | receiver_id
64     | 16   | message_id
80     | 8    | timestamp (big-endian)
88     | N    | signal_message
```

## Padding System

### Bucket Sizes
Messages are padded to one of these fixed sizes:
- 4KB (4,096 bytes)
- 16KB (16,384 bytes)
- 64KB (65,536 bytes)
- 256KB (262,144 bytes)
- 1MB (1,048,576 bytes)

### Padding Algorithm
1. Calculate bucket size: `bucket = bucketize(original_size)`
2. Generate random padding: `padding_size = bucket - original_size - 16`
3. Compute HMAC: `hmac = HMAC-SHA3-256(padding_key, padding_data)`
4. Append HMAC to end of padded message

### Padding Key Derivation
```
padding_key = HKDF-SHA3-256(
    ikm = layer_b_key,
    salt = "PaddingHMAC2024",
    info = session_id || sequence,
    len = 32
)
```

## Key Management

### Key Derivation (All Layers)

**Layer C (AES-256-GCM):**
```
shared_secret = X25519(private_key, public_key)
salt = "LayerC-" || session_id
ikm = shared_secret
info = "AES256-GCM-Key" || direction
aes_key = HKDF-SHA3-256(ikm, salt, info, 32)
```

**Layer B (ChaCha20-Poly1305):**
```
shared_secret = X25519(private_key, public_key)
salt = "LayerB-" || session_id
ikm = shared_secret
info = "ChaCha20-Key" || direction
chacha_key = HKDF-SHA3-256(ikm, salt, info, 32)
```

### Session Management

**Session ID Generation:**
```
session_id = first_16_bytes(SHA3-256(ephemeral_public_key || timestamp))
```

**Key Rotation:**
- Layer C: Every 1000 messages or 24 hours
- Layer B: Every 10000 messages or 7 days

## Transport Protocols

### Client ↔ Local Relay (WebSocket)

**Frame Format:**
```javascript
{
    "type": "onion_message",
    "session_id": "base64-encoded-session-id",
    "sequence": 12345,
    "data": "base64-encoded-onion-frame"
}
```

### Local Relay ↔ Shuttle (HTTP)

**Offer Endpoint:** `POST /api/v1/offer`
```json
{
    "message_id": "uuid-v4",
    "recipient": "recipient-id",
    "payload": "base64-encoded-layer-b-envelope",
    "ttl_seconds": 86400,
    "priority": 5,
    "metadata": {
        "sender_hint": "optional-sender-hint",
        "content_type": "application/octet-stream",
        "frame_size": 1024,
        "timestamp_ms": 1699123456789,
        "retry_count": 0
    }
}
```

**Claim Endpoint:** `POST /api/v1/claim`
```json
{
    "client_id": "recipient-id",
    "max_messages": 10,
    "timeout_seconds": 30
}
```

**Response:**
```json
{
    "messages": [
        {
            "message_id": "uuid-v4",
            "payload": "base64-encoded-layer-b-envelope",
            "queued_at": 1699123456,
            "claim_token": "uuid-v4",
            "ttl_remaining": 82800,
            "metadata": {
                "sender_hint": "optional-sender-hint",
                "content_type": "application/octet-stream",
                "frame_size": 1024,
                "timestamp_ms": 1699123456789,
                "retry_count": 0
            }
        }
    ],
    "more": false
}
```

## Security Properties

### Confidentiality
- **Layer A**: End-to-end confidentiality via Signal Protocol
- **Layer B**: Transport confidentiality between relays
- **Layer C**: Local link confidentiality

### Authentication
- **Layer A**: Signal Protocol sender authentication
- **Layer B**: ChaCha20-Poly1305 AEAD authentication
- **Layer C**: AES-256-GCM AEAD authentication

### Forward Secrecy
- **Layer A**: Signal Protocol Double Ratchet provides forward secrecy
- **Layer B**: Key rotation provides forward secrecy
- **Layer C**: Per-session keys provide forward secrecy

### Traffic Analysis Resistance
- **Padding**: Bucketized padding hides message sizes
- **Cover Traffic**: Random dummy messages (future enhancement)
- **Timing**: Constant-time cryptographic operations

## Implementation Notes

### Constant-Time Operations
All cryptographic operations MUST be implemented in constant time to prevent timing attacks.

### Memory Management
- Cryptographic keys MUST be zeroed after use
- Plaintext buffers MUST be zeroed after encryption
- Use secure memory allocation where available

### Error Handling
- Cryptographic failures MUST NOT leak information
- All errors MUST be logged for debugging
- Invalid messages MUST be discarded silently

### Performance Optimizations
- Batch multiple messages when possible
- Use vectorized AES instructions where available
- Implement zero-copy operations for large messages

## Test Vectors

### Layer C Test Vector

**Input:**
- Private Key: `0x1234567890abcdef...` (32 bytes)
- Public Key: `0xfedcba0987654321...` (32 bytes)
- Session ID: `0x1122334455667788...` (16 bytes)
- Sequence: `42`
- Plaintext: `"Hello, World!"` (13 bytes)

**Expected Ciphertext:** `0x...` (29 bytes + 16 byte tag)

### Layer B Test Vector

**Input:**
- Private Key: `0xabcdef1234567890...` (32 bytes)
- Public Key: `0x0987654321fedcba...` (32 bytes)
- Session ID: `0x8877665544332211...` (16 bytes)
- Sequence: `123`
- Direction: `0` (client→shuttle)
- Plaintext: `0x...` (padded signal envelope)

**Expected Ciphertext:** `0x...` (variable length + 16 byte tag)

## Version History

- **v1.0** (2024-01): Initial specification
- **v1.1** (2024-02): Added padding HMAC integrity protection
- **v1.2** (2024-03): Enhanced key derivation with session-specific salts

## References

1. [Signal Protocol Specification](https://signal.org/docs/)
2. [RFC 8439: ChaCha20 and Poly1305](https://tools.ietf.org/html/rfc8439)
3. [RFC 5116: AEAD Interface](https://tools.ietf.org/html/rfc5116)
4. [RFC 5869: HKDF](https://tools.ietf.org/html/rfc5869)
5. [RFC 7748: Elliptic Curves for Security](https://tools.ietf.org/html/rfc7748)