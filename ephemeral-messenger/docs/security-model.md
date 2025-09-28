# Security Model - Ephemeral Messenger

This document defines the security model, threat assumptions, and cryptographic design of Ephemeral Messenger.

## Security Objectives

### Primary Objectives
1. **Confidentiality**: Message content must remain secret from all adversaries
2. **Authenticity**: Recipients must be able to verify message sender identity
3. **Integrity**: Any tampering with messages must be detectable
4. **Forward Secrecy**: Compromise of long-term keys must not compromise past messages
5. **Post-Compromise Security**: Systems must recover from state compromise
6. **Anonymity**: Communication metadata must be protected from network observers
7. **Ephemeral Transport**: No persistent infrastructure dependencies

### Secondary Objectives
1. **Plausible Deniability**: Messages should not provide cryptographic proof of authorship
2. **Repudiability**: No non-repudiable digital signatures on message content
3. **Traffic Analysis Resistance**: Communication patterns should resist metadata analysis
4. **Zero Persistence**: No plaintext data written to permanent storage

## Threat Model

### Adversary Capabilities

#### Network Adversary (Dolev-Yao)
- **Capabilities**:
  - Complete control over network communications
  - Can intercept, modify, delay, or drop any network traffic
  - Can inject arbitrary network traffic
  - Cannot break cryptographic primitives
  - Cannot access endpoint devices physically

- **Limitations**:
  - Cannot break Tor's anonymity properties with network observation alone
  - Cannot decrypt properly encrypted traffic
  - Cannot forge signatures without private keys

#### State-Level Adversary
- **Capabilities**:
  - All network adversary capabilities
  - Traffic analysis on global scale
  - Compromise of internet infrastructure
  - Legal compulsion of service providers
  - Advanced cryptanalysis capabilities
  - Side-channel attacks on implementations

- **Limitations**:
  - Cannot break properly implemented cryptographic primitives
  - Cannot access physically secured hardware tokens
  - Cannot break mathematical foundations of cryptography

#### Physical Adversary
- **Capabilities**:
  - Physical access to devices when unattended
  - Memory analysis of powered devices
  - Hardware implants and modifications
  - Coercive attacks on users
  - Supply chain compromise

- **Limitations**:
  - Cannot access properly locked memory on secured hardware
  - Cannot extract keys from properly designed hardware tokens
  - Cannot break encryption of powered-off devices

#### Endpoint Compromise
- **Capabilities**:
  - Complete control over one communication endpoint
  - Access to all data on compromised device
  - Ability to run arbitrary code
  - Access to user input (keyboard, mouse, etc.)

- **Limitations**:
  - Cannot access data on other endpoints
  - Cannot decrypt messages sent before compromise
  - Cannot impersonate users without access to their hardware tokens

### Threat Scenarios

#### Scenario 1: Passive Network Surveillance
- **Threat**: State-level traffic analysis and content interception
- **Mitigations**:
  - Tor routing prevents traffic analysis
  - Triple encryption prevents content access
  - Ephemeral onion services prevent long-term monitoring

#### Scenario 2: Active Network Attacks
- **Threat**: Man-in-the-middle attacks, message injection, replay attacks
- **Mitigations**:
  - Out-of-band key verification prevents MITM
  - Cryptographic authentication prevents injection
  - Signal protocol provides replay protection

#### Scenario 3: Server Compromise
- **Threat**: Compromise of transport server infrastructure
- **Mitigations**:
  - Server never sees plaintext (triple encryption)
  - Ephemeral servers provide no persistent attack surface
  - Client controls server lifecycle

#### Scenario 4: Endpoint Compromise
- **Threat**: Malware, physical access, or coercive attacks on user devices
- **Mitigations**:
  - Hardware tokens protect long-term keys
  - Memory locking prevents key extraction
  - Zero persistence limits exposure window

#### Scenario 5: Long-term Key Compromise
- **Threat**: Theft or compromise of user's long-term identity keys
- **Mitigations**:
  - Signal protocol provides forward secrecy
  - Hardware tokens make key extraction difficult
  - Key rotation limits exposure time

## Cryptographic Design

### Triple Encryption Architecture

The system employs three layers of encryption for defense in depth:

```
Plaintext Message
       ↓
Layer A: Signal Double Ratchet Encryption
       ↓
Layer B: Identity ECDH Encryption
       ↓
Layer C: Age/Passphrase Encryption
       ↓
Transmitted Ciphertext
```

#### Layer A: Signal Double Ratchet
- **Purpose**: Provides forward secrecy and post-compromise security
- **Algorithm**: Signal Double Ratchet Protocol (RFC-style implementation needed)
- **Key Material**:
  - Identity key pair (long-term Ed25519)
  - Ephemeral keys (X25519, rotated per message chain)
  - Root key and chain keys (derived via HKDF)

- **Properties**:
  - Forward secrecy: Past messages remain secure after key compromise
  - Post-compromise security: Security recovers after compromise
  - Break-in recovery: New DH exchanges heal compromise
  - Asynchronous: Works without real-time key exchange

#### Layer B: Identity ECDH Encryption
- **Purpose**: Provides authenticated encryption between long-term identities
- **Algorithm**: X25519 ECDH + XChaCha20-Poly1305
- **Key Material**:
  - Sender's long-term X25519 private key
  - Recipient's long-term X25519 public key
  - Ephemeral X25519 key pair (generated per message)

- **Properties**:
  - Authenticated encryption
  - Ephemeral key prevents key reuse
  - Strong anonymity (ciphertext reveals no identity information)

#### Layer C: Age/Passphrase Encryption
- **Purpose**: Provides additional security layer and user-controlled decryption
- **Algorithm**: Age encryption or Argon2id + XChaCha20-Poly1305
- **Key Material**:
  - Age recipient keys (X25519-based) OR
  - User-supplied passphrase (processed via Argon2id)

- **Properties**:
  - User-controlled: Requires explicit user action to decrypt
  - Hardware token integration: Can be derived from hardware token
  - Deniable: Passphrase-based encryption provides plausible deniability

### Key Management

#### Identity Keys
- **Generation**: On-device using hardware RNG or hardware token
- **Storage**: Hardware token (preferred) or encrypted on-device storage
- **Lifecycle**: Long-term (months), rotated on schedule or compromise
- **Algorithm**: Ed25519 for signatures, X25519 for encryption

#### Session Keys
- **Generation**: Signal Double Ratchet key derivation
- **Storage**: Secure memory only (never written to disk)
- **Lifecycle**: Per-message or per-session
- **Algorithm**: ChaCha20-Poly1305 for AEAD encryption

#### Transport Keys
- **Generation**: Per-session, ephemeral
- **Storage**: Memory only, wiped after session
- **Lifecycle**: Single session
- **Algorithm**: X25519 for key agreement

### Authentication

#### User Authentication
- **Primary**: Hardware token (YubiKey) with PIN
- **Secondary**: Strong passphrase with Argon2id KDF
- **Biometric**: Optional, only for hardware token unlock

#### Message Authentication
- **Digital Signatures**: Ed25519 signatures on message content
- **MAC**: Poly1305 MAC from AEAD encryption
- **Identity Binding**: Signatures tied to verified identity keys

#### Peer Authentication
- **Key Verification**: Out-of-band fingerprint verification
- **Safety Numbers**: Signal-style safety number system
- **Trust-on-First-Use**: Initial key exchange with manual verification

### Anonymity and Metadata Protection

#### Network Anonymity
- **Tor Integration**: All traffic routed through Tor network
- **Onion Services**: Communication via v3 onion services
- **Traffic Padding**: Dummy traffic to obscure patterns (future enhancement)

#### Timing Correlation Resistance
- **Variable Delays**: Random delays added to message transmission
- **Batching**: Multiple messages sent together when possible
- **Cover Traffic**: Dummy messages to hide real communication patterns

#### Size Padding
- **Message Padding**: All messages padded to standard sizes
- **Chunking**: Large messages split into uniform chunks
- **Dummy Content**: Random data added to obscure real content size

## Security Properties

### Confidentiality Properties

#### Message Confidentiality
- **IND-CCA2**: Indistinguishable under chosen ciphertext attack
- **Semantic Security**: Ciphertext reveals no information about plaintext
- **Key Privacy**: Ciphertext reveals no information about keys used

#### Forward Secrecy
- **Perfect Forward Secrecy**: Compromise of long-term keys does not compromise past messages
- **Signal-level Forward Secrecy**: Each message encrypted with ephemeral keys
- **Session Forward Secrecy**: Each session uses independent keys

#### Future Secrecy (Post-Compromise Security)
- **Break-in Recovery**: Security recovers after compromise via new DH exchanges
- **Self-Healing**: Protocol automatically recovers from state compromise
- **Key Rotation**: Regular key rotation limits exposure time

### Authentication Properties

#### Message Authentication
- **Unforgeability**: Adversary cannot forge valid messages
- **Non-Malleability**: Adversary cannot modify messages without detection
- **Replay Protection**: Old messages cannot be replayed

#### Identity Authentication
- **Identity Binding**: Messages cryptographically bound to sender identity
- **Key Authenticity**: Public keys authenticated via out-of-band verification
- **Participant Authentication**: Both parties authenticate to each other

### Integrity Properties

#### Message Integrity
- **Tamper Detection**: Any modification to ciphertext detected
- **Atomic Integrity**: Partial messages rejected
- **Order Integrity**: Message ordering preserved and verified

#### Protocol Integrity
- **State Integrity**: Protocol state protected from manipulation
- **Transcript Integrity**: Full conversation transcript protected
- **Session Integrity**: Session establishment protected from attacks

### Anonymity Properties

#### Sender Anonymity
- **Network Anonymity**: Sender IP address hidden via Tor
- **Unlinkability**: Messages cannot be linked to sender
- **Traffic Analysis Resistance**: Communication patterns obscured

#### Recipient Anonymity
- **Onion Service Privacy**: Recipient location hidden
- **Access Pattern Privacy**: Access patterns to onion service obscured
- **Long-term Unlinkability**: Recipients cannot be tracked over time

#### Relationship Anonymity
- **Communication Privacy**: Fact of communication hidden
- **Frequency Privacy**: Communication frequency obscured
- **Duration Privacy**: Session duration information hidden

## Security Assumptions

### Cryptographic Assumptions
1. **Discrete Logarithm**: X25519 and Ed25519 security
2. **Random Oracle**: Hash functions behave as random oracles
3. **Authenticated Encryption**: ChaCha20-Poly1305 provides IND-CCA2 security
4. **Key Derivation**: HKDF provides secure key derivation

### Infrastructure Assumptions
1. **Tor Security**: Tor provides traffic analysis resistance
2. **Hardware Token Security**: YubiKey provides secure key storage
3. **OS Security**: TailsOS provides memory protection and amnesic properties
4. **Hardware Security**: Hardware RNG provides sufficient entropy

### Operational Assumptions
1. **User Compliance**: Users follow operational security procedures
2. **Key Verification**: Users perform out-of-band key verification
3. **Environment Security**: Users operate in physically secure environments
4. **Update Security**: Users apply security updates promptly

### Implementation Assumptions
1. **Constant-Time**: Cryptographic operations execute in constant time
2. **Memory Security**: Sensitive data properly cleared from memory
3. **Side-Channel Resistance**: Implementation resists timing and power analysis
4. **Secure Randomness**: RNG provides cryptographically secure randomness

## Attack Resistance

### Cryptographic Attacks

#### Chosen Plaintext Attack (CPA)
- **Protection**: IND-CPA security from all encryption layers
- **Mitigation**: Semantic security prevents information leakage

#### Chosen Ciphertext Attack (CCA)
- **Protection**: IND-CCA2 security from AEAD encryption
- **Mitigation**: Authentication prevents ciphertext manipulation

#### Key Recovery Attacks
- **Protection**: Computationally hard problems (DL, ECDLP)
- **Mitigation**: Strong key derivation and forward secrecy

### Protocol Attacks

#### Man-in-the-Middle (MITM)
- **Protection**: Out-of-band key verification
- **Mitigation**: Authenticated key exchange and trust anchors

#### Replay Attacks
- **Protection**: Signal protocol replay protection
- **Mitigation**: Sequence numbers and message authentication

#### Protocol Downgrade
- **Protection**: Strong negotiation and version pinning
- **Mitigation**: No fallback to weaker protocols

### Network Attacks

#### Traffic Analysis
- **Protection**: Tor routing and traffic padding
- **Mitigation**: Uniform message sizes and timing

#### Correlation Attacks
- **Protection**: Ephemeral onion services
- **Mitigation**: Variable session timing and duration

#### Intersection Attacks
- **Protection**: Cover traffic and dummy sessions
- **Mitigation**: Decoy communications (future enhancement)

### Side-Channel Attacks

#### Timing Attacks
- **Protection**: Constant-time implementations
- **Mitigation**: Algorithm selection and implementation practices

#### Power Analysis
- **Protection**: Hardware token design
- **Mitigation**: Secure hardware and randomization

#### Cache Attacks
- **Protection**: Cache-timing resistant implementations
- **Mitigation**: Memory access patterns and data-independent algorithms

## Limitations and Assumptions

### Known Limitations
1. **Signal Protocol**: Placeholder implementation requires audit
2. **Hardware Dependency**: Requires specific hardware tokens for maximum security
3. **User Error**: Vulnerable to user operational security failures
4. **Implementation Bugs**: Security depends on correct implementation

### Future Enhancements
1. **Post-Quantum Cryptography**: Add PQC algorithms for future protection
2. **Advanced Traffic Analysis**: Enhanced padding and cover traffic
3. **Formal Verification**: Mathematical proof of protocol properties
4. **Hardware Security Modules**: Support for enterprise HSMs

### Residual Risks
1. **Endpoint Compromise**: Cannot protect against full endpoint compromise
2. **User Coercion**: Cannot protect against coercive attacks on users
3. **Supply Chain**: Cannot protect against hardware/software supply chain attacks
4. **Insider Threats**: Cannot protect against malicious developers

---

This security model provides a comprehensive framework for understanding the security properties and limitations of Ephemeral Messenger. Regular security reviews and updates to this model are essential as threats evolve and the system matures.