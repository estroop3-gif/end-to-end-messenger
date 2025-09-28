# Local-Only Login Documentation

## Overview

Local-Only Login is an alternative authentication mode that stores encrypted credentials locally instead of requiring a physical hardware key. This mode provides convenience at the cost of reduced security and should only be used after careful consideration of the security implications.

⚠️ **WARNING**: Local-Only Login stores your authentication credentials on the local device. While encrypted, this represents a security risk if the device is compromised or seized.

## Security Model

### Encryption Details

#### Key Derivation
- **Algorithm**: Argon2id (RFC 9106)
- **Parameters**:
  - Time cost: 3 iterations
  - Memory cost: 64 MiB (65,536 KiB)
  - Parallelism: 1 thread
  - Output length: 32 bytes (256 bits)
- **Salt**: 32 bytes of cryptographically random data
- **Purpose**: Derives encryption key from user passphrase

#### Credential Encryption
- **Algorithm**: AES-256-GCM (AEAD)
- **Key**: Derived from passphrase using Argon2id
- **Nonce**: 12 bytes of cryptographically random data (unique per encryption)
- **Additional Data**: None (could include version/metadata in future)
- **Credential**: 32 bytes of cryptographically random data

#### Storage Format
```
Encrypted Credential File:
[32-byte salt][12-byte nonce][encrypted credential + 16-byte auth tag]

Settings File:
AES-256-GCM encrypted JSON containing:
{
  "access_mode": {
    "LocalOnly": {
      "encrypted_credential": [nonce + ciphertext + tag],
      "salt": [32-byte salt],
      "argon2_params": {
        "time_cost": 3,
        "memory_cost": 65536,
        "parallelism": 1
      }
    }
  },
  // ... other settings
}
```

## Security Risks

### Primary Risks

1. **Device Seizure**
   - Encrypted credentials stored on device
   - Subject to offline attacks
   - No physical access control

2. **Passphrase Compromise**
   - Single point of failure
   - Vulnerable to shoulder surfing, keyloggers
   - May be subject to coercion

3. **Memory Attacks**
   - Passphrase temporarily in memory during authentication
   - Vulnerable to memory dumps, hibernation files
   - Cold boot attacks on unencrypted RAM

4. **Backup Exposure**
   - Settings file may be included in system backups
   - Cloud sync may upload encrypted credentials
   - Network storage vulnerabilities

### Secondary Risks

1. **Brute Force Attacks**
   - Offline attacks against encrypted credentials
   - Argon2id provides resistance but not immunity
   - Depends on passphrase strength

2. **Side Channel Attacks**
   - Timing attacks during authentication
   - Power analysis (if applicable)
   - Cache-based attacks

3. **Software Vulnerabilities**
   - Bugs in implementation
   - Library vulnerabilities
   - OS-level security issues

## Risk Mitigation

### Required Mitigations

1. **Strong Passphrase**
   - Minimum 20 characters (strongly recommended)
   - High entropy (mix of character types)
   - Avoid common words/patterns
   - Use passphrase generator if possible

2. **Full Disk Encryption**
   - Encrypt entire system drive
   - Use strong encryption (AES-256 or equivalent)
   - Secure boot process

3. **Physical Security**
   - Secure physical access to device
   - Automatic screen locking
   - Tamper-evident storage

4. **Memory Protection**
   - Disable hibernation/swap files
   - Use encrypted swap if needed
   - Regular system reboots

### Recommended Mitigations

1. **Network Security**
   - Secure network connections only
   - VPN for untrusted networks
   - Network monitoring

2. **Backup Security**
   - Exclude settings directory from automated backups
   - Encrypt manual backups separately
   - Secure backup storage

3. **Regular Security Practices**
   - Regular passphrase rotation
   - Security audits
   - Incident response planning

## Implementation Details

### Core Implementation

The local login system has been implemented with the following components:

#### Backend Components (Rust/Tauri)
- **`settings_store.rs`**: Encrypted settings storage using Argon2id + ChaCha20-Poly1305
- **`login_commands.rs`**: Tauri command bindings for frontend integration
- **`keydetect.rs`**: Cross-platform hardware key detection

#### Frontend Components (React/TypeScript)
- **`Login.tsx`**: Main login interface with tabbed design
- **`Login.css`**: Nord theme styling with accessibility features

#### Tauri Commands Available
```rust
set_local_passphrase_cmd(passphrase: String) -> LoginResponse
verify_local_passphrase_cmd(passphrase: String) -> LoginResponse
set_hardkey_mode_cmd() -> LoginResponse
check_hardkey_cmd() -> HardKeyStatus
settings_load_cmd() -> SettingsResponse
logout_cmd() -> LoginResponse
is_authenticated_cmd() -> bool
clear_local_credential_cmd() -> LoginResponse
```

### Passphrase Requirements

#### Minimum Requirements (Enforced)
- Length: 12 characters
- Character variety: At least 3 of 4 types (upper, lower, digit, symbol)
- No common patterns: "password", "123", predictable sequences

#### Recommended Requirements
- Length: 20+ characters
- High entropy: Use diceware or random generation
- Unique: Not used elsewhere
- Memorable: Can be reliably entered without writing down

#### Strength Validation
The system provides real-time password strength feedback:
- **Weak** (0-1 points): Insufficient for local-only mode
- **Medium** (2-3 points): Minimally acceptable
- **Strong** (4-5 points): Good security
- **Very Strong** (6+ points): Excellent security

Scoring factors:
- Length (1-2 points)
- Character variety (0-2 points)
- Pattern avoidance (0-1 points, negative for common patterns)

### Key Management

#### Key Derivation Process
1. User enters passphrase
2. Generate random 32-byte salt (or use existing)
3. Derive 32-byte key using Argon2id with salt and passphrase
4. Use derived key for AES-256-GCM encryption/decryption
5. Securely clear passphrase and derived key from memory

#### Memory Security
- Passphrases stored in libsodium secure heap
- Automatic zeroing on deallocation
- Protected against memory dumps (best effort)
- Locked pages where supported

#### Session Management
- Derived keys kept in secure memory during session
- Regular activity updates to prevent timeout
- Automatic logout on inactivity
- Secure cleanup on exit

### Migration and Recovery

#### Switching to Local-Only Mode
1. Must be authenticated with hardware key
2. Admin approval required
3. Risk acknowledgment mandatory
4. Strong passphrase creation
5. Verification of passphrase
6. Credential generation and encryption
7. Settings update and verification

#### Switching Back to Hardware Key Mode
1. Must be authenticated (any mode)
2. Hardware key must be present and validated
3. Admin approval required
4. Settings update
5. Local credentials securely wiped

#### Recovery Scenarios

##### Forgotten Passphrase
- **No recovery possible** - credentials are cryptographically protected
- **Prevention**: Use memorable passphrases, secure password manager
- **Fallback**: Admin can reset to hardware key mode (data loss)

##### Corrupted Credentials
- Integrity verification detects corruption
- **No recovery possible** - authenticity cannot be verified
- **Prevention**: Regular backups, file system integrity
- **Fallback**: Reset to defaults (configuration loss)

## User Interface

### Warning System

#### Initial Warning
When user selects local-only mode, a comprehensive warning is displayed:
- Security risk explanation
- Specific threats and consequences
- Mitigation requirements
- Alternative recommendations

#### Risk Acknowledgment
User must type exact phrase to acknowledge risks:
```
"I understand the security risks of local-only access"
```

#### Ongoing Reminders
- Warning banner during authentication
- Periodic security reminders
- Audit log notifications

### Passphrase Interface

#### Creation Flow
1. Warning display and acknowledgment
2. Passphrase entry with real-time strength feedback
3. Passphrase confirmation
4. Final risk acknowledgment
5. Credential generation and storage

#### Authentication Flow
1. Passphrase prompt
2. Key derivation (with progress indication)
3. Credential decryption and verification
4. Session establishment

## Comparison with Hardware Key Mode

| Aspect | Hardware Key | Local-Only |
|--------|--------------|------------|
| **Security Level** | High | Medium |
| **Physical Token Required** | Yes | No |
| **Credential Storage** | External device | Local encrypted file |
| **Attack Surface** | Physical theft of key | Device compromise + crypto attack |
| **Convenience** | Lower (key required) | Higher (passphrase only) |
| **Recovery** | Replace key with backup | No recovery if passphrase lost |
| **Admin Approval** | Not required | Required to enable |
| **Recommended Use** | All environments | Trusted environments only |

## Compliance and Legal Considerations

### Data Protection
- Local-only mode may not meet regulatory requirements for some industries
- Consider data residency and sovereignty requirements
- Document security posture for compliance audits

### Legal Risks
- Stored credentials may be subject to legal discovery
- Consider jurisdiction-specific encryption regulations
- Plan for key disclosure orders and legal coercion

### Organizational Policy
- May conflict with organizational security policies
- Requires risk assessment and management approval
- Should be documented in security policies

## Audit and Monitoring

### Events Logged
- Local-only mode enablement/disablement
- Authentication attempts (success/failure)
- Passphrase changes
- Settings modifications
- Admin actions related to local-only mode

### Monitoring Recommendations
- Monitor for repeated authentication failures
- Alert on unauthorized settings changes
- Track admin approval usage
- Review audit logs regularly

### Forensic Considerations
- Encrypted credentials may be recoverable from system
- Memory dumps may contain temporary keys
- Backup files may contain credentials
- System logs may reveal authentication patterns

## Best Practices Summary

### For Users
✅ **DO**:
- Use hardware key mode when possible
- Create strong, unique passphrases
- Enable full disk encryption
- Secure physical device access
- Regularly review security settings

❌ **DON'T**:
- Use common or predictable passphrases
- Share passphrase with others
- Store passphrase in insecure locations
- Use on untrusted or shared devices
- Ignore security warnings

### For Administrators
✅ **DO**:
- Require admin approval for local-only mode
- Document risk acceptance
- Provide security training
- Monitor authentication patterns
- Maintain incident response procedures

❌ **DON'T**:
- Enable by default
- Allow weak passphrases
- Skip risk assessments
- Ignore audit logs
- Bypass approval processes

---

**Remember**: Local-Only Login is a convenience feature that reduces security. Use only when hardware key mode is not feasible and security requirements permit the increased risk.