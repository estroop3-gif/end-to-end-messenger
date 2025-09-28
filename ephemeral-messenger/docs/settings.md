# Settings System Documentation

## Overview

The Ephemeral Messenger includes a comprehensive Settings system that provides secure storage and admin controls for managing all major features. The system is designed with security-first principles and includes multiple layers of protection.

## Architecture

### Core Components

1. **Encrypted Settings Store** (`settings_store.rs`)
   - AES-256-GCM encryption for settings at rest
   - Argon2id key derivation
   - Atomic file operations with integrity checks
   - Versioned schema with migration support

2. **Access Mode Manager** (`access_modes.rs`)
   - Hardware key authentication
   - Local-only login with encrypted credentials
   - Session management and activity tracking
   - Password strength validation

3. **Admin Approval System** (`admin_approvals.rs`)
   - Multi-factor admin approval for dangerous actions
   - Cryptographic audit trail with Ed25519 signatures
   - Risk-based approval workflows
   - Hardware key integration for admin actions

4. **Full Wipe Preparation** (`fullwipe_prep.rs`)
   - Secure wipe plan creation and signing
   - USB bootable wipe utility generation
   - Device validation and safety checks
   - Offline execution model for maximum security

5. **Settings UI** (`SettingsSecurity.tsx`)
   - React-based interface with NordPass-inspired design
   - Progressive disclosure of dangerous features
   - Real-time validation and feedback
   - Accessibility and responsive design

## Settings Categories

### 1. Access Mode Configuration

#### Hardware Key Mode (Default, Recommended)
- **Description**: Requires a removable hardware key or hardware token for access
- **Security Level**: Highest
- **Use Case**: Maximum security environments
- **Requirements**:
  - Compatible USB device with validation keyfile
  - Hardware key must be present during authentication
  - Automatic logout when key is removed (if enabled)

#### Local-Only Login Mode
- **Description**: Stores encrypted login credentials locally
- **Security Level**: Medium (with warnings)
- **Use Case**: Convenience when hardware key is not available
- **Requirements**:
  - Strong passphrase (minimum 20 characters recommended)
  - User acknowledgment of security risks
  - Admin approval required to enable
- **Risks**:
  - Credentials stored on device (encrypted)
  - Vulnerable to device seizure
  - No physical access control
- **Mitigation**:
  - Argon2id key derivation (3 iterations, 64MB memory)
  - Full disk encryption recommended
  - Regular passphrase rotation

### 2. Wipe Policy Configuration

#### Selective Program-Data Wipe
- **Description**: Controlled wipe of application data and user files
- **Scope**: Limited to application data directories only
- **Triggers**:
  - Manual activation with confirmation
  - Panic mode (hardware key removal)
  - Dead man switch (configurable timeout)
- **Safety Features**:
  - Dry-run preview before enabling
  - 30-second countdown with abort option
  - Confirmation phrase requirement
  - Signed policy enforcement
- **Configuration**:
  - Countdown duration (10-300 seconds)
  - Custom confirmation phrase
  - Scope preview and validation

#### Full-Drive Wipe (External Tool)
- **Description**: Complete destruction of storage device data
- **Execution Model**: External bootable utility (NOT executed from main app)
- **Safety Features**:
  - Requires admin approval with hardware key
  - Device must be specified twice for confirmation
  - Refuses to run on system disk
  - Must be booted from external media
  - Cryptographic signature verification
- **Wipe Methods**:
  - **Secure Erase**: Hardware-level secure erase (if supported)
  - **Multi-Pass Random**: 3 passes of cryptographically random data
  - **Single Pass Zero**: Single pass of zeros (faster)
  - **TRIM/Discard**: SSD TRIM commands
  - **Hybrid**: Combination of TRIM + random + zero passes
- **Process**:
  1. Create signed wipe plan in main application
  2. Generate bootable USB with wipe utility
  3. Boot from USB and manually execute wipe
  4. Verify device identity before proceeding
  5. Multiple confirmation steps required

### 3. Messaging & Files Settings

#### Retention Modes
- **Memory Only**: Data exists only in RAM, never written to disk
- **Session Only**: Data cleared when client disconnects
- **Bounded**: Data expires after configurable time limit
- **Explicit Keep**: Data persists until manually deleted

#### Burner Account Settings
- **Default TTL**: 1-24 hours (default: 1 hour)
- **File Sharing**: Enable/disable file attachments for burner accounts
- **Enhanced Quotas**: Rate limits and storage quotas

#### Communication Security
- **Sealed-Sender Routing**: Enforced by default (hides recipient from relay)
- **Cover Traffic**: Optional padding and noise generation
- **Panic Features**:
  - **Panic on Key Removal**: Lock or wipe session buffers
  - **Dead Man Switch**: Auto-wipe after inactivity timeout

### 4. Cryptography Settings

#### Post-Quantum Cryptography
- **Hybrid PQ KEM**: Enable/disable hybrid classical+quantum-resistant encryption
- **Default**: Enabled for future-proofing

#### Document Security
- **Watermark Required**: Mandatory watermarking for .securedoc exports
- **Clipboard Guard**: Prevent clipboard access by other applications
- **Default**: Both enabled for maximum security

### 5. Scripture & Branding Settings

#### ESV Integration
- **License Configuration**: User-provided ESV API key or license file
- **Offline Operation**: No network calls for Scripture access
- **Compliance**: Respects ESV licensing restrictions

#### Prayer Features
- **Prayer Panel**: Enable/disable prayer panel on login screen
- **Daily Verses**: Configure verse source (KJV public domain by default)
- **Prayer Tracking**: Encrypted local storage of prayer data

## Admin Approval System

### Risk Levels

#### Low Risk
- Basic setting changes
- Non-destructive operations
- **Approval**: Simple confirmation
- **Countdown**: 10 seconds

#### Medium Risk
- Settings lock/unlock
- Retention mode changes
- **Approval**: Admin passphrase or hardware key
- **Countdown**: 30 seconds

#### High Risk
- Enable local-only access
- Enable panic features
- **Approval**: Hardware key + confirmation phrase
- **Countdown**: 60 seconds

#### Critical Risk
- Enable full-drive wipe
- Create wipe USB
- **Approval**: Hardware key + typed confirmation + double device verification
- **Countdown**: 120 seconds

### Approval Methods

1. **Hardware Key**: Admin hardware token with cryptographic validation
2. **Admin Passphrase**: Argon2id-protected admin credential
3. **YubiKey Touch**: Hardware security key with touch confirmation (optional)
4. **TOTP**: Time-based one-time password (optional secondary factor)

### Audit Trail

All admin actions are logged with:
- **Cryptographic signatures** (Ed25519)
- **Timestamp and action details**
- **Admin identity verification**
- **Hash chain for integrity**
- **Write to hardware key** (if present)
- **Tamper detection**

## Security Considerations

### Threat Model

#### Protected Against
- **Device seizure** (with hardware key mode)
- **Memory forensics** (using libsodium secure heap)
- **Settings tampering** (cryptographic integrity)
- **Unauthorized admin actions** (multi-factor approval)
- **Accidental data destruction** (multiple confirmation steps)

#### Not Protected Against
- **Hardware attacks on hardware key**
- **Sophisticated memory attacks during operation**
- **Coercion to provide passphrases**
- **Social engineering of admin credentials**

### Best Practices

#### For Users
1. **Use hardware key mode** whenever possible
2. **Enable full disk encryption** on host system
3. **Keep hardware keys physically secure**
4. **Use strong, unique passphrases** if local-only mode is necessary
5. **Regularly review audit logs** for unauthorized changes

#### For Administrators
1. **Maintain separate admin hardware keys**
2. **Use multi-factor authentication** for admin actions
3. **Regularly backup and verify** audit logs
4. **Test wipe procedures** in isolated environments
5. **Maintain emergency access procedures**

## Configuration Examples

### High-Security Environment
```json
{
  "access_mode": "HardKey",
  "wipe_policy": {
    "selective_program_data": true,
    "full_drive_enabled": false,
    "countdown_seconds": 30,
    "require_confirmation_phrase": true
  },
  "messaging": {
    "retention_mode": "MemoryOnly",
    "sealed_sender_enforced": true,
    "panic_on_key_removal": true
  },
  "cryptography": {
    "hybrid_pq_kem": true,
    "watermark_required": true,
    "clipboard_guard": true
  }
}
```

### Convenience Configuration
```json
{
  "access_mode": {
    "LocalOnly": {
      "encrypted_credential": "...",
      "salt": "...",
      "argon2_params": {
        "time_cost": 3,
        "memory_cost": 65536,
        "parallelism": 1
      }
    }
  },
  "wipe_policy": {
    "selective_program_data": false,
    "full_drive_enabled": false
  },
  "messaging": {
    "retention_mode": "SessionOnly",
    "sealed_sender_enforced": true,
    "panic_on_key_removal": false
  }
}
```

## Troubleshooting

### Common Issues

#### Settings Won't Load
- **Cause**: Corrupted settings file or wrong passphrase
- **Solution**:
  1. Check hardware key presence and validation
  2. Verify passphrase if using local-only mode
  3. Check file permissions on settings directory
  4. Delete corrupted settings file to reset to defaults

#### Admin Approval Fails
- **Cause**: Hardware key not detected or invalid admin credentials
- **Solution**:
  1. Verify admin hardware key is properly connected
  2. Check admin passphrase if using passphrase mode
  3. Ensure no other processes are using the hardware key
  4. Review audit logs for failed attempts

#### Wipe USB Creation Fails
- **Cause**: Insufficient permissions, USB device issues, or missing dependencies
- **Solution**:
  1. Run with appropriate privileges (root/administrator)
  2. Verify USB device is not mounted
  3. Check available disk space on USB device
  4. Ensure fullwipe utility is built and accessible

### Recovery Procedures

#### Lost Hardware Key
1. **If local-only mode is available**: Switch to passphrase authentication
2. **If no alternative access**: Settings reset required (data loss)
3. **Prevention**: Maintain backup hardware keys with identical credentials

#### Forgotten Admin Passphrase
1. **If hardware key available**: Use hardware key for admin approval
2. **If no alternative admin method**: Admin override required (may require application reinstall)
3. **Prevention**: Use password manager for admin credentials

#### Corrupted Settings
1. **Backup available**: Restore from encrypted backup
2. **No backup**: Reset to defaults (configuration loss)
3. **Prevention**: Regular encrypted backups of settings directory

## API Reference

### Tauri Commands

```typescript
// Settings management
await invoke('settings_load', { accessMode: 'hardware_key' | 'local_only', passphrase?: string });
await invoke('settings_save', { settings: Settings });

// Authentication
await invoke('authenticate_hardware_key');
await invoke('authenticate_passphrase', { passphrase: string });
await invoke('enable_local_access', { passphrase: string, confirmation: string });

// Admin approval
await invoke('request_admin_approval', { action: string, description: string, justification: string });
await invoke('grant_admin_approval_hardware', { ...approvalParams });

// Wipe operations
await invoke('list_storage_devices');
await invoke('create_wipe_plan', { devicePath: string, wipeMethod: string });
await invoke('create_wipe_usb', { usbDevicePath: string, wipePlan: WipePlan });
```

For complete API documentation, see the TypeScript interfaces in `SettingsSecurity.tsx`.