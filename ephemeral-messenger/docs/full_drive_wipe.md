# Full Drive Wipe Documentation

## Overview

The Full Drive Wipe system provides a secure method for completely destroying all data on a storage device. This is implemented as an **external, offline tool** that runs independently from the main application to maximize security and prevent accidental execution.

🚨 **CRITICAL WARNING**: Full drive wipe is an irreversible process that will permanently destroy ALL data on the target device. Use with extreme caution.

## Security Model

### Offline Execution Model
The full drive wipe is intentionally designed as a **separate, external tool** that:
- Cannot be executed from the main application
- Requires manual, offline execution
- Must be run from external bootable media
- Includes multiple safety checks and confirmations

### Why External Tool?
1. **Prevents Accidental Execution**: Main app cannot accidentally trigger full wipe
2. **Requires Physical Access**: Operator must be physically present
3. **Maximizes Safety**: Multiple confirmation steps and safety checks
4. **Audit Trail**: Clear separation between planning and execution
5. **Legal Protection**: Clear intent and manual execution

## Process Overview

### Phase 1: Planning (Main Application)
1. Admin approval with hardware key required
2. Storage device selection and verification
3. Wipe method selection
4. Cryptographically signed wipe plan creation
5. Bootable USB creation with wipe utility

### Phase 2: Execution (External Tool)
1. Boot from wipe USB
2. Load and verify signed wipe plan
3. Device identity verification
4. Multiple safety confirmations
5. Wipe execution with progress monitoring
6. Completion verification and audit logging

## Wipe Methods

### 1. Hardware Secure Erase
- **Description**: Uses ATA/NVMe secure erase commands
- **Speed**: Fastest (seconds to minutes)
- **Security**: Hardware-dependent, generally excellent
- **Compatibility**: Modern SSDs and some HDDs
- **Implementation**:
  - Sets security password with `hdparm`
  - Issues secure erase command
  - Verifies completion
- **Notes**: May not work on all devices; falls back to multi-pass random

### 2. Multi-Pass Random
- **Description**: Multiple passes of cryptographically random data
- **Speed**: Slowest (hours for large drives)
- **Security**: Excellent against all recovery methods
- **Compatibility**: All storage devices
- **Implementation**:
  - 3 passes of random data from libsodium
  - Full device overwrite each pass
  - Progress monitoring and verification
- **Notes**: Default recommended method for maximum security

### 3. Single Pass Zero
- **Description**: Single pass of zeros across entire device
- **Speed**: Fast (minutes to hours)
- **Security**: Good against casual recovery
- **Compatibility**: All storage devices
- **Implementation**:
  - Writes zeros to every sector
  - Fast and simple
  - Adequate for most scenarios
- **Notes**: May leave traces recoverable by advanced techniques

### 4. TRIM/Discard
- **Description**: Uses SSD TRIM commands to mark blocks as unused
- **Speed**: Very fast (seconds)
- **Security**: Hardware-dependent
- **Compatibility**: SSDs with TRIM support
- **Implementation**:
  - Issues `blkdiscard` command
  - Relies on SSD firmware implementation
  - May not actually overwrite data
- **Notes**: Not recommended as sole method; good for initial pass

### 5. Hybrid Method
- **Description**: Combination of multiple methods
- **Speed**: Medium (optimized balance)
- **Security**: Excellent
- **Compatibility**: All storage devices
- **Implementation**:
  1. TRIM/discard (if supported)
  2. Single pass random data
  3. Single pass zeros
- **Notes**: Recommended for best balance of speed and security

## Safety Mechanisms

### Pre-Execution Safety Checks

#### 1. Boot Environment Verification
```rust
fn is_booted_from_external() -> Result<bool> {
    // Check if root filesystem is on target device
    // Verify running from removable media
    // Prevent execution from internal drives
}
```

#### 2. Device Identity Verification
- Serial number matching
- Size verification (within 1% tolerance)
- Model verification
- WWN/UUID checking where available

#### 3. System Disk Protection
```rust
fn is_root_device(device_path: &str) -> Result<bool> {
    // Check if device contains root filesystem
    // Verify mount points
    // Prevent system disk selection
}
```

#### 4. Mount Point Verification
- Ensure target device is not mounted
- Check for active file systems
- Verify no processes using device

### Execution Safety Checks

#### 1. Double Device Confirmation
- Device path must be specified twice
- Both specifications must match exactly
- Interactive verification prompts

#### 2. Cryptographic Plan Verification
- Ed25519 signature verification
- Plan integrity validation
- Approval audit ID verification

#### 3. Interactive Confirmations
```
⚠️  FINAL WARNING ⚠️
This will PERMANENTLY DESTROY ALL DATA on device: /dev/sdX
Wipe method: MultiPassRandom
This action CANNOT BE UNDONE!

Are you absolutely sure you want to proceed? [y/N]: n

Type exactly: 'I understand this will destroy all data'
> I understand this will destroy all data

⏳ Starting wipe operation in 10 seconds...
Press Ctrl+C now to cancel!
⏱️  10 seconds remaining...
```

#### 4. Countdown with Abort
- 10-second countdown before execution
- Ctrl+C abort at any time
- Clear visual indicators

## Wipe Plan Structure

### Plan Creation
```rust
struct WipePlan {
    id: String,                    // UUID for tracking
    created_at: DateTime<Utc>,     // Creation timestamp
    target_device: TargetDevice,   // Device details
    wipe_method: WipeMethod,       // Selected method
    verification_required: bool,   // Always true
    admin_signature: Vec<u8>,      // Ed25519 signature
    approval_audit_id: String,     // Admin approval reference
}

struct TargetDevice {
    device_path: String,           // e.g., "/dev/sdb"
    device_id: String,             // Device identifier
    serial_number: Option<String>, // Hardware serial
    model: Option<String>,         // Device model
    size_bytes: u64,              // Total size
    verified_twice: bool,         // UI confirmation flag
}
```

### Cryptographic Signing
1. Admin creates wipe plan
2. Plan serialized to canonical JSON
3. Signed with Ed25519 private key
4. Signature attached to plan
5. Plan written to wipe USB

### Verification Process
1. Load plan from USB
2. Deserialize plan data
3. Verify Ed25519 signature
4. Check approval audit ID
5. Validate device identity
6. Proceed only if all checks pass

## USB Creation Process

### Bootable USB Structure
```
USB Device:
├── fullwipe_cli                 # Wipe utility executable
├── wipe_plan.json              # Signed wipe plan
├── README.txt                  # Instructions and warnings
├── boot/
│   └── grub/
│       └── grub.cfg            # Bootloader configuration
└── verification_tools/         # Optional verification utilities
```

### Bootloader Configuration
```bash
# GRUB configuration
set timeout=10
set default=0

menuentry "Secure Drive Wipe Utility" {
    echo "Loading secure drive wipe utility..."
    echo "WARNING: This tool can permanently destroy data!"
    echo "Press any key to continue..."
    read
    linux /fullwipe_cli --interactive
}

menuentry "Exit to BIOS/UEFI" {
    exit
}
```

### Creation Process
1. Admin selects target device
2. Wipe method selection
3. Device verification (twice)
4. Admin approval with hardware key
5. Signed wipe plan generation
6. USB device formatting
7. File copying and bootloader installation
8. Verification of USB contents

## Command Line Interface

### Available Commands

#### List Devices
```bash
sudo ./fullwipe_cli list
```
Shows all available storage devices with details.

#### Dry Run
```bash
sudo ./fullwipe_cli dry-run --plan wipe_plan.json
```
Simulates wipe operation without actually writing data.

#### Execute Wipe
```bash
sudo ./fullwipe_cli execute \
    --plan wipe_plan.json \
    --device /dev/sdb \
    --device-confirm /dev/sdb
```
Executes the wipe operation with double device confirmation.

#### Interactive Mode
```bash
sudo ./fullwipe_cli interactive
```
Guided interface with menu-driven operation.

#### Verify Plan
```bash
sudo ./fullwipe_cli verify --plan wipe_plan.json
```
Verifies plan signature and integrity without execution.

### Command Line Safety
- Requires root privileges
- Device must be specified twice for safety
- Plan file must be cryptographically signed
- Multiple confirmation prompts

## Execution Environment

### Hardware Requirements
- x86_64 or ARM64 architecture
- Minimum 512MB RAM
- USB boot capability
- Target storage device

### Software Requirements
- Linux-based bootable environment
- Required utilities:
  - `lsblk` (device enumeration)
  - `findmnt` (mount checking)
  - `hdparm` (secure erase)
  - `blkdiscard` (TRIM support)
  - Standard POSIX tools

### Boot Process
1. BIOS/UEFI boot from USB
2. Linux kernel loads
3. Minimal userspace environment
4. Wipe utility auto-starts or manual execution
5. Network interfaces disabled (air-gapped execution)

## Progress Monitoring

### Real-Time Progress
```
🎲 Starting multi-pass random data wipe...
🔄 Pass 1/3: Writing random data...
█████████████████████████████████████████ 100% | 500.0 GB/500.0 GB | ETA: 00:00
✅ Pass 1 completed
🔄 Pass 2/3: Writing random data...
████████████████████████████▌           67% | 335.0 GB/500.0 GB | ETA: 00:15:32
```

### Progress Information
- Current pass number
- Percentage complete
- Data written vs. total
- Estimated time remaining
- Visual progress bar
- Real-time speed indication

### Completion Verification
- Verify all sectors written
- Check for I/O errors
- Confirm wipe method completion
- Generate completion audit entry

## Audit and Logging

### Completion Audit Entry
```json
{
  "wipe_plan_id": "uuid-here",
  "completed_at": "2024-01-01T12:00:00Z",
  "method_used": "MultiPassRandom",
  "device_path": "/dev/sdb",
  "device_serial": "ABC123",
  "success": true,
  "error_message": null,
  "passes_completed": 3,
  "bytes_written": 500000000000,
  "execution_time_seconds": 7200,
  "verification_passed": true
}
```

### Audit Storage
1. **USB Device**: Written to `wipe_audit.jsonl` on USB
2. **Removable Media**: Copied to any detected removable storage
3. **Network Upload**: Optional (if network configured)
4. **Print Output**: Can be printed for physical records

### Chain of Custody
- Plan creation logged in main application
- USB creation logged with checksums
- Execution logged with device verification
- Completion logged with verification results

## Recovery and Verification

### Data Recovery Prevention
After successful wipe:
- **Casual Recovery**: Impossible
- **Software Recovery**: Extremely difficult
- **Professional Recovery**: Very expensive, may be impossible
- **Forensic Recovery**: Unlikely with multi-pass random

### Post-Wipe Verification
Optional verification tools can:
- Sample random sectors for data patterns
- Verify no recoverable file signatures
- Check for magnetic remnants (HDDs)
- Generate verification report

### Verification Methods
1. **Pattern Detection**: Look for known file signatures
2. **Entropy Analysis**: Verify randomness of data
3. **Sector Sampling**: Check representative sectors
4. **Magnetic Analysis**: Advanced HDD verification

## Error Handling

### Common Errors

#### Hardware Errors
- **Bad Sectors**: Logged and skipped where possible
- **Device Failures**: Immediate abort with error report
- **Controller Issues**: Retry with different methods

#### Software Errors
- **Permission Denied**: Verify root privileges and device access
- **Device Busy**: Ensure device not mounted or in use
- **Insufficient Space**: N/A for wipe operations

#### Plan Errors
- **Invalid Signature**: Abort - possible tampering
- **Device Mismatch**: Abort - wrong device selected
- **Expired Plan**: Abort - plan too old (configurable)

### Error Recovery
1. **Immediate Abort**: Stop all operations
2. **Error Logging**: Record error details
3. **Safe State**: Leave device in known state
4. **User Notification**: Clear error explanation
5. **Audit Entry**: Log failed attempt

## Legal and Compliance

### Legal Considerations
- **Regulatory Compliance**: May be required for GDPR, HIPAA, etc.
- **Chain of Custody**: Maintain audit trail
- **Legal Discovery**: May be subject to legal holds
- **Export Controls**: Cryptographic software restrictions

### Documentation Requirements
- **Risk Assessment**: Document security requirements
- **Approval Process**: Admin approval and justification
- **Execution Records**: Complete audit trail
- **Verification Results**: Proof of data destruction

### Industry Standards
- **NIST SP 800-88**: Media sanitization guidelines
- **DoD 5220.22-M**: Department of Defense standard
- **Common Criteria**: Security evaluation criteria
- **FIPS 140-2**: Cryptographic module standards

## Troubleshooting

### Pre-Boot Issues
- **USB Won't Boot**: Check BIOS/UEFI settings, secure boot
- **Missing Bootloader**: Recreate USB with bootloader
- **Hardware Compatibility**: Try different boot modes (UEFI/Legacy)

### Runtime Issues
- **Device Not Detected**: Check connections, try different USB ports
- **Permission Errors**: Ensure booted as root user
- **Missing Dependencies**: Use statically linked binary

### Execution Issues
- **Slow Performance**: Normal for large drives, check progress
- **I/O Errors**: May indicate failing drive, continue if possible
- **Unexpected Abort**: Check audit logs for error details

### Post-Execution Issues
- **Verification Failed**: Re-run wipe operation
- **Audit Log Missing**: Check all removable media
- **Plan Signature Invalid**: Regenerate wipe plan

## Best Practices

### Planning Phase
✅ **DO**:
- Test wipe procedure on non-critical devices first
- Verify device identity multiple times
- Document business justification
- Obtain proper approvals
- Create multiple USB copies

❌ **DON'T**:
- Rush the verification process
- Skip safety confirmations
- Use on unknown devices
- Ignore error messages
- Execute without backups (if data needed)

### Execution Phase
✅ **DO**:
- Boot from external USB only
- Verify device identity before proceeding
- Monitor progress actively
- Save audit logs to multiple locations
- Document execution process

❌ **DON'T**:
- Execute on system drives
- Skip confirmation prompts
- Leave unattended during execution
- Ignore safety warnings
- Rush the process

### Post-Execution
✅ **DO**:
- Verify completion status
- Save audit records securely
- Document verification results
- Securely destroy wipe USB if no longer needed
- Update asset management systems

❌ **DON'T**:
- Assume wipe succeeded without verification
- Leave audit logs unprotected
- Reuse devices without proper verification
- Skip documentation requirements
- Ignore failed verification results

---

**Remember**: Full drive wipe is irreversible. Always verify device identity, obtain proper approvals, and maintain complete audit trails. When in doubt, consult security professionals before proceeding.