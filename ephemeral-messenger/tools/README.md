# Ephemeral Messenger Key Management Tools

This directory contains the key generation and management tools for the hardware key enforcement system.

## 🔧 Tools Overview

### 1. `keygen` - CLI Key Generation Tool
- **Purpose**: Command-line tool for generating secure keyfiles
- **Features**:
  - Ed25519 + X25519 + Age key generation
  - QR code generation for public key sharing
  - SSH key import support
  - Device binding and validity configuration
  - Automatic removable media detection

### 2. `keygen-gui` - GUI Key Generation Tool
- **Purpose**: User-friendly graphical interface for key generation
- **Features**:
  - Interactive device selection
  - Visual progress indicators
  - Real-time validation
  - Integrated log output
  - Cross-platform compatibility (Linux, Windows, macOS)

### 3. `yubikey-provision` - YubiKey Provisioning Tool
- **Purpose**: Provision YubiKeys with generated keyfiles
- **Features**:
  - PIV applet support (slots 9a, 9c, 9d, 9e)
  - On-card key generation
  - Certificate management
  - Touch and PIN policy configuration
  - Backup and recovery operations

## 🚀 Quick Start

### Installation

```bash
# Install dependencies
make deps

# Build all tools
make all

# Install to system PATH (optional)
sudo make install
```

### Basic Usage

#### Generate a new keyfile:
```bash
./bin/keygen --interactive
```

#### Generate with specific parameters:
```bash
./bin/keygen \
  --user-id "123e4567-e89b-12d3-a456-426614174000" \
  --validity 365 \
  --output "/media/usb1" \
  --qr
```

#### Launch GUI:
```bash
./bin/keygen-gui
```

#### Provision YubiKey:
```bash
./bin/yubikey-provision \
  --keyfile "/media/usb1/KEYSTORE/secure_key.json" \
  --slot 9a \
  --interactive
```

## 📁 Directory Structure

```
tools/
├── keygen/                  # CLI key generation tool
│   ├── main.go             # Main CLI application
│   └── go.mod              # Go dependencies
├── keygen-gui/             # GUI key generation tool
│   ├── src/main.rs         # Rust GUI application
│   └── Cargo.toml          # Rust dependencies
├── yubikey-provision/      # YubiKey provisioning tool
│   ├── main.go             # YubiKey PIV interface
│   └── go.mod              # Go dependencies
├── bin/                    # Built binaries (created after build)
├── Makefile               # Build system
└── README.md              # This file
```

## 🔒 Security Features

### Key Generation
- **Ed25519**: Digital signatures and identity verification
- **X25519**: Elliptic curve key exchange for encryption
- **Age**: Modern file encryption compatibility
- **Cryptographic signing**: All keyfiles are self-signed with Ed25519
- **Tamper detection**: Signature verification prevents modification

### Hardware Security
- **Device binding**: Keys can be tied to specific device UUIDs
- **YubiKey integration**: Secure hardware key storage
- **Touch policies**: Require physical touch for key operations
- **PIN protection**: Multiple layers of authentication

### Operational Security
- **No local caching**: Keys written directly to removable media
- **Secure cleanup**: Memory cleared after key generation
- **Backup creation**: Automatic backup before overwriting
- **Audit logging**: All operations logged for security review

## 🛠️ Development

### Build Requirements

**For Go tools:**
- Go 1.21 or later
- Dependencies: `filippo.io/age`, `github.com/google/uuid`, `github.com/skip2/go-qrcode`

**For GUI tool:**
- Rust 1.70 or later
- Dependencies: `eframe`, `egui`, `chrono`

**For YubiKey tool:**
- Go 1.21 or later
- libpcsclite-dev (Linux) or PC/SC framework
- Dependencies: `github.com/go-piv/piv-go`

### Build Commands

```bash
# Development setup
make dev-setup

# Build individual tools
make keygen
make keygen-gui
make yubikey-provision

# Run tests
make test

# Clean build artifacts
make clean
```

### Adding New Features

1. **CLI tool**: Modify `keygen/main.go`
2. **GUI tool**: Modify `keygen-gui/src/main.rs`
3. **YubiKey tool**: Modify `yubikey-provision/main.go`
4. **Build system**: Update `Makefile` as needed

## 🔍 Security Considerations

### Threat Model
- **Physical access**: Tools assume physical security of generation environment
- **Side channels**: No protection against sophisticated side-channel attacks
- **Hardware tampering**: YubiKey provides tamper-evident hardware security
- **Software integrity**: Verify tool signatures before use

### Best Practices
1. **Air-gapped generation**: Generate keys on offline systems when possible
2. **Secure disposal**: Securely wipe generation systems after use
3. **Multiple copies**: Create redundant copies of critical keyfiles
4. **Regular rotation**: Rotate keys according to your security policy
5. **Hardware verification**: Verify YubiKey authenticity before provisioning

### Limitations
- **Private key exposure**: CLI tools handle private keys in memory
- **Platform dependencies**: Some features require specific OS capabilities
- **Hardware requirements**: YubiKey features require compatible hardware
- **Recovery complexity**: Lost hardware keys require secure recovery procedures

## 📚 Additional Resources

- [YubiKey PIV Documentation](https://developers.yubico.com/PIV/)
- [Age Encryption Specification](https://age-encryption.org/)
- [Ed25519 Signature Algorithm](https://tools.ietf.org/html/rfc8032)
- [Hardware Security Module Best Practices](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)

## 🐛 Troubleshooting

### Common Issues

**"No removable devices detected"**
- Check USB device permissions
- Ensure device is properly mounted
- Try manual path specification

**"YubiKey not found"**
- Install PC/SC daemon (Linux: `pcscd`)
- Check USB permissions
- Verify YubiKey is PIV-enabled

**"Permission denied writing keyfile"**
- Check device mount permissions
- Ensure device is not read-only
- Try running with elevated privileges

**"Age identity generation failed"**
- Check available entropy
- Install `rng-tools` if needed
- Verify Go crypto dependencies

### Debug Mode

Enable verbose logging:
```bash
./bin/keygen --interactive --verbose
RUST_LOG=debug ./bin/keygen-gui
./bin/yubikey-provision --interactive --verbose
```

## 🤝 Contributing

1. Follow existing code style and patterns
2. Add tests for new functionality
3. Update documentation for changes
4. Consider security implications of modifications
5. Test on multiple platforms when possible

## 📄 License

This software is part of the Ephemeral Messenger project and follows the same licensing terms as the main project.