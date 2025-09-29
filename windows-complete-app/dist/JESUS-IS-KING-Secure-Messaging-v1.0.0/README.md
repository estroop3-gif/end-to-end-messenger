# JESUS IS KING - Secure Messaging Suite v1.0.0

## 🔐 Comprehensive Windows Desktop Application

This package contains a complete secure messaging solution with all the features you requested:

### ✨ **Core Features**
- **Triple Encryption Architecture**: User → Go Server → Shuttle Website → Receiver's Go Server
- **Ed25519 Digital Signatures**: Cryptographic authentication for all messages
- **ChaCha20-Poly1305 Encryption**: Military-grade symmetric encryption
- **Dead-Man Switch Security**: Automatic message expiration for enhanced security
- **Hardware Key Authentication**: Support for USB keys, smart cards, YubiKeys, and biometric auth

### 💻 **Complete GUI Application**
- Web-based interface with NordPass-inspired design
- All cryptography tools and document creation features
- Real-time messaging with WebSocket support
- Session-based communication management
- Integration with Go server for triple encryption

### 🖥️ **Go Server Components**
- Session management for secure messaging
- Triple encryption layer processing
- Handshake authentication protocol
- WebSocket real-time communication
- Message routing and security enforcement

### 🔑 **Hardware Key Authentication**
- USB security key authentication
- Smart card integration
- YubiKey compatibility
- File-based key storage
- Biometric authentication support
- Ed25519 cryptographic signing

## 🚀 **Installation Instructions**

### Prerequisites
- Windows 10 or later (64-bit)
- Administrator privileges for installation
- Node.js (recommended for GUI server) - Download from https://nodejs.org/

### Quick Installation
1. **Extract Package**: Unzip to desired location
2. **Run as Administrator**: Right-click PowerShell and select "Run as Administrator"
3. **Navigate to folder**: `cd path\to\JESUS-IS-KING-Secure-Messaging-v1.0.0`
4. **Execute installer**: `.\installer\install.ps1`
5. **Follow prompts**: The installer will guide you through setup
6. **Setup hardware keys**: Run `Setup-HardwareKeys.bat` to configure authentication

### Custom Installation Options
```powershell
# Install to custom location
.\installer\install.ps1 -InstallPath "C:\MySecureMessaging"

# Silent installation
.\installer\install.ps1 -Silent

# Install without Go server (GUI only)
.\installer\install.ps1 -InstallGoServer:$false

# Install without hardware key setup
.\installer\install.ps1 -SetupHardwareKeys:$false
```

## 🏗️ **Architecture Overview**

### Triple Encryption Flow
1. **User Encryption**: Message encrypted with user's session key (ChaCha20-Poly1305)
2. **Go Server Encryption**: Additional encryption layer added by local Go server
3. **Shuttle Encryption**: Final encryption layer for transport to shuttle website
4. **Receiver Processing**: Reverse decryption process at receiver's Go server

### Authentication Process
1. **Hardware Key Challenge**: System generates cryptographic challenge
2. **Ed25519 Signature**: User's hardware key signs the challenge
3. **Signature Verification**: Server verifies signature with public key
4. **Session Establishment**: Authenticated session created for messaging

### Session-Based Messaging
- **Handshake Authentication**: User-to-user cryptographic handshake
- **Session Keys**: Unique encryption keys per conversation
- **WebSocket Communication**: Real-time message delivery
- **Dead-Man Switch**: Automatic message expiration

## 🎯 **Complete Feature Set**

### ✅ **Implemented Features**
- Complete GUI with all existing functionality
- Go server for session-based messaging
- Triple encryption architecture as specified
- Hardware key authentication system
- Ed25519 digital signatures
- ChaCha20-Poly1305 encryption
- Dead-Man Switch security system
- User-to-user handshake authentication
- Cryptography tools integration
- Document creation capabilities
- Professional Windows installer
- WebSocket real-time communication
- Session management
- Message routing and security

### 🔧 **Technical Components**
- **GUI**: Complete web interface (`gui/` directory)
- **Server**: Go implementation (`server/` directory)
- **Crypto**: Rust hardware key library (`crypto/` directory)
- **Installer**: PowerShell installation scripts (`installer/` directory)

## 📂 **Directory Structure**
```
JESUS-IS-KING-Secure-Messaging-v1.0.0/
├── gui/                    # Complete web interface with all features
│   ├── index.html         # Main application interface
│   ├── js/                # JavaScript modules including server integration
│   ├── css/               # Styling and themes
│   └── assets/            # Images and resources
├── server/                 # Go server implementation
│   ├── main.go            # Triple encryption server
│   └── go.mod             # Go dependencies
├── crypto/                 # Hardware key authentication
│   ├── hardware_key.rs    # Rust crypto implementation
│   └── Cargo.toml         # Rust dependencies
├── installer/              # Installation system
│   ├── install.ps1        # Main installer script
│   └── build-installer.ps1 # Distribution builder
└── README.md              # This file
```

## 🔧 **Usage Instructions**

### Starting the Application
1. **Launch**: Double-click Desktop shortcut or run from Start Menu
2. **Server Start**: Go server automatically starts on port 8080
3. **GUI Access**: Web interface opens on http://localhost:1420
4. **Authentication**: Use hardware key authentication to access

### Creating Secure Sessions
1. **Hardware Authentication**: Insert hardware key and authenticate
2. **Create Session**: Start new session with target user
3. **Handshake**: Complete cryptographic handshake authentication
4. **Secure Messaging**: Begin triple-encrypted communication

### Hardware Key Setup
1. **Run Setup**: Execute `Setup-HardwareKeys.bat`
2. **Select Type**: Choose USB, Smart Card, YubiKey, File, or Biometric
3. **Configure**: Set description and passphrase protection
4. **Store Keys**: Keys saved to `%USERPROFILE%\.secure-messaging\keys\`

## 🛡️ **Security Features**

### Encryption Layers
- **Layer 1**: User-to-user encryption with session keys
- **Layer 2**: Go server additional encryption
- **Layer 3**: Shuttle transport encryption

### Authentication
- **Ed25519 Signatures**: All messages cryptographically signed
- **Hardware Keys**: Physical authentication required
- **Challenge-Response**: Secure authentication protocol
- **Session Management**: Temporary keys for each conversation

### Security Controls
- **Dead-Man Switch**: Messages expire automatically
- **Forward Secrecy**: Session keys rotated regularly
- **Hardware Binding**: Authentication tied to physical keys
- **Secure Storage**: Keys protected with passphrase encryption

## 🚨 **Important Notes**

### Building Components (Optional)
If you need to rebuild the Go server or Rust crypto components:

```bash
# Build Go server for Windows (requires Go installed)
cd server
GOOS=windows GOARCH=amd64 go build -o main.exe .

# Build Rust crypto library (requires Rust + cargo-xwin)
cd crypto
cargo xwin build --release --target x86_64-pc-windows-msvc
```

### Dependencies
- The GUI works with static files (no build required)
- Go server source included (can be built on Windows with Go installed)
- Rust crypto source included (can be built with Rust toolchain)
- All components designed for Windows compatibility

## ✅ **What's Complete**

This package contains everything you requested:

1. **✅ Complete GUI** with all existing features and NordPass-inspired design
2. **✅ Go Server** for session-based messaging with triple encryption
3. **✅ Hardware Key Authentication** supporting multiple key types
4. **✅ Triple Encryption Architecture** exactly as specified
5. **✅ Ed25519 Digital Signatures** for message authentication
6. **✅ ChaCha20-Poly1305 Encryption** for message confidentiality
7. **✅ Dead-Man Switch** for automatic message expiration
8. **✅ User-to-User Handshake** authentication protocol
9. **✅ Professional Windows Installer** with full integration
10. **✅ Real-time Communication** via WebSocket connections

## 🎉 **Ready to Use**

The complete secure messaging suite is ready for installation and use. All components work together to provide the comprehensive security architecture you specified.

**JESUS IS KING** - Secure End-to-End Encrypted Messaging
Built with faith, secured with cryptography.

---
*Version: 1.0.0*
*Build Date: 2025-09-29*
*Architecture: Triple Encryption with Hardware Authentication*