# JESUS IS KING - Secure Messaging Suite v1.0.3

## Comprehensive Windows Desktop Application

This package contains a complete secure messaging solution with:

### 🔐 Core Features
- **Triple Encryption Architecture**: Signal Protocol + ChaCha20-Poly1305 + AES-256-GCM
- **Certificate Pinning**: Protection against man-in-the-middle attacks
- **Request Signing**: Ed25519 digital signatures for API authentication
- **Mutual TLS Authentication**: Client certificate-based security
- **Intrusion Detection**: Real-time threat monitoring and response
- **Security Monitoring**: Comprehensive client and server-side monitoring

### 💻 GUI Application
- Complete web-based interface with modern design
- All cryptography tools and document creation features
- Real-time messaging with WebSocket support
- Session-based communication management

### 🖥️ Server Components
- Local Go relay for client connections
- Shuttle service for message queuing
- Triple encryption layer processing
- Redis-backed persistent storage

### 🔒 Enhanced Security Features
- Certificate pinning with SPKI validation
- HMAC-SHA256 and Ed25519 request signing
- Mutual TLS with client certificates
- Real-time intrusion detection (SQL injection, XSS, brute force)
- Security event monitoring and alerting

## Installation Instructions

### Prerequisites
- Windows 10 or later (64-bit)
- Python (recommended for GUI server)
- Optional: Node.js for alternative GUI server

### Quick Installation (Recommended)
1. **Double-click INSTALL.bat**: This uses the most compatible batch installer
2. **Follow prompts**: The installer will guide you through the setup process
3. **Alternative installers**: Use installer\ folder for other options

### Alternative Installation Methods
- **INSTALL.bat** (Recommended): Maximum compatibility, no PowerShell issues
- **installer\install-simple.ps1**: Clean PowerShell script (requires PowerShell)
- **installer\install.ps1**: Original installer (may have syntax issues)
- **installer\download-latest.bat**: Download latest version from GitHub

### Post-Installation Setup
1. **Start Application**: Launch from Desktop shortcut or Start Menu
2. **Configure Security**: Review certificate pinning and authentication settings
3. **Create Sessions**: Use the GUI to initiate secure messaging sessions

## Architecture Overview

### Triple Encryption Flow
```
Client (Tauri) ↔ Local Relay (Go) ↔ Shuttle Service (Go) ↔ Local Relay (Go) ↔ Client (Tauri)
     ↓                ↓                     ↓                    ↓                ↓
Layer C          Layer B/C            Redis Queue          Layer B/C          Layer C
Layer B          IDS Monitor         Rate Limiting        IDS Monitor        Layer B
Layer A          mTLS Auth           API Keys            mTLS Auth          Layer A
Security         Cert Pinning        Intrusion Detection  Cert Pinning       Security
Monitor          Request Signing     Alert Management     Request Signing    Monitor
```

### Security Layers
1. **Layer A (Inner)**: Signal Protocol Double Ratchet for end-to-end encryption
2. **Layer B (Middle)**: ChaCha20-Poly1305 for inter-relay transport security
3. **Layer C (Outer)**: AES-256-GCM for local client-relay encryption

### Enhanced Security Features
- **Certificate Pinning**: SHA-256 SPKI validation prevents MITM attacks
- **Request Signing**: HMAC-SHA256 and Ed25519 digital signatures
- **Mutual TLS**: Client certificate authentication
- **Intrusion Detection**: Real-time monitoring for attacks and anomalies
- **Security Monitoring**: Comprehensive event tracking and alerting

## Directory Structure
```
JESUS-IS-KING-Secure-Messaging-v1.0.3/
├── INSTALL.bat                 # Main installer (recommended)
├── installer/                  # Alternative installers
│   ├── install-batch.bat      # Batch installer (same as INSTALL.bat)
│   ├── install-simple.ps1     # Clean PowerShell installer
│   ├── install.ps1            # Original installer
│   └── download-latest.bat    # Download latest from GitHub
├── gui/                       # Complete web interface
├── server/                    # Go server implementation
└── README.md                  # This file
```

## Usage

### Starting the Application
- **Desktop Shortcut**: Double-click "JESUS IS KING Messenger"
- **Start Menu**: Search for "JESUS IS KING"
- **Command Line**: Run launcher from installation directory

### Security Configuration
The application includes comprehensive security features:
- Certificate pinning for server validation
- Request signing for API authentication
- Intrusion detection for threat monitoring
- Security event logging and alerting

## Troubleshooting

### Common Issues
- **Installation Errors**: Try the batch installer (INSTALL.bat) for maximum compatibility
- **PowerShell Syntax Errors**: Use install-batch.bat instead of PowerShell installers
- **Port Conflicts**: GUI (1420) or Server (8080) ports in use
- **Python Missing**: Install Python for GUI server functionality

### Installation Options
If you encounter issues with one installer:
1. Try **INSTALL.bat** (most compatible)
2. Try **installer\install-simple.ps1** (clean PowerShell)
3. Use **installer\download-latest.bat** to get newest version

### Log Files
- Application logs in installation directory
- Check Windows Event Viewer for system errors
- Security events logged in security.log

## Security Considerations

### Best Practices
- Keep certificate pins updated
- Monitor security alerts and events
- Regularly rotate cryptographic keys
- Use strong authentication methods
- Keep software updated

### Threat Protection
This application protects against:
- Network surveillance and interception
- Man-in-the-middle attacks
- Message tampering and forgery
- SQL injection and XSS attacks
- Brute force and scanning attacks
- Unauthorized access attempts

## Updates and Support

### Getting Updates
- Use **installer\download-latest.bat** to get the newest version
- Check GitHub repository for latest releases
- Monitor security advisories for critical updates

### Version History
- **v1.0.3**: Fixed installer compatibility, added alternative installers
- **v1.0.2**: Enhanced security features, intrusion detection
- **v1.0.1**: Improved UI and stability
- **v1.0.0**: Initial release

---

**JESUS IS KING** - Secure End-to-End Encrypted Messaging
Built with faith, secured with enterprise-grade cryptography.

Version: 1.0.3
Build Date: 2024-01-15
Repository: https://github.com/estroop3-gif/end-to-end-messenger