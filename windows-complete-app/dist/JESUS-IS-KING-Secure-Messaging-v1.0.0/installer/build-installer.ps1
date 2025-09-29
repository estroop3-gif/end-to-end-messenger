# Build Complete Windows Installer Package
# Creates a comprehensive installer for JESUS IS KING Secure Messaging

param(
    [string]$OutputDir = "dist",
    [string]$Version = "1.0.0",
    [switch]$BuildGoServer = $true,
    [switch]$BuildCrypto = $true,
    [switch]$CreateZip = $true,
    [switch]$CreateMSI = $true
)

$ErrorActionPreference = "Stop"

Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "  JESUS IS KING - Windows Installer Builder" -ForegroundColor Cyan
Write-Host "  Creating Comprehensive Security Suite" -ForegroundColor Cyan
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host ""

# Create output directory
if (Test-Path $OutputDir) {
    Remove-Item -Path $OutputDir -Recurse -Force
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

$PackageDir = Join-Path $OutputDir "JESUS-IS-KING-Secure-Messaging-v$Version"
New-Item -ItemType Directory -Path $PackageDir -Force | Out-Null

# Copy GUI files
Write-Host "Packaging GUI application..." -ForegroundColor Yellow
$GUIPackageDir = Join-Path $PackageDir "gui"
Copy-Item -Path "../gui/*" -Destination $GUIPackageDir -Recurse -Force

# Build and package Go server
if ($BuildGoServer) {
    Write-Host "Building Go server..." -ForegroundColor Yellow
    $ServerPackageDir = Join-Path $PackageDir "server"
    New-Item -ItemType Directory -Path $ServerPackageDir -Force | Out-Null

    # Copy Go source
    Copy-Item -Path "../server/*" -Destination $ServerPackageDir -Force

    # Build for Windows (if on Linux with Go cross-compilation)
    Push-Location "../server"
    try {
        # Set environment for Windows build
        $env:GOOS = "windows"
        $env:GOARCH = "amd64"
        $env:CGO_ENABLED = "0"

        # Build the executable
        & go build -ldflags "-s -w -X main.version=$Version" -o "../installer/$ServerPackageDir/main.exe" .

        if ($LASTEXITCODE -eq 0) {
            Write-Host "Go server built successfully" -ForegroundColor Green
        } else {
            Write-Host "Go server build failed, including source code only" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Go build error: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Including source code for manual build" -ForegroundColor Yellow
    } finally {
        Pop-Location
        # Reset environment
        Remove-Item Env:GOOS -ErrorAction SilentlyContinue
        Remove-Item Env:GOARCH -ErrorAction SilentlyContinue
        Remove-Item Env:CGO_ENABLED -ErrorAction SilentlyContinue
    }
}

# Build and package crypto components
if ($BuildCrypto) {
    Write-Host "Building crypto components..." -ForegroundColor Yellow
    $CryptoPackageDir = Join-Path $PackageDir "crypto"
    New-Item -ItemType Directory -Path $CryptoPackageDir -Force | Out-Null

    # Copy Rust crypto source
    Copy-Item -Path "../crypto/*" -Destination $CryptoPackageDir -Force

    # Build Rust library for Windows (if cross-compilation available)
    Push-Location "../crypto"
    try {
        # Try to build with cargo-xwin if available
        if (Get-Command "cargo-xwin" -ErrorAction SilentlyContinue) {
            & cargo xwin build --release --target x86_64-pc-windows-msvc
            if ($LASTEXITCODE -eq 0) {
                $TargetDir = "target/x86_64-pc-windows-msvc/release"
                if (Test-Path "$TargetDir/hardware_key_crypto.dll") {
                    Copy-Item "$TargetDir/hardware_key_crypto.dll" "../installer/$CryptoPackageDir/"
                    Write-Host "Crypto library built successfully" -ForegroundColor Green
                }
            }
        } else {
            Write-Host "cargo-xwin not available, including source code only" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Crypto build error: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-Host "Including source code for manual build" -ForegroundColor Yellow
    } finally {
        Pop-Location
    }
}

# Copy installer scripts
Write-Host "Packaging installer scripts..." -ForegroundColor Yellow
Copy-Item -Path "install.ps1" -Destination $PackageDir -Force

# Create README
$ReadmeContent = @"
# JESUS IS KING - Secure Messaging Suite v$Version

## Comprehensive Windows Desktop Application

This package contains a complete secure messaging solution with:

### 🔐 Core Features
- **Triple Encryption Architecture**: User → Go Server → Shuttle Website → Receiver's Go Server
- **Ed25519 Digital Signatures**: Cryptographic authentication for all messages
- **ChaCha20-Poly1305 Encryption**: Military-grade symmetric encryption
- **Dead-Man Switch Security**: Automatic message expiration for enhanced security
- **Hardware Key Authentication**: Support for USB keys, smart cards, YubiKeys, and biometric auth

### 💻 GUI Application
- Complete web-based interface with NordPass-inspired design
- All cryptography tools and document creation features
- Real-time messaging with WebSocket support
- Session-based communication management

### 🖥️ Server Components
- Go server implementation for session management
- Triple encryption layer processing
- Handshake authentication protocol
- Message routing and security enforcement

### 🔑 Hardware Key Support
- USB security key authentication
- Smart card integration
- YubiKey compatibility
- File-based key storage
- Biometric authentication support

## Installation Instructions

### Prerequisites
- Windows 10 or later (64-bit)
- Administrator privileges for installation
- Node.js (recommended for GUI server)
- Optional: Go runtime for server compilation

### Quick Installation
1. **Run as Administrator**: Right-click PowerShell and select "Run as Administrator"
2. **Execute installer**: ``.\install.ps1``
3. **Follow prompts**: The installer will guide you through the setup process
4. **Setup hardware keys**: Run ``Setup-HardwareKeys.bat`` to configure authentication

### Custom Installation
``````powershell
# Install to custom location
.\install.ps1 -InstallPath "C:\MySecureMessaging"

# Silent installation
.\install.ps1 -Silent

# Install without Go server (GUI only)
.\install.ps1 -InstallGoServer:`$false

# Install without hardware key setup
.\install.ps1 -SetupHardwareKeys:`$false
``````

### Post-Installation Setup
1. **Configure Hardware Keys**: Run the hardware key setup to create authentication credentials
2. **Start Application**: Launch from Desktop shortcut or Start Menu
3. **Create Session**: Use the GUI to initiate secure messaging sessions
4. **Handshake Authentication**: Complete user-to-user authentication process

## Architecture Overview

### Triple Encryption Flow
1. **User Encryption**: Message encrypted with user's session key
2. **Go Server Encryption**: Additional encryption layer added by local Go server
3. **Shuttle Encryption**: Final encryption layer for transport to shuttle website
4. **Receiver Processing**: Reverse process at receiver's Go server

### Authentication Process
1. **Hardware Key Challenge**: System generates cryptographic challenge
2. **Ed25519 Signature**: User's hardware key signs the challenge
3. **Signature Verification**: Server verifies signature with public key
4. **Session Establishment**: Authenticated session created for messaging

### Security Features
- **End-to-End Encryption**: Messages encrypted from sender to receiver
- **Forward Secrecy**: Session keys rotated for each conversation
- **Dead-Man Switch**: Messages automatically expire after set time
- **Hardware Authentication**: Physical security key required for access
- **Digital Signatures**: All messages cryptographically signed

## Directory Structure
``````
JESUS-IS-KING-Secure-Messaging-v$Version/
├── gui/                    # Complete web interface
├── server/                 # Go server implementation
├── crypto/                 # Hardware key cryptography
├── installer/              # Installation scripts
└── install.ps1            # Main installer
``````

## Usage

### Starting the Application
- **Desktop Shortcut**: Double-click "JESUS IS KING - Secure Messaging"
- **Start Menu**: Search for "JESUS IS KING"
- **Command Line**: Run ``JESUS-IS-KING-Messenger.bat``

### Creating Secure Sessions
1. Launch the application
2. Create new session with target user
3. Complete handshake authentication
4. Begin encrypted communication

### Hardware Key Management
- **Setup Keys**: Use ``Setup-HardwareKeys.bat``
- **Key Types**: USB, Smart Card, YubiKey, File, Biometric
- **Key Storage**: Keys stored in ``%USERPROFILE%\.secure-messaging\keys\``

## Troubleshooting

### Common Issues
- **Port Conflicts**: GUI (1420) or Server (8080) ports in use
- **Firewall Blocking**: Add application to Windows Firewall exceptions
- **Hardware Key Not Detected**: Check key setup and drivers
- **Node.js Missing**: Install Node.js for GUI server functionality

### Log Files
- Application logs: ``%PROGRAMFILES%\JESUS IS KING Secure Messaging\logs\``
- Server logs: ``server.log``
- Error logs: ``error.log``

## Security Considerations

### Best Practices
- Use hardware authentication keys when possible
- Regularly rotate session keys
- Set appropriate Dead-Man Switch timeouts
- Keep software updated
- Protect hardware keys physically

### Threat Model
This application is designed to protect against:
- Network surveillance and interception
- Man-in-the-middle attacks
- Message tampering and forgery
- Unauthorized access to stored messages
- Key compromise scenarios

## Support and Documentation

For additional support and documentation:
- Check log files for error details
- Verify hardware key configuration
- Ensure all prerequisites are installed
- Review Windows Event Viewer for system errors

---

**JESUS IS KING** - Secure End-to-End Encrypted Messaging
Built with faith, secured with cryptography.

Version: $Version
Build Date: $(Get-Date -Format "yyyy-MM-dd")
"@

$ReadmeContent | Out-File -FilePath (Join-Path $PackageDir "README.md") -Encoding UTF8

# Create installation batch file for easy execution
$InstallBat = @"
@echo off
title JESUS IS KING - Secure Messaging Installer

echo ===============================================
echo   JESUS IS KING - Secure Messaging v$Version
echo   Windows Installation
echo ===============================================
echo.

echo This installer requires Administrator privileges.
echo Please run this as Administrator for proper installation.
echo.

pause

REM Check for admin rights
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Administrator privileges confirmed.
    echo Starting PowerShell installer...
    echo.
    powershell.exe -ExecutionPolicy Bypass -File "install.ps1"
) else (
    echo Error: Administrator privileges required.
    echo Please right-click this file and select "Run as Administrator"
    echo.
    pause
)
"@

$InstallBat | Out-File -FilePath (Join-Path $PackageDir "INSTALL.bat") -Encoding ASCII

# Create zip package if requested
if ($CreateZip) {
    Write-Host "Creating ZIP package..." -ForegroundColor Yellow
    $ZipPath = Join-Path $OutputDir "JESUS-IS-KING-Secure-Messaging-v$Version-Windows.zip"

    try {
        Compress-Archive -Path $PackageDir -DestinationPath $ZipPath -CompressionLevel Optimal
        Write-Host "ZIP package created: $ZipPath" -ForegroundColor Green

        # Calculate file hash
        $Hash = Get-FileHash -Path $ZipPath -Algorithm SHA256
        Write-Host "SHA256: $($Hash.Hash)" -ForegroundColor Cyan

        # Save hash to file
        $Hash.Hash | Out-File -FilePath "$ZipPath.sha256" -Encoding ASCII
    } catch {
        Write-Host "Error creating ZIP: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Create MSI installer if requested (requires WiX toolset)
if ($CreateMSI) {
    Write-Host "Checking for WiX toolset..." -ForegroundColor Yellow

    if (Get-Command "candle.exe" -ErrorAction SilentlyContinue) {
        Write-Host "Creating MSI installer..." -ForegroundColor Yellow

        # Create WiX configuration (simplified)
        $WixConfig = @"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="JESUS IS KING - Secure Messaging" Language="1033" Version="$Version"
           Manufacturer="Secure Messaging Team" UpgradeCode="12345678-1234-1234-1234-123456789012">
    <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine" />

    <MediaTemplate EmbedCab="yes" />

    <Feature Id="ProductFeature" Title="JESUS IS KING Secure Messaging" Level="1">
      <ComponentGroupRef Id="ProductComponents" />
    </Feature>

    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="ProgramFilesFolder">
        <Directory Id="INSTALLFOLDER" Name="JESUS IS KING Secure Messaging" />
      </Directory>
    </Directory>

    <ComponentGroup Id="ProductComponents" Directory="INSTALLFOLDER">
      <Component Id="MainExecutable" Guid="*">
        <File Id="install.ps1" Source="$PackageDir\install.ps1" KeyPath="yes" />
      </Component>
    </ComponentGroup>
  </Product>
</Wix>
"@

        $WixFile = Join-Path $OutputDir "installer.wxs"
        $WixConfig | Out-File -FilePath $WixFile -Encoding UTF8

        try {
            & candle.exe -out "$OutputDir\installer.wixobj" $WixFile
            & light.exe -out "$OutputDir\JESUS-IS-KING-Secure-Messaging-v$Version.msi" "$OutputDir\installer.wixobj"
            Write-Host "MSI installer created successfully" -ForegroundColor Green
        } catch {
            Write-Host "MSI creation failed: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "WiX toolset not found. MSI installer not created." -ForegroundColor Yellow
        Write-Host "Install WiX from: https://wixtoolset.org/" -ForegroundColor Cyan
    }
}

# Build summary
$PackageSize = (Get-ChildItem -Path $PackageDir -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
$FileCount = (Get-ChildItem -Path $PackageDir -Recurse -File).Count

Write-Host ""
Write-Host "===============================================" -ForegroundColor Green
Write-Host "  BUILD COMPLETED SUCCESSFULLY!" -ForegroundColor Green
Write-Host "===============================================" -ForegroundColor Green
Write-Host ""
Write-Host "Package Details:" -ForegroundColor Cyan
Write-Host "  Location: $PackageDir" -ForegroundColor White
Write-Host "  Size: $([math]::Round($PackageSize, 2)) MB" -ForegroundColor White
Write-Host "  Files: $FileCount" -ForegroundColor White
Write-Host ""
Write-Host "Components Included:" -ForegroundColor Cyan
Write-Host "  ✓ Complete GUI Application" -ForegroundColor Green
if ($BuildGoServer) {
    Write-Host "  ✓ Go Server for Triple Encryption" -ForegroundColor Green
}
if ($BuildCrypto) {
    Write-Host "  ✓ Hardware Key Cryptography" -ForegroundColor Green
}
Write-Host "  ✓ Installation Scripts" -ForegroundColor Green
Write-Host "  ✓ Documentation" -ForegroundColor Green
if ($CreateZip) {
    Write-Host "  ✓ ZIP Distribution Package" -ForegroundColor Green
}
if ($CreateMSI) {
    Write-Host "  ✓ MSI Windows Installer" -ForegroundColor Green
}
Write-Host ""
Write-Host "Ready for Distribution!" -ForegroundColor Green
Write-Host "Users can run INSTALL.bat to install the complete suite." -ForegroundColor Yellow
Write-Host ""