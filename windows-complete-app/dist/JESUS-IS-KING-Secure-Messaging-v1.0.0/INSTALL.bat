@echo off
title JESUS IS KING - Secure Messaging Installer v1.0.0

REM Change to the directory where this script is located
cd /d "%~dp0"

echo ===============================================
echo   JESUS IS KING - Secure Messaging v1.0.0
echo   Complete Windows Installation
echo ===============================================
echo.
echo This installer will set up the complete secure messaging suite:
echo   * Complete GUI Application with all features
echo   * Go Server for Triple Encryption Architecture
echo   * Hardware Key Authentication System
echo   * Ed25519 Digital Signatures and ChaCha20-Poly1305 Encryption
echo   * Dead-Man Switch Security System
echo   * All Cryptography Tools and Document Creation
echo.
echo Triple Encryption Flow:
echo   User --^> Go Server --^> Shuttle Website --^> Receiver's Go Server
echo.
echo Current directory: %CD%
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
    cd /d "%~dp0"
    if exist "installer\install.ps1" (
        powershell.exe -ExecutionPolicy Bypass -File "installer\install.ps1"
    ) else (
        echo ERROR: installer\install.ps1 not found!
        echo Please make sure you extracted the complete package and are running INSTALL.bat from the main directory.
        echo Current directory: %CD%
        echo Looking for: %CD%\installer\install.ps1
        echo.
        pause
        exit /b 1
    )
    echo.
    echo Installation completed!
    echo.
    echo Next steps:
    echo 1. Run 'Setup-HardwareKeys.bat' to configure authentication
    echo 2. Launch 'JESUS IS KING - Secure Messaging' from Desktop
    echo 3. Complete user-to-user handshake authentication
    echo.
    echo JESUS IS KING!
    pause
) else (
    echo.
    echo ERROR: Administrator privileges required!
    echo.
    echo Please right-click this file and select "Run as Administrator"
    echo.
    pause
)