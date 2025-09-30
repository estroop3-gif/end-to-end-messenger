# JESUS IS KING Secure Messenger - Windows Installer (Simple Version)
# This installer avoids complex syntax and focuses on core functionality

param(
    [Parameter(Mandatory=$false)]
    [string]$InstallPath = "$env:USERPROFILE\JESUS-IS-KING-Messenger"
)

Write-Host "================================" -ForegroundColor Green
Write-Host "JESUS IS KING Secure Messenger" -ForegroundColor Green
Write-Host "Windows Installation Script" -ForegroundColor Green
Write-Host "Version 1.0.3 (Simplified)" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host ""

Write-Host "Installation path: $InstallPath" -ForegroundColor Yellow
Write-Host ""

# Create installation directory
Write-Host "Creating installation directory..." -ForegroundColor Cyan
if (!(Test-Path $InstallPath)) {
    New-Item -ItemType Directory -Path $InstallPath -Force | Out-Null
    Write-Host "Created: $InstallPath" -ForegroundColor Green
} else {
    Write-Host "Directory already exists: $InstallPath" -ForegroundColor Yellow
}

# Create subdirectories
$BinDir = Join-Path $InstallPath "bin"
$LogsDir = Join-Path $InstallPath "logs"
$ConfigDir = Join-Path $InstallPath "config"

@($BinDir, $LogsDir, $ConfigDir) | ForEach-Object {
    if (!(Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
        Write-Host "Created: $_" -ForegroundColor Green
    }
}

# Copy application files
Write-Host "Copying application files..." -ForegroundColor Cyan
$SourceDir = Split-Path -Parent $PSScriptRoot

# Copy main executable
$ExeSource = Join-Path $SourceDir "JESUS-IS-KING-Messenger.exe"
$ExeDest = Join-Path $BinDir "JESUS-IS-KING-Messenger.exe"

if (Test-Path $ExeSource) {
    Copy-Item $ExeSource $ExeDest -Force
    Write-Host "Copied main executable" -ForegroundColor Green
} else {
    Write-Host "Warning: Main executable not found at $ExeSource" -ForegroundColor Yellow
}

# Copy GUI files if they exist
$GuiSource = Join-Path $SourceDir "gui"
$GuiDest = Join-Path $InstallPath "gui"

if (Test-Path $GuiSource) {
    Copy-Item $GuiSource $GuiDest -Recurse -Force
    Write-Host "Copied GUI files" -ForegroundColor Green
} else {
    Write-Host "GUI files not found - skipping" -ForegroundColor Yellow
}

# Create launcher script
Write-Host "Creating launcher script..." -ForegroundColor Cyan

$LauncherScript = @"
@echo off
title JESUS IS KING Secure Messenger
echo ================================
echo JESUS IS KING Secure Messenger
echo ================================
echo.
echo Starting secure messaging application...
echo.
echo Security Features:
echo - Triple-Layer Encryption (Signal + ChaCha20 + AES-256)
echo - Certificate Pinning
echo - Request Signing
echo - Intrusion Detection
echo.

cd /d "$InstallPath"

if exist "bin\JESUS-IS-KING-Messenger.exe" (
    echo Starting main application...
    "bin\JESUS-IS-KING-Messenger.exe"
) else (
    echo Error: Main executable not found!
    echo Please reinstall the application.
    pause
    exit /b 1
)

if exist "gui\index.html" (
    echo.
    echo Starting web interface...

    REM Try Python first (most reliable)
    python --version >nul 2>&1
    if not errorlevel 1 (
        echo Using Python web server...
        cd gui
        start "" "http://localhost:1420"
        python -m http.server 1420
        cd ..
    ) else (
        REM Try opening directly
        echo Opening GUI in default browser...
        start "" "gui\index.html"
    )
)

echo.
echo Application started successfully!
pause
"@

$LauncherPath = Join-Path $BinDir "JESUS-IS-KING-Messenger.bat"
$LauncherScript | Out-File -FilePath $LauncherPath -Encoding ASCII

Write-Host "Created launcher: $LauncherPath" -ForegroundColor Green

# Create desktop shortcut
Write-Host "Creating desktop shortcut..." -ForegroundColor Cyan
try {
    $WScriptShell = New-Object -ComObject WScript.Shell
    $DesktopPath = $WScriptShell.SpecialFolders("Desktop")
    $ShortcutPath = Join-Path $DesktopPath "JESUS IS KING Messenger.lnk"
    $Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)
    $Shortcut.TargetPath = $LauncherPath
    $Shortcut.WorkingDirectory = $InstallPath
    $Shortcut.Description = "JESUS IS KING Secure Messenger"
    $Shortcut.Save()
    Write-Host "Created desktop shortcut" -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not create desktop shortcut: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Create Start Menu entry
Write-Host "Creating Start Menu entry..." -ForegroundColor Cyan
try {
    $StartMenuPath = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
    $StartMenuShortcut = Join-Path $StartMenuPath "JESUS IS KING Messenger.lnk"
    $Shortcut = $WScriptShell.CreateShortcut($StartMenuShortcut)
    $Shortcut.TargetPath = $LauncherPath
    $Shortcut.WorkingDirectory = $InstallPath
    $Shortcut.Description = "JESUS IS KING Secure Messenger"
    $Shortcut.Save()
    Write-Host "Created Start Menu entry" -ForegroundColor Green
} catch {
    Write-Host "Warning: Could not create Start Menu entry: $($_.Exception.Message)" -ForegroundColor Yellow
}

# Create uninstaller
Write-Host "Creating uninstaller..." -ForegroundColor Cyan

$UninstallerScript = @"
# JESUS IS KING Messenger Uninstaller
param([switch]`$Force)

Write-Host "JESUS IS KING Messenger Uninstaller" -ForegroundColor Red
Write-Host "====================================" -ForegroundColor Red
Write-Host ""

if (-not `$Force) {
    `$response = Read-Host "Are you sure you want to uninstall? (y/N)"
    if (`$response -ne "y" -and `$response -ne "Y") {
        Write-Host "Uninstall cancelled." -ForegroundColor Yellow
        exit
    }
}

Write-Host "Removing application files..." -ForegroundColor Yellow

# Remove desktop shortcut
`$DesktopShortcut = Join-Path ([Environment]::GetFolderPath("Desktop")) "JESUS IS KING Messenger.lnk"
if (Test-Path `$DesktopShortcut) {
    Remove-Item `$DesktopShortcut -Force
    Write-Host "Removed desktop shortcut" -ForegroundColor Green
}

# Remove Start Menu entry
`$StartMenuShortcut = Join-Path `$env:APPDATA "Microsoft\Windows\Start Menu\Programs\JESUS IS KING Messenger.lnk"
if (Test-Path `$StartMenuShortcut) {
    Remove-Item `$StartMenuShortcut -Force
    Write-Host "Removed Start Menu entry" -ForegroundColor Green
}

# Remove installation directory
`$InstallDir = "$InstallPath"
if (Test-Path `$InstallDir) {
    Remove-Item `$InstallDir -Recurse -Force
    Write-Host "Removed installation directory" -ForegroundColor Green
}

Write-Host ""
Write-Host "Uninstall completed successfully!" -ForegroundColor Green
Write-Host "Thank you for using JESUS IS KING Messenger." -ForegroundColor Cyan
pause
"@

$UninstallerPath = Join-Path $InstallPath "Uninstall.ps1"
$UninstallerScript | Out-File -FilePath $UninstallerPath -Encoding UTF8

Write-Host "Created uninstaller: $UninstallerPath" -ForegroundColor Green

# Installation complete
Write-Host ""
Write-Host "================================" -ForegroundColor Green
Write-Host "INSTALLATION COMPLETED!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host ""
Write-Host "Application installed to: $InstallPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "To start the application:" -ForegroundColor Yellow
Write-Host "- Use the desktop shortcut" -ForegroundColor White
Write-Host "- Use the Start Menu entry" -ForegroundColor White
Write-Host "- Run: $LauncherPath" -ForegroundColor White
Write-Host ""
Write-Host "To uninstall:" -ForegroundColor Yellow
Write-Host "- Run: $UninstallerPath" -ForegroundColor White
Write-Host ""
Write-Host "Security Features Enabled:" -ForegroundColor Green
Write-Host "- Triple-Layer Encryption (Signal Protocol + ChaCha20-Poly1305 + AES-256-GCM)" -ForegroundColor White
Write-Host "- Certificate Pinning for MITM Protection" -ForegroundColor White
Write-Host "- Ed25519 Digital Signatures" -ForegroundColor White
Write-Host "- Real-time Intrusion Detection" -ForegroundColor White
Write-Host "- Request Authentication & Authorization" -ForegroundColor White
Write-Host ""
Write-Host "Press any key to launch the application..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

# Launch the application
& $LauncherPath