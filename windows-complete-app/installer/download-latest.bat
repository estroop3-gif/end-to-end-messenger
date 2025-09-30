@echo off
title Download Latest JESUS IS KING Messenger
color 0A

echo =========================================
echo Download Latest JESUS IS KING Messenger
echo =========================================
echo.

echo This will download the latest installer from GitHub...
echo.

REM Check if curl is available
curl --version >nul 2>&1
if not errorlevel 1 (
    echo Using curl to download...
    echo.
    echo Downloading simple PowerShell installer...
    curl -L -o "install-simple.ps1" "https://raw.githubusercontent.com/estroop3-gif/end-to-end-messenger/main/windows-complete-app/installer/install-simple.ps1"

    echo.
    echo Downloading batch installer...
    curl -L -o "install-batch.bat" "https://raw.githubusercontent.com/estroop3-gif/end-to-end-messenger/main/windows-complete-app/installer/install-batch.bat"

) else (
    REM Check if PowerShell is available for download
    powershell -Command "Get-Command Invoke-WebRequest" >nul 2>&1
    if not errorlevel 1 (
        echo Using PowerShell to download...
        echo.
        echo Downloading simple PowerShell installer...
        powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/estroop3-gif/end-to-end-messenger/main/windows-complete-app/installer/install-simple.ps1' -OutFile 'install-simple.ps1'"

        echo.
        echo Downloading batch installer...
        powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/estroop3-gif/end-to-end-messenger/main/windows-complete-app/installer/install-batch.bat' -OutFile 'install-batch.bat'"

    ) else (
        echo Error: No download method available!
        echo.
        echo Please install one of the following:
        echo - curl (recommended)
        echo - PowerShell with Invoke-WebRequest
        echo.
        echo Or manually download the files from:
        echo https://github.com/estroop3-gif/end-to-end-messenger/tree/main/windows-complete-app/installer
        echo.
        pause
        exit /b 1
    )
)

echo.
echo Download completed!
echo.
echo Available installers:
echo - install-simple.ps1 (PowerShell version)
echo - install-batch.bat (Batch version)
echo.
echo Recommended: Use install-batch.bat for maximum compatibility
echo.

set /p "choice=Run batch installer now? (y/N): "
if /i "%choice%"=="y" (
    echo.
    echo Starting installation...
    call install-batch.bat
) else (
    echo.
    echo You can run the installer later by double-clicking:
    echo - install-batch.bat (recommended)
    echo - install-simple.ps1 (PowerShell version)
    echo.
    pause
)