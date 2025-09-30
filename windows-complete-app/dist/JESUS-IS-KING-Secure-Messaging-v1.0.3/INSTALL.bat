@echo off
setlocal enabledelayedexpansion

title JESUS IS KING Secure Messenger - Installer
color 0A

echo ========================================
echo    JESUS IS KING Secure Messenger
echo    Windows Installation Script
echo    Version 1.0.3 (Batch)
echo ========================================
echo.

REM Set installation path
set "INSTALL_PATH=%USERPROFILE%\JESUS-IS-KING-Messenger"

echo Installation path: %INSTALL_PATH%
echo.

REM Create installation directory
echo Creating installation directory...
if not exist "%INSTALL_PATH%" mkdir "%INSTALL_PATH%"
if not exist "%INSTALL_PATH%\bin" mkdir "%INSTALL_PATH%\bin"
if not exist "%INSTALL_PATH%\logs" mkdir "%INSTALL_PATH%\logs"
if not exist "%INSTALL_PATH%\config" mkdir "%INSTALL_PATH%\config"

echo Created directory structure.
echo.

REM Copy files
echo Copying application files...
set "SOURCE_DIR=%~dp0.."

if exist "%SOURCE_DIR%\JESUS-IS-KING-Messenger.exe" (
    copy "%SOURCE_DIR%\JESUS-IS-KING-Messenger.exe" "%INSTALL_PATH%\bin\" >nul
    echo Copied main executable.
) else (
    echo Warning: Main executable not found.
)

if exist "%SOURCE_DIR%\gui" (
    xcopy "%SOURCE_DIR%\gui" "%INSTALL_PATH%\gui" /E /I /Y >nul
    echo Copied GUI files.
) else (
    echo GUI files not found - using console mode only.
)

REM Create launcher
echo Creating launcher script...

set "LAUNCHER_PATH=%INSTALL_PATH%\bin\JESUS-IS-KING-Messenger.bat"

echo @echo off > "%LAUNCHER_PATH%"
echo title JESUS IS KING Secure Messenger >> "%LAUNCHER_PATH%"
echo color 0B >> "%LAUNCHER_PATH%"
echo echo ================================ >> "%LAUNCHER_PATH%"
echo echo JESUS IS KING Secure Messenger >> "%LAUNCHER_PATH%"
echo echo ================================ >> "%LAUNCHER_PATH%"
echo echo. >> "%LAUNCHER_PATH%"
echo echo Starting secure messaging application... >> "%LAUNCHER_PATH%"
echo echo. >> "%LAUNCHER_PATH%"
echo echo Security Features: >> "%LAUNCHER_PATH%"
echo echo - Triple-Layer Encryption >> "%LAUNCHER_PATH%"
echo echo - Certificate Pinning >> "%LAUNCHER_PATH%"
echo echo - Digital Signatures >> "%LAUNCHER_PATH%"
echo echo - Intrusion Detection >> "%LAUNCHER_PATH%"
echo echo. >> "%LAUNCHER_PATH%"
echo cd /d "%INSTALL_PATH%" >> "%LAUNCHER_PATH%"
echo if exist "bin\JESUS-IS-KING-Messenger.exe" ( >> "%LAUNCHER_PATH%"
echo     echo Starting main application... >> "%LAUNCHER_PATH%"
echo     "bin\JESUS-IS-KING-Messenger.exe" >> "%LAUNCHER_PATH%"
echo ^) else ( >> "%LAUNCHER_PATH%"
echo     echo Error: Main executable not found! >> "%LAUNCHER_PATH%"
echo     echo Please reinstall the application. >> "%LAUNCHER_PATH%"
echo     pause >> "%LAUNCHER_PATH%"
echo     exit /b 1 >> "%LAUNCHER_PATH%"
echo ^) >> "%LAUNCHER_PATH%"
echo if exist "gui\index.html" ( >> "%LAUNCHER_PATH%"
echo     echo. >> "%LAUNCHER_PATH%"
echo     echo Starting web interface... >> "%LAUNCHER_PATH%"
echo     python --version ^>nul 2^>^&1 >> "%LAUNCHER_PATH%"
echo     if not errorlevel 1 ( >> "%LAUNCHER_PATH%"
echo         echo Using Python web server... >> "%LAUNCHER_PATH%"
echo         cd gui >> "%LAUNCHER_PATH%"
echo         start "" "http://localhost:1420" >> "%LAUNCHER_PATH%"
echo         python -m http.server 1420 >> "%LAUNCHER_PATH%"
echo         cd .. >> "%LAUNCHER_PATH%"
echo     ^) else ( >> "%LAUNCHER_PATH%"
echo         echo Opening GUI in browser... >> "%LAUNCHER_PATH%"
echo         start "" "gui\index.html" >> "%LAUNCHER_PATH%"
echo     ^) >> "%LAUNCHER_PATH%"
echo ^) >> "%LAUNCHER_PATH%"
echo echo. >> "%LAUNCHER_PATH%"
echo echo Application started successfully! >> "%LAUNCHER_PATH%"
echo pause >> "%LAUNCHER_PATH%"

echo Created launcher script.
echo.

REM Create desktop shortcut (using VBScript)
echo Creating desktop shortcut...

set "SHORTCUT_SCRIPT=%TEMP%\create_shortcut.vbs"

echo Set WshShell = WScript.CreateObject("WScript.Shell"^) > "%SHORTCUT_SCRIPT%"
echo DesktopPath = WshShell.SpecialFolders("Desktop"^) >> "%SHORTCUT_SCRIPT%"
echo Set Shortcut = WshShell.CreateShortcut(DesktopPath ^& "\JESUS IS KING Messenger.lnk"^) >> "%SHORTCUT_SCRIPT%"
echo Shortcut.TargetPath = "%LAUNCHER_PATH%" >> "%SHORTCUT_SCRIPT%"
echo Shortcut.WorkingDirectory = "%INSTALL_PATH%" >> "%SHORTCUT_SCRIPT%"
echo Shortcut.Description = "JESUS IS KING Secure Messenger" >> "%SHORTCUT_SCRIPT%"
echo Shortcut.Save >> "%SHORTCUT_SCRIPT%"

cscript //nologo "%SHORTCUT_SCRIPT%" >nul 2>&1
if %errorlevel% equ 0 (
    echo Created desktop shortcut.
) else (
    echo Warning: Could not create desktop shortcut.
)

del "%SHORTCUT_SCRIPT%" >nul 2>&1

REM Create Start Menu shortcut
echo Creating Start Menu entry...

set "STARTMENU_SCRIPT=%TEMP%\create_startmenu.vbs"

echo Set WshShell = WScript.CreateObject("WScript.Shell"^) > "%STARTMENU_SCRIPT%"
echo StartMenuPath = WshShell.SpecialFolders("Programs"^) >> "%STARTMENU_SCRIPT%"
echo Set Shortcut = WshShell.CreateShortcut(StartMenuPath ^& "\JESUS IS KING Messenger.lnk"^) >> "%STARTMENU_SCRIPT%"
echo Shortcut.TargetPath = "%LAUNCHER_PATH%" >> "%STARTMENU_SCRIPT%"
echo Shortcut.WorkingDirectory = "%INSTALL_PATH%" >> "%STARTMENU_SCRIPT%"
echo Shortcut.Description = "JESUS IS KING Secure Messenger" >> "%STARTMENU_SCRIPT%"
echo Shortcut.Save >> "%STARTMENU_SCRIPT%"

cscript //nologo "%STARTMENU_SCRIPT%" >nul 2>&1
if %errorlevel% equ 0 (
    echo Created Start Menu entry.
) else (
    echo Warning: Could not create Start Menu entry.
)

del "%STARTMENU_SCRIPT%" >nul 2>&1

REM Create uninstaller
echo Creating uninstaller...

set "UNINSTALLER_PATH=%INSTALL_PATH%\Uninstall.bat"

echo @echo off > "%UNINSTALLER_PATH%"
echo setlocal >> "%UNINSTALLER_PATH%"
echo title JESUS IS KING Messenger - Uninstaller >> "%UNINSTALLER_PATH%"
echo color 0C >> "%UNINSTALLER_PATH%"
echo echo JESUS IS KING Messenger Uninstaller >> "%UNINSTALLER_PATH%"
echo echo ==================================== >> "%UNINSTALLER_PATH%"
echo echo. >> "%UNINSTALLER_PATH%"
echo set /p "response=Are you sure you want to uninstall? (y/N): " >> "%UNINSTALLER_PATH%"
echo if /i not "!response!"=="y" ( >> "%UNINSTALLER_PATH%"
echo     echo Uninstall cancelled. >> "%UNINSTALLER_PATH%"
echo     pause >> "%UNINSTALLER_PATH%"
echo     exit /b >> "%UNINSTALLER_PATH%"
echo ^) >> "%UNINSTALLER_PATH%"
echo echo. >> "%UNINSTALLER_PATH%"
echo echo Removing application files... >> "%UNINSTALLER_PATH%"
echo del "%%USERPROFILE%%\Desktop\JESUS IS KING Messenger.lnk" ^>nul 2^>^&1 >> "%UNINSTALLER_PATH%"
echo del "%%APPDATA%%\Microsoft\Windows\Start Menu\Programs\JESUS IS KING Messenger.lnk" ^>nul 2^>^&1 >> "%UNINSTALLER_PATH%"
echo cd /d "%%USERPROFILE%%" >> "%UNINSTALLER_PATH%"
echo rmdir /s /q "%INSTALL_PATH%" ^>nul 2^>^&1 >> "%UNINSTALLER_PATH%"
echo echo. >> "%UNINSTALLER_PATH%"
echo echo Uninstall completed successfully! >> "%UNINSTALLER_PATH%"
echo echo Thank you for using JESUS IS KING Messenger. >> "%UNINSTALLER_PATH%"
echo pause >> "%UNINSTALLER_PATH%"

echo Created uninstaller.
echo.

REM Installation complete
echo ========================================
echo         INSTALLATION COMPLETED!
echo ========================================
echo.
echo Application installed to: %INSTALL_PATH%
echo.
echo To start the application:
echo - Use the desktop shortcut
echo - Use the Start Menu entry
echo - Run: %LAUNCHER_PATH%
echo.
echo To uninstall:
echo - Run: %UNINSTALLER_PATH%
echo.
echo Security Features Enabled:
echo - Triple-Layer Encryption
echo - Certificate Pinning
echo - Digital Signatures
echo - Intrusion Detection
echo.
echo Press any key to launch the application...
pause >nul

REM Launch the application
start "" "%LAUNCHER_PATH%"

echo.
echo Application launched successfully!
echo You can close this window.
pause