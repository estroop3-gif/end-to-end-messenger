; JESUS IS KING - Professional Windows Installer
; Modern NSIS installer with proper GUI and uninstaller

!define APPNAME "JESUS IS KING - Secure Messenger"
!define COMPANYNAME "JESUS IS KING Development Team"
!define DESCRIPTION "Professional secure messaging with triple-encryption"
!define VERSIONMAJOR 1
!define VERSIONMINOR 0
!define VERSIONBUILD 3
!define HELPURL "https://github.com/estroop3-gif/end-to-end-messenger"
!define UPDATEURL "https://github.com/estroop3-gif/end-to-end-messenger/releases"
!define ABOUTURL "https://github.com/estroop3-gif/end-to-end-messenger"
!define INSTALLSIZE 15000

RequestExecutionLevel admin
InstallDir "$PROGRAMFILES\${APPNAME}"
LicenseData "license.txt"
Name "${APPNAME}"
Icon "icon.ico"
outFile "JESUS-IS-KING-Secure-Messenger-v${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD}-Setup.exe"

!include LogicLib.nsh
!include MUI2.nsh

; Modern UI Configuration
!define MUI_ABORTWARNING
!define MUI_ICON "icon.ico"
!define MUI_UNICON "icon.ico"
!define MUI_HEADERIMAGE
!define MUI_HEADERIMAGE_BITMAP "header.bmp"
!define MUI_WELCOMEFINISHPAGE_BITMAP "welcome.bmp"
!define MUI_UNWELCOMEFINISHPAGE_BITMAP "welcome.bmp"

; Pages
!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "license.txt"
!insertmacro MUI_PAGE_COMPONENTS
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!define MUI_FINISHPAGE_RUN "$INSTDIR\jesus-is-king-messenger.exe"
!define MUI_FINISHPAGE_RUN_TEXT "Launch JESUS IS KING Secure Messenger"
!insertmacro MUI_PAGE_FINISH

; Uninstaller pages
!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES
!insertmacro MUI_UNPAGE_FINISH

; Languages
!insertmacro MUI_LANGUAGE "English"

; Version Information
VIProductVersion "${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD}.0"
VIAddVersionKey "ProductName" "${APPNAME}"
VIAddVersionKey "CompanyName" "${COMPANYNAME}"
VIAddVersionKey "LegalCopyright" "© 2024 ${COMPANYNAME}"
VIAddVersionKey "FileDescription" "${DESCRIPTION}"
VIAddVersionKey "FileVersion" "${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD}.0"
VIAddVersionKey "ProductVersion" "${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD}.0"

; Default installation for all users
default:

; Modern installer sections
Section "JESUS IS KING Secure Messenger (required)" SecMain
	SectionIn RO ; Read only - required

	; Set output path to the installation directory
	SetOutPath $INSTDIR

	; Install main executable
	File "jesus-is-king-messenger.exe"
	File "icon.ico"

	; Create application directories
	CreateDirectory "$INSTDIR\config"
	CreateDirectory "$INSTDIR\logs"
	CreateDirectory "$INSTDIR\keys"
	CreateDirectory "$INSTDIR\data"

	; Install configuration files
	SetOutPath "$INSTDIR\config"
	File /oname=app.conf "app.conf"

	; Install documentation
	SetOutPath "$INSTDIR"
	File "README.txt"
	File "LICENSE.txt"

	; Write the installation path into the registry
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayName" "${APPNAME}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "QuietUninstallString" "$\"$INSTDIR\uninstall.exe$\" /S"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "InstallLocation" "$\"$INSTDIR$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayIcon" "$\"$INSTDIR\icon.ico$\""
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "Publisher" "${COMPANYNAME}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "HelpLink" "${HELPURL}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "URLUpdateInfo" "${UPDATEURL}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "URLInfoAbout" "${ABOUTURL}"
	WriteRegStr HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "DisplayVersion" "${VERSIONMAJOR}.${VERSIONMINOR}.${VERSIONBUILD}"
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "VersionMajor" ${VERSIONMAJOR}
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "VersionMinor" ${VERSIONMINOR}
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoModify" 1
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "NoRepair" 1
	WriteRegDWORD HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "EstimatedSize" ${INSTALLSIZE}

	; Create uninstaller
	WriteUninstaller "$INSTDIR\uninstall.exe"
SectionEnd

Section "Desktop Shortcut" SecDesktop
	; Create desktop shortcut
	CreateShortCut "$DESKTOP\${APPNAME}.lnk" "$INSTDIR\jesus-is-king-messenger.exe" "" "$INSTDIR\icon.ico"
SectionEnd

Section "Start Menu Shortcuts" SecStartMenu
	; Create start menu shortcuts
	CreateDirectory "$SMPROGRAMS\${APPNAME}"
	CreateShortCut "$SMPROGRAMS\${APPNAME}\${APPNAME}.lnk" "$INSTDIR\jesus-is-king-messenger.exe" "" "$INSTDIR\icon.ico"
	CreateShortCut "$SMPROGRAMS\${APPNAME}\Uninstall.lnk" "$INSTDIR\uninstall.exe"
	CreateShortCut "$SMPROGRAMS\${APPNAME}\Documentation.lnk" "${HELPURL}"
SectionEnd

Section "Triple Encryption Service" SecService
	; Install and register Windows service for triple encryption
	DetailPrint "Installing triple encryption service..."

	; Copy service files
	SetOutPath "$INSTDIR\service"
	File "service\triple-encryption-service.exe"
	File "service\service.conf"

	; Register service
	ExecWait '"$INSTDIR\service\triple-encryption-service.exe" --install'

	; Start service
	ExecWait 'sc start "JESUS-IS-KING-TripleEncryption"'
SectionEnd

; Section descriptions
!insertmacro MUI_FUNCTION_DESCRIPTION_BEGIN
	!insertmacro MUI_DESCRIPTION_TEXT ${SecMain} "Core application files and libraries (required)"
	!insertmacro MUI_DESCRIPTION_TEXT ${SecDesktop} "Create a desktop shortcut for easy access"
	!insertmacro MUI_DESCRIPTION_TEXT ${SecStartMenu} "Add shortcuts to the Start Menu"
	!insertmacro MUI_DESCRIPTION_TEXT ${SecService} "Install Windows service for triple encryption background processing"
!insertmacro MUI_FUNCTION_DESCRIPTION_END

; Uninstaller section
Section "Uninstall"
	; Stop and remove service if installed
	ExecWait 'sc stop "JESUS-IS-KING-TripleEncryption"'
	ExecWait 'sc delete "JESUS-IS-KING-TripleEncryption"'

	; Remove registry keys
	DeleteRegKey HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}"

	; Remove files and directories
	Delete "$INSTDIR\jesus-is-king-messenger.exe"
	Delete "$INSTDIR\icon.ico"
	Delete "$INSTDIR\README.txt"
	Delete "$INSTDIR\LICENSE.txt"
	Delete "$INSTDIR\uninstall.exe"

	; Remove config files
	RMDir /r "$INSTDIR\config"
	RMDir /r "$INSTDIR\service"

	; Remove user data (ask first)
	MessageBox MB_YESNO "Do you want to remove user data and encryption keys? This cannot be undone." IDNO +3
	RMDir /r "$INSTDIR\logs"
	RMDir /r "$INSTDIR\keys"
	RMDir /r "$INSTDIR\data"

	; Remove shortcuts
	Delete "$DESKTOP\${APPNAME}.lnk"
	RMDir /r "$SMPROGRAMS\${APPNAME}"

	; Remove installation directory if empty
	RMDir "$INSTDIR"

	; Success message
	MessageBox MB_OK "JESUS IS KING Secure Messenger has been successfully removed from your computer.$\r$\n$\r$\nThank you for using our secure messaging platform."
SectionEnd

; Functions
Function .onInit
	; Check if already installed
	ReadRegStr $R0 HKLM "Software\Microsoft\Windows\CurrentVersion\Uninstall\${APPNAME}" "UninstallString"
	StrCmp $R0 "" done

	MessageBox MB_OKCANCEL|MB_ICONEXCLAMATION \
		"${APPNAME} is already installed. $\n$\nClick `OK` to remove the previous version or `Cancel` to cancel this installation." \
		IDOK uninst
	Abort

	uninst:
		ClearErrors
		ExecWait '$R0 _?=$INSTDIR'

		IfErrors no_remove_uninstaller done
		no_remove_uninstaller:

	done:
FunctionEnd

Function un.onInit
	MessageBox MB_OKCANCEL "Are you sure you want to completely remove ${APPNAME} and all of its components?" IDOK next
		Abort
	next:
	!insertmacro MUI_UNGETLANGUAGE
FunctionEnd