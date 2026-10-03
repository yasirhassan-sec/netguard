; Inno Setup script for the NetGuard Windows installer.
; Requires Inno Setup 6 (https://jrsoftware.org/isinfo.php). Build after PyInstaller:
;   "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" packaging\installer.iss
; Output: dist\NetGuard-Setup-<version>.exe

#define AppName "NetGuard"
#define AppVersion "3.0.0"
#define AppPublisher "NetGuard"
#define AppExe "NetGuard.exe"

[Setup]
; Never change AppId after the first public release: upgrades and uninstall depend on it.
AppId={{6F1E4C2A-8B7D-4E3F-9A21-5C0D7B8E4F13}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
LicenseFile=..\legal\EULA.txt
OutputDir=..\dist
OutputBaseFilename=NetGuard-Setup-{#AppVersion}
SetupIconFile=netguard.ico
UninstallDisplayIcon={app}\{#AppExe}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Per-user install by default (no admin prompt); user can choose all-users.
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
CloseApplications=yes
MinVersion=10.0

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"
Name: "autostart"; Description: "Start NetGuard when I sign in to Windows"; GroupDescription: "Startup:"; Flags: unchecked

[Files]
Source: "..\dist\NetGuard\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\legal\*"; DestDir: "{app}\legal"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExe}"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExe}"; Tasks: desktopicon

[Registry]
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "{#AppName}"; \
  ValueData: """{app}\{#AppExe}"""; Flags: uninsdeletevalue; Tasks: autostart

[Run]
Filename: "{app}\{#AppExe}"; Description: "{cm:LaunchProgram,{#AppName}}"; Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Scan history/settings in %LOCALAPPDATA%\NetGuard are kept on purpose so upgrades and
; reinstalls keep the user's data. Uncomment to remove them on uninstall:
; Type: filesandordirs; Name: "{localappdata}\NetGuard"
