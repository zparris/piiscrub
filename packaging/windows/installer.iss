; packaging/windows/installer.iss
; Inno Setup script — produces PIIScrub-Windows-Setup.exe
;
; Install Inno Setup from https://jrsoftware.org/isinfo.php
; Then compile with:   iscc packaging\windows\installer.iss
; Or from GUI:         Open this file in Inno Setup Compiler, press F9
;
; Output: packaging\windows\Output\PIIScrub-Windows-Setup.exe

#define AppName "PIIScrub"
#define AppVersion "0.1.0"
#define AppPublisher "Zahir Parris"
#define AppURL "https://github.com/zparris/piiscrub"
#define AppExeName "PIIScrub.exe"
#define SourceDir "..\..\dist\PIIScrub"
#define OutputDir "Output"

[Setup]
AppId={{B7A4C2E1-8F3D-4A5B-9C6E-0D1E2F3A4B5C}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}/issues
AppUpdatesURL={#AppURL}/releases
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes
; No admin required — installs to per-user Program Files
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog
OutputDir={#OutputDir}
OutputBaseFilename=PIIScrub-Windows-Setup
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
; Show a "Data never leaves your machine" notice on the welcome page
WizardImageFile=compiler:WizModernImage.bmp
WizardSmallImageFile=compiler:WizModernSmallImage.bmp
UninstallDisplayName={#AppName}
CloseApplications=yes
RestartIfNeededByRun=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; \
    GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked

[Files]
; Copy everything from PyInstaller's one-dir output
Source: "{#SourceDir}\*"; DestDir: "{app}"; \
    Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"; \
    Comment: "Scrub PII from documents — data stays on your machine"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; \
    Tasks: desktopicon; Comment: "Scrub PII from documents"

[Run]
; Offer to launch the app at the end of installation
Filename: "{app}\{#AppExeName}"; \
    Description: "{cm:LaunchProgram,{#StringChange(AppName,'&','&&')}}"; \
    Flags: nowait postinstall skipifsilent

[UninstallDelete]
; Clean up any runtime-generated files in the install dir
Type: filesandordirs; Name: "{app}\__pycache__"
Type: filesandordirs; Name: "{app}\_MEI*"

[Code]
// Show a privacy notice before installation
function InitializeSetup(): Boolean;
var
  MsgResult: Integer;
begin
  MsgResult := MsgBox(
    'PIIScrub processes documents locally on your computer.' + #13#10 +
    'No data is sent to any external server.' + #13#10 + #13#10 +
    'A terminal window will appear when PIIScrub is running — ' +
    'this is normal. Your web browser will open automatically.' + #13#10 + #13#10 +
    'Windows SmartScreen may warn about this installer because it is not ' +
    'digitally signed. Click "More info" then "Run anyway" to proceed.',
    mbInformation, MB_OKCANCEL
  );
  Result := (MsgResult = IDOK);
end;
