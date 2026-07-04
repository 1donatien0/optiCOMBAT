; =============================================================================
; optiCombat — Installateur Windows (Inno Setup)
; =============================================================================
; AppRelease = nom vM.m (v1.0) · AppVersion = semver / Directory.Build.props

#define AppName        "optiCombat"
#ifndef AppVersion
#define AppVersion     "1.0.0"
#endif
#ifndef AppRelease
#define AppRelease     "v1.0"
#endif
#define AppPublisher   "Dona By"
#define AppURL         "https://sourceforge.net/projects/opticombat/"
#define AppExeName     "optiCombat.exe"
#define AppId          "{{F3A2C1D0-5B6E-4F7A-8C9D-0E1F2A3B4C5D}"
#define AppIconFile    "optiCombat.ico"
#if FileExists(AddBackslash(SourcePath) + AppIconFile)
  ; ok
#else
  #expr Error("Icone installateur absente : copiez optiCombat.ico dans installer\ (scripts\sync-installer-icon.ps1)")
#endif

; ── ISPP : emplacement de publish (VS / dotnet peuvent sortir dans publish\win-x64\ ou publish\)
; Préférer win-x64 en premier : c'est la sortie d'un « dotnet publish -r win-x64 » / profil dossier,
; et un vieux optiCombat.exe à la racine de publish\ ne doit pas masquer une publication RID récente.
; Le .csproj supprime win-x64 / win-x86 / publish avant chaque publish (cible CleanStalePublishOutput).
; CI : /DAppPublishSource=..\publish\win-x64\*
#ifndef AppPublishSource
#if FileExists(AddBackslash(SourcePath) + "..\optiCombat.WinUI\bin\Release\net8.0-windows10.0.19041.0\publish\win-x64\optiCombat.exe")
  #define AppPublishSource "..\optiCombat.WinUI\bin\Release\net8.0-windows10.0.19041.0\publish\win-x64\*"
#elif FileExists(AddBackslash(SourcePath) + "..\optiCombat\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\optiCombat.exe")
  #define AppPublishSource "..\optiCombat\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\*"
#elif FileExists(AddBackslash(SourcePath) + "..\optiCombat\bin\Release\net8.0-windows10.0.17763.0\publish\optiCombat.exe")
  #define AppPublishSource "..\optiCombat\bin\Release\net8.0-windows10.0.17763.0\publish\*"
#else
  #expr Error("optiCombat.exe introuvable. Publiez d'abord WinUI : dotnet publish optiCombat.WinUI -c Release -r win-x64 --self-contained true")
#endif
#endif

; Publication self-contained : le runtime .NET est embarqué — pas de blocage installeur.
#ifndef SelfContainedPublish
#if FileExists(AddBackslash(SourcePath) + "..\optiCombat.WinUI\bin\Release\net8.0-windows10.0.19041.0\publish\win-x64\System.Private.CoreLib.dll")
  #define SelfContainedPublish
#elif FileExists(AddBackslash(SourcePath) + "..\optiCombat\bin\Release\net8.0-windows10.0.17763.0\publish\win-x64\System.Private.CoreLib.dll")
  #define SelfContainedPublish
#endif
#endif

[Setup]
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppRelease} ({#AppVersion})
AppPublisher={#AppPublisher}
AppPublisherURL={#AppURL}
AppSupportURL={#AppURL}
AppUpdatesURL={#AppURL}
AppCopyright=Copyright 2026 Dona By
AppComments=optiCombat {#AppRelease} ({#AppVersion}) — Antivirus (ClamAV + YARA) et optimisation système
SetupIconFile={#AppIconFile}
UninstallDisplayIcon={app}\{#AppExeName}
#if FileExists("..\LICENSE.txt")
LicenseFile=..\LICENSE.txt
#endif
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
AllowNoIcons=yes
OutputDir=.\output
OutputBaseFilename=optiCombat_Setup_v{#AppVersion}
Compression=lzma2/ultra64
SolidCompression=yes
; no : évite un processus enfant LZMA parfois tué par l'antivirus (« Compile aborted » sans détail)
LZMAUseSeparateProcess=no
WizardStyle=modern
PrivilegesRequired=admin
MinVersion=10.0.17763
ArchitecturesAllowed=x86 x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
CloseApplicationsFilter=*.exe;*.dll
RestartApplications=no
VersionInfoVersion={#AppVersion}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} — Installateur
VersionInfoProductName={#AppName}
VersionInfoProductVersion={#AppVersion}
VersionInfoCopyright=Copyright 2026 Dona By

; ── SIGNATURE DE CODE (Authenticode / EV) ───────────────────────────────────
; Sans signature : SmartScreen affiche « éditeur inconnu » et de nombreux
; antivirus bloquent l'installeur. Pour signer l'installeur (et le désinstalleur) :
;   1. Tools > Configure Sign Tools… dans l'IDE Inno, créer un outil nommé "signtool" :
;      signtool sign /fd SHA256 /tr http://timestamp.digicert.com /td SHA256 /a $f
;   2. Décommenter les deux lignes ci-dessous.
; (Laisser commenté tant qu'aucun certificat n'est configuré, sinon ISCC échoue.)
;SignTool=signtool $f
;SignedUninstaller=yes

; Langue de l'installateur = langue de l'application (UiCulture en Registre).
ShowLanguageDialog=auto

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon";   Description: "Créer une icône sur le Bureau";                              GroupDescription: "Icônes supplémentaires"
Name: "startupicon";   Description: "Lancer optiCombat au démarrage de Windows";                   GroupDescription: "Options avancées"; Flags: unchecked
Name: "autoUpdateSig"; Description: "Activer les mises à jour auto des signatures (recommandé)"; GroupDescription: "Antivirus ClamAV"; Flags: checkedonce
; Mode plateforme (service Windows + minifiltre noyau) : prévu dans 3 à 5 ans (pilote signé EV).
; Case visible mais désactivée dans l'assistant — la RTP user-mode fonctionne sans lui.
Name: "platformservice"; Description: "Protection système avancée — prévue dans 3 à 5 ans (pilote signé requis, indisponible aujourd'hui)"; GroupDescription: "Protection avancée (à venir)"; Flags: unchecked

[Files]
; ── Application principale ───────────────────────────────────────────────────
; Avant de compiler : Build > Publish (Release) ou : dotnet publish -c Release
; Le chemin exact est résolu par le préprocesseur (AppPublishSource).
; clamav\*, rules\* et yara\* sont exclus ici — gérés séparément ci-dessous.
Source: "{#AppPublishSource}"; DestDir: "{app}"; Excludes: "clamav\*,rules\*,yara\*"; Flags: ignoreversion recursesubdirs createallsubdirs
; ── ClamAV (architecture-specific) — ignoré si le dossier n'existe pas (clone partiel) ──
#if DirExists(AddBackslash(SourcePath) + "..\runtime\clamav\x64")
Source: "..\runtime\clamav\x64\*"; DestDir: "{app}\clamav\x64"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: IsWin64
#endif
#if DirExists(AddBackslash(SourcePath) + "..\runtime\clamav\x86")
Source: "..\runtime\clamav\x86\*"; DestDir: "{app}\clamav\x86"; Flags: ignoreversion recursesubdirs createallsubdirs; Check: not IsWin64
#endif
; Certificat CVD (freshclam ≥ 1.5) — skip si absent (évite l'échec de compilation ISCC)
Source: "..\runtime\clamav\certs\clamav.crt"; DestDir: "{app}\clamav\x64\certs"; Flags: ignoreversion skipifsourcedoesntexist; Check: IsWin64
Source: "..\runtime\clamav\certs\clamav.crt"; DestDir: "{app}\clamav\x86\certs"; Flags: ignoreversion skipifsourcedoesntexist; Check: not IsWin64
Source: "..\runtime\clamav\database\*"; DestDir: "{app}\clamav\database"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
; ── YARA ─────────────────────────────────────────────────────────────────────
Source: "..\runtime\rules\*"; DestDir: "{app}\rules"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
Source: "..\runtime\yara\*"; DestDir: "{app}\yara"; Flags: ignoreversion recursesubdirs createallsubdirs skipifsourcedoesntexist
; ── Service Windows + composants natifs (optionnels si non compilés) ───────────
Source: "{#AppPublishSource}\optiCombat.Service.exe"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\native\optiCombat.AmsiProvider\x64\Release\optiCombat.AmsiProvider.dll"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\native\optiCombat.Minifilter\x64\optiCombat.Minifilter.sys"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
; ── Coeur moteur Rust optiCombat (cdylib FFI) — voir scripts\build-engine.ps1 ──
Source: "..\engine\target\release\opticombat.dll"; DestDir: "{app}"; Flags: ignoreversion skipifsourcedoesntexist
Source: "..\scripts\add-defender-exclusions.ps1"; DestDir: "{app}\scripts"; Flags: ignoreversion

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\{#AppExeName}"
Name: "{group}\Désinstaller {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#AppName}"; Filename: "{app}\{#AppExeName}"; Tasks: startupicon

[Registry]
; Menu contextuel Explorateur : enregistré en [Code] selon la langue de l'installateur (HKCU\Software\Classes).
Root: HKCU; Subkey: "Software\optiCombat"; ValueName: "AutoUpdateSignatures"; ValueType: dword; ValueData: "1"; Tasks: autoUpdateSig
Root: HKCU; Subkey: "Software\optiCombat"; ValueName: "Version"; ValueType: string; ValueData: "{#AppVersion}"; Flags: uninsdeletekey
; UiCulture est réécrit à chaque install / mise à jour (fr-FR ou en-US selon la langue Inno).

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Lancer {#AppName} maintenant"; Flags: nowait postinstall skipifsilent runascurrentuser

; =============================================================================
; CLEAN INSTALL — exécuté AVANT la copie des nouveaux fichiers
; =============================================================================
; Supprime les fichiers de configuration legacy susceptibles de contenir des
; chemins de la machine de dev ou la directive CVDCertsDirectory cassée
; (héritée des versions antérieures). Le code optiCombat regénère un freshclam.conf
; propre dans %LocalAppData% au premier lancement de la mise à jour.
[InstallDelete]
; --- freshclam.conf legacy dans le dossier d'install ---
Type: files; Name: "{app}\clamav\x64\freshclam.conf"
Type: files; Name: "{app}\clamav\x86\freshclam.conf"
Type: files; Name: "{app}\clamav\freshclam.conf"
Type: files; Name: "{app}\clamav\x64\freshclam.conf.v1.bak"
Type: files; Name: "{app}\clamav\x86\freshclam.conf.v1.bak"
Type: files; Name: "{app}\clamav\x64\freshclam.conf.broken.bak"
Type: files; Name: "{app}\clamav\x86\freshclam.conf.broken.bak"

; --- clamd.conf legacy (peut avoir un BOM ou un path absolu de dev) ---
Type: files; Name: "{app}\clamav\x64\clamd.conf"
Type: files; Name: "{app}\clamav\x86\clamd.conf"

; --- freshclam.conf utilisateur potentiellement cassé (ancienne version) ---
; On ne touche PAS à la base de signatures (250 Mo) ni à la quarantaine.
Type: files; Name: "{localappdata}\optiCombat\clamav\freshclam.conf"
Type: files; Name: "{localappdata}\optiCombat\clamav\freshclam.conf.v1.bak"
Type: files; Name: "{localappdata}\optiCombat\clamav\freshclam.conf.broken.bak"

; --- Verrous orphelins éventuels d'un freshclam précédent crashé ---
Type: files; Name: "{app}\clamav\database\freshclam.pid"
Type: files; Name: "{app}\clamav\database\mirrors.dat.lock"
Type: files; Name: "{app}\clamav\database\freshclam.dat.lock"

[UninstallDelete]
; Fichiers résiduels dans le dossier d'install
Type: filesandordirs; Name: "{app}\clamav\database"
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\quarantine"
; Données utilisateur (préférences, historique, logs, quarantaine) — gérées
; en supplément par CurUninstallStepChanged ci-dessous, avec confirmation.

[Code]

function IsDotNet8Installed(): Boolean;
var
  Arch: string;
begin
  Result := False;

  if IsWin64 then
    Arch := 'x64'
  else
    Arch := 'x86';

  if RegKeyExists(HKLM, 'SOFTWARE\dotnet\Setup\InstalledVersions\' + Arch + '\sharedfx\Microsoft.WindowsDesktop.App') then
  begin
    Result := True;
    Exit;
  end;

  if RegKeyExists(HKLM, 'SOFTWARE\dotnet\Setup\InstalledVersions\' + Arch + '\sharedhost') then
  begin
    Result := True;
    Exit;
  end;

  if IsWin64 then
    Result := DirExists(ExpandConstant('{pf64}\dotnet\shared\Microsoft.WindowsDesktop.App'))
  else
    Result := DirExists(ExpandConstant('{pf}\dotnet\shared\Microsoft.WindowsDesktop.App'));
end;

function InitializeSetup(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;

#ifndef SelfContainedPublish
  if not IsDotNet8Installed() then
  begin
    if ActiveLanguage = 'english' then
    begin
      if MsgBox(
        '.NET 8 Desktop Runtime is not installed on this computer.' + #13#10 + #13#10 +
        'optiCombat requires it to run.' + #13#10 +
        'Would you like to open the download page?',
        mbConfirmation, MB_YESNO) = IDYES then
        ShellExec('open', 'https://dotnet.microsoft.com/en-us/download/dotnet/8.0', '', '', SW_SHOW, ewNoWait, ResultCode);
    end
    else
    if MsgBox(
      '.NET 8 Desktop Runtime n''est pas installé sur cet ordinateur.' + #13#10 + #13#10 +
      'optiCombat en a besoin pour fonctionner.' + #13#10 +
      'Voulez-vous être redirigé vers la page de téléchargement ?',
      mbConfirmation, MB_YESNO) = IDYES then
    begin
      ShellExec('open', 'https://dotnet.microsoft.com/en-us/download/dotnet/8.0', '', '', SW_SHOW, ewNoWait, ResultCode);
    end;
    Result := False;
  end;
#endif
end;

procedure DisablePlatformServiceTask();
var
  I: Integer;
  ItemText: string;
begin
  for I := 0 to WizardForm.TasksList.Items.Count - 1 do
  begin
    ItemText := LowerCase(WizardForm.TasksList.Items[I]);
    if (Pos('protection système avancée', ItemText) > 0)
      or (Pos('advanced system protection', ItemText) > 0)
      or (Pos('protection avancée', ItemText) > 0) then
    begin
      WizardForm.TasksList.ItemEnabled[I] := False;
      WizardForm.TasksList.Checked[I] := False;
    end;
  end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = wpSelectTasks then
    DisablePlatformServiceTask();
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  UserDataLocal: string;
  UserDataRoaming: string;
  Response: Integer;
  ResultCode: Integer;
begin
  if CurUninstallStep = usPostUninstall then
  begin
    // 1. Toujours : suppression de la branche Registre HKCU\Software\optiCombat
    RegDeleteKeyIncludingSubkeys(HKCU, 'Software\optiCombat');
    RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Classes\*\shell\Scanner avec optiCombat');
    RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Classes\*\shell\Scan with optiCombat');
    RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Classes\Directory\shell\Scanner avec optiCombat');
    RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Classes\Directory\shell\Scan with optiCombat');
    RegDeleteKeyIncludingSubkeys(HKCR, '*\shell\Scanner avec optiCombat');
    RegDeleteKeyIncludingSubkeys(HKCR, '*\shell\Scan with optiCombat');
    RegDeleteKeyIncludingSubkeys(HKCR, 'Directory\shell\Scanner avec optiCombat');
    RegDeleteKeyIncludingSubkeys(HKCR, 'Directory\shell\Scan with optiCombat');

    Exec('fltmc.exe', 'unload optiCombatMinifilter', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('sc.exe', 'stop optiCombatProtection', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('sc.exe', 'delete optiCombatProtection', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('sc.exe', 'stop optiCombatProtectionV8', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Exec('sc.exe', 'delete optiCombatProtectionV8', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

    // 2. Proposition : suppression des données utilisateur (quarantaine,
    //    historique, préférences, logs). On demande explicitement car
    //    l'utilisateur peut vouloir réinstaller plus tard et conserver son
    //    historique de scans.
    UserDataLocal := ExpandConstant('{localappdata}\optiCombat');
    UserDataRoaming := ExpandConstant('{userappdata}\optiCombat');

    if DirExists(UserDataLocal) or DirExists(UserDataRoaming) then
    begin
      if ActiveLanguage = 'english' then
        Response := MsgBox(
          'Do you also want to remove all optiCombat user data?' + #13#10 + #13#10 +
          '  • Scan history' + #13#10 +
          '  • Quarantined files' + #13#10 +
          '  • Preferences and exclusions' + #13#10 +
          '  • Logs' + #13#10 + #13#10 +
          'Choose No to keep this data for a future reinstall.',
          mbConfirmation, MB_YESNO or MB_DEFBUTTON2)
      else
        Response := MsgBox(
          'Voulez-vous aussi supprimer toutes les données utilisateur d''optiCombat ?' + #13#10 + #13#10 +
          '  • Historique des scans' + #13#10 +
          '  • Fichiers en quarantaine' + #13#10 +
          '  • Préférences et exclusions' + #13#10 +
          '  • Journaux et logs' + #13#10 + #13#10 +
          'Choisir « Non » conserve ces données pour une éventuelle réinstallation.',
          mbConfirmation, MB_YESNO or MB_DEFBUTTON2);

      if Response = IDYES then
      begin
        if DirExists(UserDataLocal) then
          DelTree(UserDataLocal, True, True, True);
        if DirExists(UserDataRoaming) then
          DelTree(UserDataRoaming, True, True, True);
      end;
    end;
  end;
end;

// =============================================================================
// CLEAN INSTALL — détecte une installation précédente et propose un reset
// =============================================================================
// Si l'utilisateur fait une mise à jour par-dessus une version antérieure buguée
// (avec un freshclam.conf cassé en LocalAppData), on propose de wiper le
// dossier de conf pour repartir sur des bases saines. La quarantaine et
// l'historique sont conservés.
procedure WriteInstallerUiCulture();
begin
  if ActiveLanguage = 'english' then
    RegWriteStringValue(HKCU, 'Software\optiCombat', 'UiCulture', 'en-US')
  else
    RegWriteStringValue(HKCU, 'Software\optiCombat', 'UiCulture', 'fr-FR');
end;

procedure RegisterExplorerContextMenu();
var
  MenuName, ExePath, Cmd: string;
begin
  if ActiveLanguage = 'english' then
    MenuName := 'Scan with optiCombat'
  else
    MenuName := 'Scanner avec optiCombat';

  ExePath := ExpandConstant('{app}\{#AppExeName}');
  Cmd := '"' + ExePath + '" --scan "%1"';

  RegDeleteKeyIncludingSubkeys(HKCR, '*\shell\Scanner avec optiCombat');
  RegDeleteKeyIncludingSubkeys(HKCR, '*\shell\Scan with optiCombat');
  RegDeleteKeyIncludingSubkeys(HKCR, 'Directory\shell\Scanner avec optiCombat');
  RegDeleteKeyIncludingSubkeys(HKCR, 'Directory\shell\Scan with optiCombat');
  RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Classes\*\shell\Scanner avec optiCombat');
  RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Classes\*\shell\Scan with optiCombat');
  RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Classes\Directory\shell\Scanner avec optiCombat');
  RegDeleteKeyIncludingSubkeys(HKCU, 'Software\Classes\Directory\shell\Scan with optiCombat');

  RegWriteStringValue(HKCU, 'Software\Classes\*\shell\' + MenuName, '', MenuName);
  RegWriteStringValue(HKCU, 'Software\Classes\*\shell\' + MenuName, 'Icon', ExePath + ',0');
  RegWriteStringValue(HKCU, 'Software\Classes\*\shell\' + MenuName + '\command', '', Cmd);

  RegWriteStringValue(HKCU, 'Software\Classes\Directory\shell\' + MenuName, '', MenuName);
  RegWriteStringValue(HKCU, 'Software\Classes\Directory\shell\' + MenuName, 'Icon', ExePath + ',0');
  RegWriteStringValue(HKCU, 'Software\Classes\Directory\shell\' + MenuName + '\command', '', Cmd);
end;

procedure RegisterDefenderExclusions();
var
  ScriptPath, Params: string;
  ResultCode: Integer;
begin
  ScriptPath := ExpandConstant('{app}\scripts\add-defender-exclusions.ps1');
  if not FileExists(ScriptPath) then
    Exit;
  Params := '-NoProfile -ExecutionPolicy Bypass -File "' + ScriptPath + '" -InstallDir "' + ExpandConstant('{app}') + '"';
  Exec('powershell.exe', Params, '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ConfPath: string;
  Content: AnsiString;
  ShouldReset: Boolean;
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    WriteInstallerUiCulture();
    RegisterExplorerContextMenu();
    RegisterDefenderExclusions();
    if IsTaskSelected('platformservice') then
    begin
      if ActiveLanguage = 'english' then
        MsgBox(
          'Advanced system protection is not available yet.' + #13#10 +
          'It is planned in 3 to 5 years (signed kernel driver required).' + #13#10 + #13#10 +
          'User-mode real-time protection remains active in optiCombat.',
          mbInformation, MB_OK)
      else
        MsgBox(
          'La protection système avancée n''est pas encore disponible.' + #13#10 +
          'Elle est prévue dans 3 à 5 ans (pilote noyau signé requis).' + #13#10 + #13#10 +
          'La protection temps réel user-mode reste active dans optiCombat.',
          mbInformation, MB_OK);
    end;

    { ── Installation service / minifilter : conservé pour phase 2 (pilote signé).
       Réactiver quand PlatformProtectionFeatureGate.IsUserActivatable = true. }
    if False and IsTaskSelected('platformservice') then
    begin
      if FileExists(ExpandConstant('{app}\optiCombat.Service.exe')) then
      begin
        Exec('sc.exe', 'create optiCombatProtection binPath= "\"' + ExpandConstant('{app}\optiCombat.Service.exe') + '\"" start= auto DisplayName= "optiCombat Protection"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
        Exec('sc.exe', 'description optiCombatProtection "Moteur de protection optiCombat (RTP, AMSI, IPC)"', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
        Exec('sc.exe', 'start optiCombatProtection', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
      end
      else if ActiveLanguage = 'english' then
        MsgBox('The system protection service (optiCombat.Service.exe) was not included in this build. Real-time protection (RTP/AMSI/IPC) will be unavailable.', mbInformation, MB_OK)
      else
        MsgBox('Le service de protection système (optiCombat.Service.exe) n''est pas inclus dans cette version. La protection temps réel (RTP/AMSI/IPC) sera indisponible.', mbInformation, MB_OK);

      if not FileExists(ExpandConstant('{app}\optiCombat.Minifilter.sys')) then
      begin
        if ActiveLanguage = 'english' then
          MsgBox('Note: the kernel minifilter driver (optiCombat.Minifilter.sys) is absent or unsigned. Kernel-level real-time protection will not load on 64-bit Windows without a properly signed driver.', mbInformation, MB_OK)
        else
          MsgBox('Note : le pilote minifiltre noyau (optiCombat.Minifilter.sys) est absent ou non signé. La protection temps réel au niveau noyau ne se chargera pas sous Windows 64 bits sans pilote signé.', mbInformation, MB_OK);
      end;
    end;
  end;

  if CurStep = ssInstall then
  begin
    ConfPath := ExpandConstant('{localappdata}\optiCombat\clamav\freshclam.conf');
    if FileExists(ConfPath) then
    begin
      ShouldReset := False;

      // Détection automatique d'un conf cassé : contient CVDCertsDirectory
      // (directive qui faisait crasher freshclam dans les anciennes versions).
      if LoadStringFromFile(ConfPath, Content) then
      begin
        if Pos('CVDCertsDirectory', Content) > 0 then
          ShouldReset := True;
        // Détection BOM UTF-8 : si les 3 premiers octets sont EF BB BF,
        // c'est aussi un conf cassé qui fera échouer freshclam.
        if (Length(Content) >= 3) and (Ord(Content[1]) = $EF)
           and (Ord(Content[2]) = $BB) and (Ord(Content[3]) = $BF) then
          ShouldReset := True;
      end;

      if ShouldReset then
      begin
        DeleteFile(ConfPath);
        // Best effort : pas de message à l'utilisateur, c'est silencieux.
        // Le code optiCombat regénérera un conf propre au premier clic
        // "Mettre à jour".
      end;
    end;
  end;
end;
