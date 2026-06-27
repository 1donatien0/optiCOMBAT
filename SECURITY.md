# Security Policy — optiCOMBAT

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x (`main`) | Yes |

## Reporting a vulnerability

If you discover a security issue in optiCOMBAT, please report it privately:

1. **Do not** open a public GitHub issue for exploitable vulnerabilities.
2. Email the maintainer with: description, reproduction steps, impact, and affected version.
3. Allow up to **14 business days** for an initial response.

## Security architecture (summary)

> **Default protection is user-mode.** Real-time protection runs in-process via `FileSystemWatcher` and needs **no kernel driver and no Microsoft signing** (`UsePlatformProtectionService = false` by default). The platform layer below (Windows service, AMSI provider, kernel minifilter) is **present in the code but dormant**; it requires a **signed driver** (EV cert + Microsoft Partner Center) and is intended for a later phase.

- **Self-scan exclusion**: install directory (Program Files / process base) and `%LocalAppData%\optiCombat` (ClamAV DB, YARA rules, quarantine, update staging) are never scanned or auto-quarantined (`OpticombatProtectedPaths`); mandatory exclusion folders cannot be removed in Options.
- **Windows Defender coexistence**: on install and at startup, optiCOMBAT registers the same protected paths and its processes (`optiCombat.exe`, ClamAV/YARA binaries) in Defender exclusions via `WindowsDefenderExclusionService` and `scripts/add-defender-exclusions.ps1` (admin/UAC). Tamper Protection may block automatic registration — manual exclusions may be required.
- **Third-party AV (Kaspersky, Bitdefender, etc.)**: Defender exclusions do **not** apply to other products. An active Kaspersky RTP may **terminate** `optiCombat.exe` within seconds (behavior similar to a second antivirus: file watchers, quarantine, unsigned `opticombat.dll`). Use `scripts/kaspersky-exclusions-guide.ps1` for folder/process lists; sign binaries (`scripts/sign-dev-local.ps1`) and restore from Kaspersky Quarantine if needed.
- **Quarantine**: AES-256-GCM encryption, HMAC-signed manifest, DPAPI-protected master key; path traversal checks on restore.
- **Sensitive paths**: restore and IPC scan refuse System32, Windows, ProgramFiles, ProgramData, Startup.
- **Platform layer (dormant)**: present in code but **not user-activatable** (`PlatformProtectionFeatureGate.IsUserActivatable = false`); Options UI and installer task are grayed with « planned in 3–5 years ». When enabled in a future phase: ACL on IPC pipe; `shutdown` requires a token under `%ProgramData%\optiCombat\` (admin-only ACL).
- **AMSI (dormant)**: native `optiCombat.AmsiProvider.dll` forwards script buffers to `--service-host` via the protection pipe (admin registration). Active only when the platform layer is enabled with a signed driver.
- **Secrets**: user preferences (VirusTotal key) stored via DPAPI `SecureStore`; no credentials in the repository.
- **Release builds**: warnings as errors in Release (`Directory.Build.props`); CI on `main` (`.github/workflows/ci.yml`) runs **300** .NET tests + Rust tests before merge.

## Threat model notes

optiCOMBAT is a **desktop antivirus for Windows**. It assumes:

- Protection against typical user-space malware and misconfiguration.
- **Not** a guarantee against malware running with the same user privileges or kernel-level attackers.
- DPAPI `CurrentUser` protects local data from other users, not from same-session malware.

## Hardening backlog

- Code signing for installer and native binaries (Authenticode / EV for minifilter)
- Minifilter driver full implementation (stub in repo today)
