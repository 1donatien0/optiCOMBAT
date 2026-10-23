<p align="center">
  <img src="assets/branding/optiCombat_emblem_transparent.png" alt="optiCOMBAT" width="180">
</p>

<h1 align="center">optiCOMBAT</h1>

<p align="center">
  <strong>Free antivirus and PC optimizer for Windows, with a WinUI 3 shell, ClamAV, and YARA.</strong><br>
  No account, no ads, no telemetry.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-v1.0.0-2ea44f?style=for-the-badge&logo=windows" alt="optiCOMBAT v1.0.0 for Windows">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/platform-Windows%2010%20%7C%2011%20x64-0078D6" alt="Platform: Windows 10 and 11 x64">
  <img src="https://img.shields.io/badge/.NET-8-512BD4" alt=".NET 8">
  <img src="https://img.shields.io/badge/UI-WinUI%203-0078D4" alt="WinUI 3">
  <a href="https://github.com/1donatien0/optiCOMBAT/actions/workflows/ci.yml"><img src="https://github.com/1donatien0/optiCOMBAT/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://github.com/1donatien0/optiCOMBAT/actions/workflows/codeql.yml"><img src="https://github.com/1donatien0/optiCOMBAT/actions/workflows/codeql.yml/badge.svg" alt="CodeQL"></a>
</p>

<p align="center">
  English · <a href="README.fr.md">Français</a>
</p>

## Why optiCOMBAT?

Most “free” antivirus products push an upgrade, collect data, or show ads. optiCOMBAT is a Windows app that puts two well-known detection engines, [ClamAV](https://www.clamav.net/) and [YARA](https://virustotal.github.io/yara/), behind a WinUI 3 interface, and adds the cleanup and tuning tools people usually look for in a separate optimizer. Signature updates are the only network traffic. There is no account, no advertising, and no telemetry.

optiCOMBAT is designed to **work alongside Windows Defender**, not to replace it. On first launch, if Defender is active, the app offers to leave real-time protection to Defender. Exclusions for optiCOMBAT stay off until you turn them on in Options.

## Features

**Antivirus**

- Quick, full, and custom scans, plus a file or a folder
- “Scan with optiCombat” in the File Explorer context menu
- ClamAV and YARA running in parallel, with automatic signature and YARA-Forge rule updates
- Optional Rust core (`opticombat.dll`), off by default: Options → “Native Rust core (experimental)”
- User-mode real-time protection and process monitoring
- Automatic scan of USB drives and SD cards, and a scheduled scan
- Encrypted quarantine (AES-GCM), with restore and delete
- Scan history with HTML and PDF reports
- Security score out of 100, with one-click fixes
- Companion mode for Windows Defender

**Optimizer**

- Cleanup of temporary files, caches from seven browsers, the Recycle Bin, Windows logs, the Windows Update cache, the DNS cache, and browsing history
- Application updates through `winget`, and a shortcut to Windows Update
- Fourteen Windows tweaks

**Interface**

- One WinUI 3 window, fully in French and English
- Light, dark, and high-contrast themes, following the Windows theme
- Accent presets: Combat Aqua, Midnight, Ocean, Ember, plus a custom color
- Mica, a live status bar, a first-run guide, and a notification-area icon

## Good to know

The platform layer — Windows service, AMSI, and minifilter — is **included but inactive**. Protection runs without a signed driver. Windows Defender remains the real-time protection to keep on.

An upgrade replaces the app in the same folder. Scan history, quarantine, and preferences stay in place. There is no need to uninstall first.

| What | Where |
|------|--------|
| Program | `optiCombat.exe` |
| Scan data, history, quarantine | `%LocalAppData%\optiCombat` |
| Preferences | `%AppData%\optiCombat` |
| Installer | `optiCombat_Setup_v1.0.0.exe` (self-contained, in-place update) |

## Install

1. Run **`optiCombat_Setup_v1.0.0.exe`**. Build it with the release script below, or use a published binary when one is attached to a release.
2. Choose English or French, then finish the installer. It needs administrator rights. The .NET runtime is included.
3. Open optiCOMBAT and let it download the ClamAV signatures and YARA rules. Leave Windows Defender enabled.

**Requirements:** Windows 10 or Windows 11, 64-bit.

## How it works

```
optiCombat.exe              WinUI 3 shell (.NET 8)
    ├── ClamAV              clamd, or clamscan as a fallback
    ├── YARA                rules, including YARA-Forge
    └── opticombat.dll      optional Rust core, off by default
          ├── reputation    hash lists; MalwareBazaarDb when a caller loads a CSV
          ├── yara-engine   local YARA rules
          ├── heuristics    PE analysis, ML classifier
          └── ioc-engine    URLhaus + ThreatFox, empty until a feed is loaded

Platform layer              Windows service, AMSI, minifilter
                            shipped with the product, inactive
```

The shell does not download MalwareBazaar, URLhaus, or ThreatFox. The Rust core makes no network calls. `Dispatcher::new` leaves the IOC engine empty.

The technical guide covers architecture, the security model, the build, and the release process: **[docs/GUIDE_COMPLET.md](docs/GUIDE_COMPLET.md)**.

## Build from source

```powershell
git clone https://github.com/1donatien0/optiCOMBAT.git
cd optiCOMBAT
.\scripts\fetch-runtime-deps.ps1
dotnet build optiCombat.sln -c Release
.\scripts\build-engine.ps1
dotnet test optiCombat.Tests\optiCombat.Tests.csproj -c Release
dotnet run --project optiCombat.WinUI\optiCombat.WinUI.csproj
```

You need Windows 10 or 11 x64, the .NET 8 SDK, and Rust. The installer build also needs Inno Setup 6. Details: [CONTRIBUTING.md](CONTRIBUTING.md).

Full release (tests, publish, `opticombat.dll`, installer):

```powershell
.\scripts\prepare-release.ps1
# Output: installer\output\optiCombat_Setup_v1.0.0.exe
```

## Documentation

| Document | Topic |
|----------|--------|
| [docs/GUIDE_COMPLET.md](docs/GUIDE_COMPLET.md) | Architecture, interface, engines, release, quality |
| [docs/SHELL_WINUI.md](docs/SHELL_WINUI.md) | WinUI 3 shell |
| [docs/GUIDE_DISTRIBUTION.md](docs/GUIDE_DISTRIBUTION.md) | Signing and coexistence with other antivirus products |
| [engine/README.md](engine/README.md) | Rust detection core |
| [SECURITY.md](SECURITY.md) | Vulnerabilities and threat model |
| [CHANGELOG.md](CHANGELOG.md) | Release notes |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Build, tests, contributions |

## Quality

Release unit tests (xUnit): **618 / 618** passing, including the shell view models. Line coverage **66.4%** — CI floor **62%**, target **65%**.

Rust: **111** `#[test]` functions in the workspace (`cargo test --workspace --manifest-path engine/Cargo.toml`), including `ioc-engine`, `urlhaus`, `threatfox`, `extractor`, `bazaar_tests`, and the dispatcher IOC tests. Line coverage at least **65%** (`cargo llvm-cov`, target 75%), plus `cargo clippy -D warnings` and `cargo fmt --check`.

CI runs the C# and Rust tests, CodeQL, Gitleaks, Dependency Review, and Dependabot.

## Contributing

Questions, bugs, and false positives: [open an issue](https://github.com/1donatien0/optiCOMBAT/issues).

Security vulnerabilities: report them in private, as described in [SECURITY.md](SECURITY.md).

## License

optiCOMBAT is free software distributed under the [end-user license](LICENSE.txt), without warranty. You may use it and redistribute it unmodified and at no charge. ClamAV (GPL-2.0), YARA-Forge, and the other bundled components keep their own licenses.

Made by **Dona By (Donatien Byakombe)** in Vanier (Ottawa), Canada.
