# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A single PowerShell deployment script, `osdcloud-test-v1.ps1`, that uses the [OSD module](https://www.osdcloud.com) (`Start-OSDCloud`) to do a zero-touch install of Windows 11 22H2 Enterprise en-US (Volume). There is no build, lint or test tooling. The script can only be run for real inside a WinPE/OSDCloud boot environment on target hardware or a VM. It writes to `X:\` and `C:\`, reboots the machine, and wipes the disk.

To check syntax without running it (requires `pwsh`):

```bash
pwsh -NoProfile -Command '$null = [System.Management.Automation.Language.Parser]::ParseFile("osdcloud-test-v1.ps1", [ref]$null, [ref]$e); $e'
```

To lint it, if PSScriptAnalyzer is installed:

```bash
pwsh -NoProfile -Command 'Invoke-ScriptAnalyzer -Path osdcloud-test-v1.ps1'
```

## Architecture: one file, several boot phases

The file runs in **WinPE**, and most of its body is here-strings (`@' ... '@`) that it writes to `C:\Windows\Setup\Scripts\`, where they run later during **OOBE**. When editing, work out which phase a line runs in:

1. **WinPE (runs directly):** sets env vars and TLS 1.2, warns if not on AC power, then calls `Start-OSDCloud -ZTI ...` (OS selection lives here). It records the start time and version as `key=value` lines in `X:\OSDCloud\preset.txt` and `C:\OSDCloud\set.txt`. It also exports WinPE WiFi profiles as XML into `C:\Windows\Setup\Scripts`. Finally it runs `wpeutil reboot`.
2. **Generated `oobe.cmd`:** the OOBE entry point. It chains `wifi.ps1`, then `ps.ps1` (Windows PowerShell), then `VcRedist.ps1` and `oobe.ps1` (both under `pwsh`).
3. **Generated `ps.ps1`:** installs PowerShell 7 via `aka.ms/install-powershell.ps1` in a job with a 300 s timeout, and reboots on failure.
4. **Generated `oobe.ps1` (PowerShell 7):** installs the OSD and PSWindowsUpdate modules and applies registry tweaks (Wi-Fi Sense, Teams Chat). It removes the provisioned Appx packages in `$appname`, adds the NetFX capabilities and disables PowerShell 2.0. It then installs driver updates, then software updates, logging to `C:\OSDCloud\*.log`. After that it gathers device and deployment facts and posts them as a Teams MessageCard to `$uri`. Last, it cleans up `C:\Drivers`, `C:\Intel` and `C:\OSDCloud` plus the setup scripts, and restarts.

Things that cut across phases:
- **Debug flags are per phase.** `$OSDDEBUG` is `"True"` in the WinPE part but hard-coded `"False"` inside the `oobe.ps1` here-string. It controls `$ErrorActionPreference`, whether the cleanup runs, and whether Shift+F10 is disabled (`DisableCMDRequest.TAG`; creating the tag is currently commented out). `$OOBESHIFTF10` in `oobe.ps1` decides whether the `.TAG` file survives cleanup.
- **Handing data to OOBE:** `oobe.ps1` reads `set.txt` and `preset.txt` with `ConvertFrom-StringData`. It reads the keys `Version`, `Started` and `USBOwner`. Keep these files in `key=value` form.
- **Single quotes matter:** the here-strings use `@' '@`, so `$variables` inside them are **not** expanded at WinPE time. They are resolved when the generated script runs. Don't switch them to `@" "@` without escaping.
- Generated files are written with `-Encoding ascii`. Avoid non-ASCII characters inside the here-strings.

## Known gaps in the current script

These are left as they are on purpose, so check with the user before "fixing" them:
- `oobe.cmd` calls `wifi.ps1` and `VcRedist.ps1`, but the script never generates either one. (`Install-Module VcRedist` runs in WinPE, but no `VcRedist.ps1` is written.)
- `$uri` (the Teams webhook) is commented out, and `$pc` (the card title) is never set. As a result, the `Invoke-RestMethod` post fails.
- The Teams Chat registry paths use `HKLM\...` instead of `HKLM:\...`.
- `oobe.cmd` contains PowerShell-style lines (`#` comments, `Start-Sleep`) that `cmd.exe` doesn't understand.
- `README.md` is empty.
