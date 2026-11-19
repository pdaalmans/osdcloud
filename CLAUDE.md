# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

This repo is the start of a platform for managing OSDCloud deployments for customers. It should cover three things:

1. **OSDCloud PowerShell scripts:** the startup and deployment scripts run during WinPE and OOBE, kept under version control.
2. **The OSDCloud workspace:** the template and workspace configuration (drivers, wallpaper, startup script, Wi-Fi profiles, cloud/offline OS sources) that boot media are built from.
3. **Boot image builds:** WinPE/WinRE boot images and USB media for customers, built repeatably from the scripts and workspace above.

**Nothing about the platform is decided yet:** not the language, the layout, whether it is a CLI, a web UI or a CI pipeline, or how customers are separated. Don't assume an architecture or create scaffolding for one. If a task depends on one of these choices, ask the user. Record decisions in this file once they're made.

## Current state

- The only code is `osdcloud-test-v1.ps1`, an early experiment. Treat it as a reference for the kind of WinPE/OOBE logic the platform must handle, not as a base to build on or something to polish.
- There is no build, lint or test tooling yet.

## Domain constraints that shape any design

- Media is built with the PowerShell **OSD module**. Typical flow: `New-OSDCloudTemplate` (add `-WinRE` for a WinRE-based image with Wi-Fi support) → `New-OSDCloudWorkspace` → `Edit-OSDCloudWinPE` (drivers, startup script/URL, wallpaper) → `New-OSDCloudISO` / `New-OSDCloudUSB` / `Update-OSDCloudUSB`.
- Building images needs **Windows** with the Windows ADK and the WinPE add-on, usually running elevated. This Linux container can't build or test images, so image builds will need a Windows host or runner.
- Scripts run in several stages: WinPE first (on the `X:` RAM drive), then OOBE on the installed OS, often under Windows PowerShell 5.1 before PowerShell 7 exists. Code meant for a later stage is often written to disk as a here-string during an earlier one. Be explicit about which stage and which PowerShell version a piece of code targets.
- Customer media will differ per customer (drivers, Wi-Fi, Teams webhooks and other endpoints, branding). Never commit customer secrets such as Wi-Fi keys or webhook URLs. Keep them out of the scripts as parameters or config.
