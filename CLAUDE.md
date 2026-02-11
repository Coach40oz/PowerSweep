# CLAUDE.md - PowerSweep

## Project Overview

PowerSweep is a PowerShell-based network discovery and security assessment tool for Windows environments. It provides multi-threaded network scanning, device fingerprinting, vulnerability assessment, and report generation through both an interactive console UI and CLI parameters.

- **Author:** Ulises Paiz
- **License:** MIT
- **Requirements:** Windows OS, PowerShell 5.1+, Administrator privileges
- **No external dependencies** — uses only built-in .NET/PowerShell modules

## Repository Structure

```
PowerSweep/
├── powersweep.ps1                  # Full version (v4.1)
├── PowerSweeplite.ps1              # Lite version (v1.1)
├── README.md                       # User-facing documentation
├── CHANGELOG.md                    # Version history
├── CLAUDE.md                       # This file
├── .editorconfig                   # Editor formatting rules
├── PSScriptAnalyzerSettings.psd1   # Linting configuration
├── tests/
│   └── PowerSweep.Tests.ps1       # Pester unit tests
└── .github/
    └── workflows/
        └── ci.yml                  # GitHub Actions CI pipeline
```

## Key Files

### powersweep.ps1 (Full Version)

The main tool with all features. Supports both interactive menu mode and non-interactive CLI mode.

**CLI Parameters:** `-Target`, `-Threads`, `-Timeout`, `-Ports`, `-OutputCsv`, `-OutputHtml`, `-OutputJson`, `-NoPorts`, `-NoShares`, `-NoVuln`, `-NonInteractive`

**UI/Display:** `Show-InfoBox`, `Show-ProgressBar`, `Show-AnimatedBanner`, `Show-ResultSummary`, `Show-Menu`

**Network Discovery:** `Get-LocalNetworkInfo` (collects local config, calculates subnet ranges), `Scan-Network` (core multi-threaded scanner using PowerShell runspaces), `Get-DeviceType` (fingerprints devices via port signatures and hostname patterns)

**Security Assessment:** `Scan-Vulnerabilities` (checks for insecure protocols, exposed services, misconfigurations with severity ratings)

**Export:** `Export-HtmlReport` (interactive HTML reports with embedded CSS), `Export-JsonReport` (structured JSON with metadata, hosts, vulnerabilities)

### PowerSweeplite.ps1 (Lite Version)

Simplified subset — core network discovery only, no port scanning, no vulnerability assessment, no exports. Shares the same UI components (`Show-InfoBox`, `Show-ProgressBar`) and `Get-LocalNetworkInfo`/`Scan-Network` (simplified).

## Running the Scripts

```powershell
# Interactive mode (requires admin)
powershell -ExecutionPolicy Bypass -File .\powersweep.ps1

# Non-interactive CLI mode
powershell -ExecutionPolicy Bypass -File .\powersweep.ps1 -Target "192.168.1.1-192.168.1.254" -OutputJson report.json -OutputHtml report.html

# Custom ports
powershell -ExecutionPolicy Bypass -File .\powersweep.ps1 -Target "10.0.0.1-10.0.0.50" -Ports "22,80,443,3389" -OutputCsv scan.csv
```

Both scripts require `#Requires -RunAsAdministrator`.

## Development Workflow

### Testing

```powershell
# Install Pester if not present
Install-Module -Name Pester -Force -Scope CurrentUser -MinimumVersion 5.0

# Run tests
Invoke-Pester ./tests -Output Detailed
```

Tests cover: `Get-DeviceType` (port/hostname-based detection), `Scan-Vulnerabilities` (detection of insecure protocols, exposed services), `Export-JsonReport` (valid JSON generation), and script parameter validation.

### Linting

```powershell
# Install PSScriptAnalyzer if not present
Install-Module -Name PSScriptAnalyzer -Force -Scope CurrentUser

# Lint
Invoke-ScriptAnalyzer -Path ./powersweep.ps1 -Settings ./PSScriptAnalyzerSettings.psd1
Invoke-ScriptAnalyzer -Path ./PowerSweeplite.ps1 -Settings ./PSScriptAnalyzerSettings.psd1
```

### CI

GitHub Actions runs PSScriptAnalyzer and Pester tests on push/PR to master.

## Code Conventions

- **Function naming:** PascalCase with Verb-Noun pattern (PowerShell standard)
- **Variable naming:** PascalCase for local variables, UPPERCASE for global variables
- **Global state:** `$Global:NetworkInfo` stores persistent scan parameters
- **Parameters:** Typed declarations with `[Parameter(Mandatory)]` attributes and default values
- **Error handling:** Try-catch blocks around network operations with graceful fallbacks
- **Output:** `Write-Host` with `-ForegroundColor` for color-coded console output
- **Collections:** `ArrayList` for dynamic result storage; hashtables for mappings and configuration
- **Console UI:** Unicode box-drawing characters for bordered displays
- **Threading:** `[runspacefactory]::CreateRunspacePool()` for parallel IP scanning (configurable 1–100 threads)

## Architecture Patterns

**Runspace Pool Pattern:** Each IP address gets its own runspace for concurrent scanning. Results are collected in an `ArrayList` and polled for completion. **Critical:** Functions used inside runspace scriptblocks must be defined *inside* the scriptblock — runspaces cannot access parent-scope functions. Results from `EndInvoke()` return `PSDataCollection<PSObject>` and must be unwrapped (e.g., `$endResult[0]`) before use.

**Port Signature Detection:** Maps combinations of open ports to device types (e.g., ports 80+443 → web server, port 3389 → Windows RDP). Default 29 common ports, configurable via `-Ports` parameter or menu.

**Device Fingerprinting:** Two-pass identification — first by port signature, then by hostname pattern matching (30+ patterns for routers, printers, cameras, IoT devices, etc.).

**Vulnerability Assessment:** Checks for 15+ vulnerability types with severity ratings (High/Medium/Low), references to industry standards (NIST, CIS, PCI DSS, CVE), and actionable recommendations.

## Development Notes

- No build step required — edit `.ps1` files directly
- The full and lite versions are maintained as independent standalone files (single-file distribution model for one-liner GitHub downloads)
- Heavy use of color output — maintain color consistency when adding new output
- When modifying `Scan-Network`, be careful with: (1) runspace lifecycle management, (2) keeping functions embedded in the scriptblock, (3) unwrapping `EndInvoke()` results
- PSScriptAnalyzer settings suppress `PSAvoidUsingWriteHost` and `PSUseApprovedVerbs` since Write-Host is intentional for the UI and `Scan-*` verbs are used throughout
