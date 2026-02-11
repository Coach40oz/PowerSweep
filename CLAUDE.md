# CLAUDE.md - PowerSweep

## Project Overview

PowerSweep is a PowerShell-based network discovery and security assessment tool for Windows environments. It provides multi-threaded network scanning, device fingerprinting, vulnerability assessment, and report generation through an interactive console UI.

- **Author:** Ulises Paiz
- **License:** MIT
- **Requirements:** Windows OS, PowerShell 5.1+, Administrator privileges
- **No external dependencies** — uses only built-in .NET/PowerShell modules

## Repository Structure

```
PowerSweep/
├── powersweep.ps1       # Full version (v4.0) — 2,184 lines
├── PowerSweeplite.ps1   # Lite version (v1.1) — 953 lines
└── README.md            # User-facing documentation
```

There are no subdirectories, build systems, package managers, CI/CD pipelines, or test frameworks. The project consists of standalone PowerShell scripts that run directly.

## Key Files

### powersweep.ps1 (Full Version)

The main tool with all features. Functions organized by purpose:

**UI/Display:** `Show-InfoBox`, `Show-ProgressBar`, `Show-AnimatedBanner`, `Show-ResultSummary`, `Show-Menu`

**Network Discovery:** `Get-LocalNetworkInfo` (collects local config, calculates subnet ranges), `Scan-Network` (core multi-threaded scanner using PowerShell runspaces), `Get-DeviceType` (fingerprints devices via port signatures and hostname patterns)

**Security Assessment:** `Scan-Vulnerabilities` (checks for insecure protocols, exposed services, misconfigurations with severity ratings), `Export-HtmlReport` (generates interactive HTML reports with embedded CSS)

### PowerSweeplite.ps1 (Lite Version)

Simplified subset — core network discovery only, no port scanning, no vulnerability assessment, no HTML reports. Shares the same UI components (`Show-InfoBox`, `Show-ProgressBar`) and `Get-LocalNetworkInfo`/`Scan-Network` (simplified).

## Execution Flow

1. Display animated banner
2. Check administrator privileges (required)
3. Gather local network information
4. Enter interactive menu loop for scan configuration
5. Execute multi-threaded network scan
6. Display results, vulnerabilities, and summary
7. Optionally export HTML report or CSV
8. Return to menu or exit

## Code Conventions

- **Function naming:** PascalCase with Verb-Noun pattern (PowerShell standard)
- **Variable naming:** PascalCase for local variables, UPPERCASE for global variables
- **Global state:** `$Global:NetworkInfo` stores persistent scan parameters
- **Parameters:** Typed declarations with `[Parameter(Mandatory)]` attributes and default values
- **Error handling:** Try-catch blocks around network operations with graceful fallbacks
- **Output:** `Write-Host` with `-ForegroundColor` for color-coded console output
- **Collections:** `ArrayList` for dynamic result storage; hashtables for mappings and configuration
- **Console UI:** Unicode box-drawing characters (`┌─┐ │ └─┘`) for bordered displays
- **Threading:** `[runspacefactory]::CreateRunspacePool()` for parallel IP scanning (configurable 1–100 threads)

## Architecture Patterns

**Runspace Pool Pattern:** Each IP address gets its own runspace for concurrent scanning. Results are collected in an `ArrayList` and polled for completion. This is the core performance mechanism.

**Port Signature Detection:** Maps combinations of open ports to device types (e.g., ports 80+443 → web server, port 3389 → Windows RDP). Approximately 28 common ports scanned per host.

**Device Fingerprinting:** Two-pass identification — first by port signature, then by hostname pattern matching (30+ patterns for routers, printers, cameras, IoT devices, etc.).

**Vulnerability Assessment:** Checks for 15+ vulnerability types with severity ratings (High/Medium/Low), references to industry standards (NIST, CIS, PCI DSS, CVE), and actionable recommendations.

## Running the Scripts

```powershell
# Local execution (requires admin)
powershell -ExecutionPolicy Bypass -File .\powersweep.ps1

# Direct from GitHub
irm https://raw.githubusercontent.com/Coach40oz/PowerSweep/main/powersweep.ps1 | iex
```

Both scripts require `#Requires -RunAsAdministrator`.

## Development Notes

- No build step required — edit `.ps1` files directly
- No test suite exists — changes should be manually verified
- No linting configuration — follow existing PowerShell conventions in the codebase
- The full and lite versions share some function implementations but are maintained as independent files (no shared module extraction)
- Heavy use of color output (381+ `Write-Host` color calls) — maintain color consistency when adding new output
- When modifying `Scan-Network`, be careful with runspace lifecycle management (creation, polling, cleanup) to avoid resource leaks
