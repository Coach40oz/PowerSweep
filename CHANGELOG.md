# Changelog

All notable changes to PowerSweep will be documented in this file.

## [4.1] - 2026-02-11

### Fixed
- **CSV/HTML export bug**: Scan results were wrapped in PSDataCollection objects from runspace EndInvoke(), causing Export-Csv and HTML reports to export metadata instead of actual scan data. Results are now properly unwrapped.
- **Device type detection in full version**: `Get-DeviceType` was defined outside the runspace scriptblock but called inside it. Runspaces are isolated and cannot access parent-scope functions. The function is now embedded directly in the scriptblock.
- **HTML report missing table closing tag**: When no vulnerabilities were found, the hosts `<table>` element was never closed, producing malformed HTML.
- **Same EndInvoke unwrapping bug in PowerSweep Lite**: Applied the same fix to the lite version.

### Added
- **CLI parameters for non-interactive use**: New parameters `-Target`, `-Threads`, `-Timeout`, `-Ports`, `-OutputCsv`, `-OutputHtml`, `-OutputJson`, `-NoPorts`, `-NoShares`, `-NoVuln`, `-NonInteractive` allow scripted/automated scanning without the interactive menu.
- **JSON export**: New `Export-JsonReport` function generates structured JSON reports with metadata, host details, and vulnerability findings. Available in both interactive menu and CLI mode.
- **Configurable port list**: Custom ports can be specified via the `-Ports` CLI parameter or the new "R. Configure Port List" menu option. Defaults to 29 common ports when not specified.
- **Port configuration menu item**: New "R" option in the interactive menu to set custom port lists.
- **Pester test suite**: Unit tests for `Get-DeviceType`, `Scan-Vulnerabilities`, `Export-JsonReport`, and parameter validation in `tests/PowerSweep.Tests.ps1`.
- **GitHub Actions CI**: Automated PSScriptAnalyzer linting and Pester test execution on push and pull request.
- **PSScriptAnalyzer configuration**: `PSScriptAnalyzerSettings.psd1` with rules tuned for this project (Write-Host allowed, approved verbs not enforced).
- **EditorConfig**: `.editorconfig` for consistent formatting across editors.

## [4.0] - 2025

### Added
- Multi-threaded network scanning with configurable thread count
- Port scanning with 29 common ports and service identification
- Device type fingerprinting by port signatures and hostname patterns
- Vulnerability assessment with severity ratings and industry references
- Interactive HTML report generation with embedded CSS
- CSV export with numerical IP sorting
- Enhanced console UI with Unicode borders, progress bars, and color coding
- Network share discovery and enumeration
- Animated ASCII art banner

## [1.1 Lite] - 2025

### Added
- Lightweight version with core network discovery
- Basic device type detection by hostname
- Simplified interactive menu
- Console table output with progress tracking
