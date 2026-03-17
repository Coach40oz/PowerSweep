# PowerSweep 4.1

PowerSweep is an advanced PowerShell network discovery and security assessment tool designed to provide comprehensive network scanning capabilities with an enhanced, intuitive console interface.

## 🔆 What's New in Version 4.1

- **Scan Profiles**: One-click presets (Quick, Full, Security) for common scan scenarios
- **Custom Port Scanning**: Scan any ports you want with comma-separated lists
- **JSON Export**: Export results in JSON format for easy integration with other tools
- **Configuration Save/Load**: Save your preferred settings and load them instantly
- **Result Filtering**: Filter scan results by device type, port, or hostname
- **Scan Comparison**: Compare current scan with previous results to track network changes
- **Improved Menu**: Reorganized menu with cleaner layout and better grouping

## 🔆 What's New in Version 4.0

- **Enhanced GUI**: Beautiful console interface with info boxes, animated banners, and colored output
- **Real-time Progress**: Advanced progress bars with scan rate and ETA calculation
- **Device Type Detection**: Improved device fingerprinting for more accurate identification
- **HTML Report Generation**: Create beautiful, detailed HTML reports of scan results
- **Vulnerability Assessment**: Enhanced security scanning with severity ratings and references
- **Interactive Menu**: Streamlined, intuitive menu system with improved visual feedback

## 🚀 Features

- **Network Discovery**: Automatically identifies active hosts on your local network
- **Port Scanning**: Detects open ports and maps them to common services (custom or default)
- **Device Fingerprinting**: Identifies device types, operating systems, and roles based on open ports and hostnames
- **Share Discovery**: Discovers open network shares on Windows devices
- **Vulnerability Assessment**: Performs security assessment and provides recommendations
- **Multithreaded Scanning**: Uses PowerShell runspaces for efficient parallel scanning
- **Enhanced UI**: Beautiful console interface with detailed progress and results
- **Scan Profiles**: Quick, Full, and Security presets for different use cases
- **Export Capabilities**: Save scan results as CSV, HTML, or JSON
- **Result Filtering**: Filter results by device type, port number, or hostname pattern
- **Scan Comparison**: Compare scans over time to detect network changes
- **Configuration Persistence**: Save and load scan settings

## 📋 Requirements

- Windows operating system
- PowerShell 5.1 or higher
- Administrator privileges (for full functionality)

## 💻 Installation & Execution

### Direct Execution from GitHub

You can run PowerSweep directly from GitHub with these commands:

#### PowerSweep (Full Version)
```powershell
# Launch PowerShell as Administrator and run:
irm https://raw.githubusercontent.com/Coach40oz/PowerSweep/main/powersweep.ps1 | iex
```

#### PowerSweep Lite (Lightweight Version)
```powershell
# Launch PowerShell as Administrator and run:
irm https://raw.githubusercontent.com/Coach40oz/PowerSweep/main/PowerSweeplite.ps1 | iex
```

### Manual Download and Execution

1. Download both PowerSweep.ps1 and PowerSweeplite.ps1 files to your computer

2. Ensure PowerShell execution policy allows script execution
```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process
```

3. Run the script with administrator privileges
```powershell
powershell -ExecutionPolicy Bypass -File .\PowerSweep.ps1
```

## 📖 How to Use

### Running PowerSweep

1. Launch PowerShell as Administrator
2. Execute using one of the methods above
3. Navigate the menu using the keyboard

### Main Menu Options

PowerSweep offers an intuitive menu interface organized into sections:

**Scan & Configuration:**

| Option | Description |
|--------|-------------|
| S | Start network scan with current settings |
| 1 | Load a scan profile (Quick, Full, or Security) |
| 2 | Change IP range to custom values |
| 3 | Configure timeout and thread count |
| 4 | Set custom ports to scan |

**Feature Toggles:**

| Option | Description |
|--------|-------------|
| T | Toggle port scanning on/off |
| H | Toggle share discovery on/off |
| V | Toggle vulnerability scanning on/off |
| E | Toggle CSV export on/off |
| J | Toggle JSON export on/off |
| P | Change export file path |

**Tools:**

| Option | Description |
|--------|-------------|
| F | Filter last scan results |
| C | Compare with a previous scan |
| X | Save current configuration to file |
| L | Load a saved configuration |

**Other:**

| Option | Description |
|--------|-------------|
| A | About PowerSweep |
| Q | Quit PowerSweep |

### Scan Profiles

PowerSweep 4.1 includes three built-in scan profiles:

| Profile | Timeout | Threads | Ports | Shares | Vulns | Use Case |
|---------|---------|---------|-------|--------|-------|----------|
| **Quick** | 200ms | 100 | No | No | No | Fast ping sweep to see what's online |
| **Full** | 500ms | 50 | Yes (29) | Yes | Yes | Comprehensive network assessment |
| **Security** | 1000ms | 30 | Yes (29) | Yes | Yes | Security audit with extended port list |

### Export Formats

PowerSweep supports three export formats:

- **CSV**: Tabular data for spreadsheets and databases
- **HTML**: Beautiful visual reports with color coding and charts
- **JSON**: Structured data for automation, scripting, and tool integration

### Filtering Results

After running a scan, press `F` to filter results by:

1. **Device type** - Use regex patterns (e.g., `Server`, `Printer`, `Router`)
2. **Open port** - Find hosts with a specific port open (e.g., `443`, `3389`)
3. **Hostname** - Search by hostname pattern (e.g., `web`, `dc-`)

### Comparing Scans

Track network changes over time:

1. Run a scan with JSON export enabled (`J` to toggle)
2. Wait a period of time, then scan again
3. Press `C` and provide the path to the previous JSON file
4. See new hosts, removed hosts, and configuration changes

### Saving & Loading Configuration

- Press `X` to save your current scan settings to a file
- Press `L` to load previously saved settings
- Default location: `~/.powersweep/config.json`

### Example Usage Scenarios

**Quick Network Survey:**
```powershell
# Run PowerSweep
irm https://raw.githubusercontent.com/Coach40oz/PowerSweep/main/powersweep.ps1 | iex
# Press 1, select Quick profile
# Press S to start scanning
```

**Custom Port Scan:**
```powershell
# Run PowerSweep
irm https://raw.githubusercontent.com/Coach40oz/PowerSweep/main/powersweep.ps1 | iex
# Press 4, enter: 22,80,443,3389,8080
# Press S to start scanning
```

**Security Audit with Reports:**
```powershell
# Run PowerSweep
irm https://raw.githubusercontent.com/Coach40oz/PowerSweep/main/powersweep.ps1 | iex
# Press 1, select Security profile
# Press J to enable JSON export
# Press S to start the scan
# When prompted, generate HTML report
# Results saved as HTML + JSON
```

**Track Network Changes Weekly:**
```powershell
# Week 1: Run scan with JSON export
# Week 2: Run scan again, press C to compare with last week's JSON
# See exactly what changed on your network
```

## 📊 Understanding the Output

### Enhanced Device Type Detection

PowerSweep uses multiple techniques to determine device types:

- Port patterns: Identifies common service combinations (e.g., ports 80+443 indicate a web server)
- Hostname analysis: Checks for keywords that indicate device function
- Service fingerprinting: Examines open services to determine OS and device role

### Improved Vulnerability Assessment

The vulnerability scan checks for:

- Insecure protocols: FTP, Telnet, unencrypted HTTP
- Exposed services: RDP, database servers, VNC, printers
- Network shares: Open, potentially unsecured file shares
- Missing encryption: Services that should use encryption but don't
- Multiple high-risk services: Combinations of vulnerable services

Each finding includes:
- Severity rating (High, Medium, Low)
- Description of the issue
- Specific recommendation to address the vulnerability
- Industry standards and reference information

### Color Coding

PowerSweep uses color to help identify important information:

- Green: IP addresses, successful operations
- Red: High severity issues, errors
- Yellow: Medium severity issues, warnings
- Cyan: System information, headings
- Magenta: Network devices, section titles
- Blue: Windows systems
- White: General information

## 🛠️ Advanced Features

### Visual Progress Tracking

The progress bar provides:
- Percentage completion
- Scan rate (IPs/second)
- Estimated time remaining
- Visual indicator of progress

### Real-time Discovery Notifications

As hosts are discovered, PowerSweep immediately displays:
- Device IP and hostname
- Color-coded device type
- Response time

### Default Port List

PowerSweep scans these common ports by default (or use option 4 to set custom ports):

20, 21, 22, 23, 25, 53, 80, 88, 110, 123, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1434, 3306, 3389, 5900, 8080, 8443, 9100

The Security profile adds: 1521, 5432, 5985, 5986, 6379, 27017

### Thread Management

Adjust the thread count based on your system's capabilities:
- Higher thread counts = faster scanning but more resource usage
- Lower thread counts = slower scanning but less system impact

## ⚠️ Known Issues

- **HTML Report IP Formatting**: Some IP addresses may not display correctly in the HTML report. This is a known issue that will be addressed in a future update.
- **MAC Address Detection**: Requires administrator privileges; will show as "Unknown" otherwise.
- **Share Discovery**: May not work on non-Windows devices or without proper authentication.
- **Device Type Detection Accuracy**: May incorrectly identify devices with unusual port configurations.
- **Large Network Scanning**: Very large networks (>10,000 hosts) may experience memory pressure during scanning.

## 🔒 Security Note

This tool is intended for legitimate network administration and security assessment. Always ensure you have proper authorization before scanning networks that you don't own or manage.

## ✅ Troubleshooting

- **CSV/HTML/JSON Export Issues**: If you encounter problems exporting to the Desktop, the script will offer to save to Documents instead.
- **No Devices Found**: Check network connectivity and firewall settings. Try increasing the timeout value.
- **Slow Scanning**: Reduce thread count to lower system impact or increase it to speed up scanning.
- **Error Messages**: Most "Connection Failed" messages are normal and indicate hosts are not active or are blocking scans.
- **Missing Device Types**: The script uses multiple detection methods; however, some devices may not be identifiable based on available information.
- **Config Not Loading**: Ensure the config file is valid JSON. Delete `~/.powersweep/config.json` to reset.

# PowerSweep Lite

PowerSweep Lite is a minimal, lightweight network scanner for quickly discovering devices on your network. It focuses solely on finding active hosts without any of the advanced features of the full PowerSweep tool.

## Features

- **Simplified Network Discovery**: Finds active hosts on your network with minimal overhead
- **Basic Device Identification**: Identifies common device types based on hostname patterns
- **Multithreaded Scanning**: Fast parallel processing for quick results
- **Clean Visual Interface**: Colorful, easy-to-read console output
- **Direct Result Display**: Shows results in a simple table format

## Installation & Usage

Run directly from GitHub:
```powershell
# Launch PowerShell as Administrator and run:
irm https://raw.githubusercontent.com/Coach40oz/PowerSweep/main/PowerSweeplite.ps1 | iex
```

Or download and execute:
1. Download the PowerSweep-Lite.ps1 file
2. Run PowerShell as Administrator (recommended)
3. Navigate to the directory containing the script
4. Execute: `.\PowerSweep-Lite.ps1`

## Key Differences from PowerSweep Full

- **Focused Functionality**: Only performs basic network discovery
- **No Port Scanning**: Doesn't scan for open ports
- **No Share Discovery**: Doesn't attempt to discover network shares
- **No Vulnerability Assessment**: No security checks performed
- **No Export Functionality**: Results are displayed directly in the console
- **Simplified Menu**: Only includes essential options

## License

This tool is released under the MIT License.

## Author

- **Ulises Paiz** - Initial work and development

---

MIT License

Copyright (c) 2025 Ulises Paiz

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
