# PowerSweep 4.0

PowerSweep is an advanced PowerShell network discovery and security assessment tool designed to provide comprehensive network scanning capabilities with an enhanced, intuitive console interface.

## 🔆 What's New in Version 4.0

- **Enhanced GUI**: Beautiful console interface with info boxes, animated banners, and colored output
- **Real-time Progress**: Advanced progress bars with scan rate and ETA calculation
- **Device Type Detection**: Improved device fingerprinting for more accurate identification
- **HTML Report Generation**: Create beautiful, detailed HTML reports of scan results
- **Vulnerability Assessment**: Enhanced security scanning with severity ratings and references
- **Interactive Menu**: Streamlined, intuitive menu system with improved visual feedback

## 🚀 Features

- **Network Discovery**: Automatically identifies active hosts on your local network
- **Port Scanning**: Detects open ports and maps them to common services
- **Device Fingerprinting**: Identifies device types, operating systems, and roles based on open ports and hostnames
- **Share Discovery**: Discovers open network shares on Windows devices
- **Vulnerability Assessment**: Performs security assessment and provides recommendations
- **Multithreaded Scanning**: Uses PowerShell runspaces for efficient parallel scanning
- **Enhanced UI**: Beautiful console interface with detailed progress and results
- **Export Capabilities**: Save scan results as CSV or HTML for detailed analysis

## 📋 Requirements

- Windows operating system
- PowerShell 5.1 or higher
- Administrator privileges (for full functionality)

## 💻 Installation

1. Download both PowerSweep.ps1 and PowerSweeplite.ps1 files to your computer

2. Ensure PowerShell execution policy allows script execution
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process

3. Run the script with administrator privileges
powershell -ExecutionPolicy Bypass -File .\PowerSweep.ps1


## 📖 How to Use

### Running PowerSweep

1. Launch PowerShell as Administrator
2. Navigate to the directory containing PowerSweep.ps1
3. Run the script:

### Main Menu Options

PowerSweep offers an intuitive menu interface with the following configuration options:

| Option | Description |
|--------|-------------|
| 1. IP Range | Set the range of IP addresses to scan |
| 2. Timeout | Adjust connection timeout in milliseconds (100-5000) |
| 3. Thread Count | Set the number of concurrent threads (1-100) |
| 4. Scan Ports | Enable/disable port scanning |
| 5. Find Shares | Enable/disable network share discovery |
| 6. Vuln Scan | Enable/disable vulnerability assessment |
| 7. Export | Enable/disable export to CSV |
| 8. Export Path | Set the path for exporting results |
| S. Start Scan | Begin scanning with current settings |
| Q. Quit | Exit PowerSweep |

### New HTML Reports

PowerSweep 4.0 introduces beautiful HTML report generation:

- After each scan, you'll be prompted to create an HTML report
- Reports include detailed device information, vulnerability findings, and statistics
- Fully responsive design works on any device or browser
- Color-coded results for quick visual analysis
- Can be shared with team members or included in documentation

### Understanding Scan Results

PowerSweep provides results in several sections:

1. **Network Discovery Output**: Lists all discovered hosts with:
   - IP Address
   - Hostname (if available)
   - Device type
   - Response time
   - Open ports and services
   - Available shares

2. **Results Summary**: Overview of findings including:
   - Device types detected
   - Common services found
   - Hosts with open shares

3. **Vulnerability Assessment** (if enabled): Security analysis including:
   - Potentially insecure protocols
   - Exposed services
   - Security recommendations with severity ratings
   - Industry-standard references (CIS, NIST, CVE, etc.)

### Example Usage Scenarios

**Quick Network Survey:**
# Default settings will scan your local subnet
.\PowerSweep.ps1
# Press S to start scanning


**Scan Specific IP Range:**
.\PowerSweep.ps1
# Select option 1, then enter 'C' for custom range
# Enter start IP: 192.168.1.1
# Enter end IP: 192.168.1.50
# Press S to start scanning

**Security Audit with HTML Report:**

.\PowerSweep.ps1
# Ensure options 4, 5, 6 (ports, shares, vulnerabilities) are enabled
# Press S to start the scan
# When prompted, select Y to generate HTML report
# Results will be saved as an interactive HTML page

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

The new progress bar provides:
- Percentage completion
- Scan rate (IPs/second)
- Estimated time remaining
- Visual indicator of progress

### Real-time Discovery Notifications

As hosts are discovered, PowerSweep immediately displays:
- Device IP and hostname
- Color-coded device type
- Response time

### Custom Port Scanning

PowerSweep scans common ports by default (21, 22, 23, 25, 53, 80, 88, 110, 123, 135, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 1434, 3306, 3389, 5900, 8080, 8443, 9100).

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

- **CSV/HTML Export Issues**: If you encounter problems exporting to the Desktop, the script will offer to save to Documents instead.
- **No Devices Found**: Check network connectivity and firewall settings. Try increasing the timeout value.
- **Slow Scanning**: Reduce thread count to lower system impact or increase it to speed up scanning.
- **Error Messages**: Most "Connection Failed" messages are normal and indicate hosts are not active or are blocking scans.
- **Missing Device Types**: The script uses multiple detection methods; however, some devices may not be identifiable based on available information.

# PowerSweep Lite

PowerSweep Lite is a minimal, lightweight network scanner for quickly discovering devices on your network. It focuses solely on finding active hosts without any of the advanced features of the full PowerSweep tool.

## Features

- **Simplified Network Discovery**: Finds active hosts on your network with minimal overhead
- **Basic Device Identification**: Identifies common device types based on hostname patterns
- **Multithreaded Scanning**: Fast parallel processing for quick results
- **Clean Visual Interface**: Colorful, easy-to-read console output
- **Direct Result Display**: Shows results in a simple table format

## Installation & Usage

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
