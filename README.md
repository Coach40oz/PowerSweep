# PowerSweep
[License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**PowerSweep** is an advanced PowerShell network discovery tool designed to provide comprehensive network scanning capabilities. It serves as a robust alternative to tools like Advanced IP Scanner or Angry IP Scanner, but with the flexibility and scriptability of PowerShell.

Features

- **Network Range Detection**: Automatically detects your network range and subnet mask
- **Fast Multithreaded Scanning**: Scans thousands of IP addresses quickly using PowerShell runspaces
- **Port Scanning**: Identifies open ports and services on discovered devices
- **Device Type Detection**: Attempts to identify device types based on ports and hostname patterns
- **Network Share Discovery**: Discovers available shares on network devices
- **MAC Address Resolution**: Displays MAC addresses for discovered devices
- **Colorful CLI Interface**: Easy-to-read, color-coded terminal output
- **Export Capabilities**: Export results to CSV for further analysis

Requirements

- Windows 7/Server 2008 R2 or newer
- PowerShell 5.1 or newer
- Administrative privileges (for full functionality)


 Usage

Basic Usage

Simply run the script, and it will detect your network information and present a menu:

PowerSweep.ps1


Menu Options

1. **IP Range**: Customize the IP range to scan
2. **Timeout**: Adjust connection timeout (in milliseconds)
3. **Thread Count**: Control the number of simultaneous scanning threads
4. **Scan Ports**: Toggle port scanning on/off
5. **Discover Shares**: Toggle network share discovery on/off
6. **Export Results**: Toggle CSV export on/off
7. **Export Path**: Customize the export file path (when export is enabled)

Scanning Commands

- **S**: Start scan with current settings
- **Q**: Quit the application

Advanced Usage

Scan Only a Specific Range

You can select option 1 from the menu and specify a custom IP range:

1. IP Range: 192.168.1.1 to 192.168.1.254

Increase Performance

For faster scanning:
1. Reduce timeout to 300ms (option 2)
2. Increase thread count to 75-100 (option 3)
3. Disable port scanning if not needed (option 4)

Understanding Results

The tool categorizes devices into types like:
- Router/Gateway
- Windows Device
- Linux/Unix Device
- Web Server
- Printer
- Media Device
- IP Camera
- Mobile Device

Troubleshooting

Permission Issues

If you encounter permission issues:

[WARNING] This script is not running with administrator privileges.
Some features like MAC address detection and share discovery may not work properly.


Right-click on PowerShell and select "Run as Administrator".

Slow Scanning

If scanning is too slow:
1. Reduce the IP range
2. Lower the timeout value
3. Disable port scanning or share discovery
4. Increase thread count (if on a powerful system)

Contributing

Contributions are welcome! Feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

License

This project is licensed under the MIT License

Acknowledgements

- Inspired by tools like Advanced IP Scanner and Angry IP Scanner
- Built with PowerShell for maximum flexibility and scriptability

Author

**Ulises Paiz** 

---

Made with ❤️ and PowerShell
