#requires -RunAsAdministrator
<#
.SYNOPSIS
    PowerSweep Lite - Simple PowerShell Network Scanner
.DESCRIPTION
    A lightweight network scanning tool that discovers active hosts on the network.
.NOTES
    Author: Ulises Paiz
    Version: 1.0 (Lite)
    License: GNU GPL v3 - https://www.gnu.org/licenses/gpl-3.0.en.html
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.
#>

function Get-LocalNetworkInfo {
    Write-Host "`n═════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "           LOCAL NETWORK INFORMATION           " -ForegroundColor Yellow
    Write-Host "═════════════════════════════════════════════`n" -ForegroundColor Cyan
    
    $networkInfo = Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}
    
    foreach ($adapter in $networkInfo) {
        # Calculate subnet mask in dotted decimal format
        $prefixLength = $adapter.IPv4Address.PrefixLength
        $subnetMaskInt = [UInt32]([UInt32]::MaxValue -shl (32 - $prefixLength))
        $subnetMaskBytes = [BitConverter]::GetBytes($subnetMaskInt)
        [Array]::Reverse($subnetMaskBytes)
        $subnetMaskDotted = [IPAddress]$subnetMaskBytes
        
        Write-Host "`n═════════════════ YOUR MACHINE ═════════════════" -ForegroundColor Yellow
        Write-Host "Interface: " -NoNewline -ForegroundColor Cyan
        Write-Host "$($adapter.InterfaceAlias)" -ForegroundColor White
        
        Write-Host "YOUR IP ADDRESS: " -NoNewline -ForegroundColor Green -BackgroundColor Black
        Write-Host "$($adapter.IPv4Address.IPAddress)" -ForegroundColor White -BackgroundColor DarkGreen
        
        Write-Host "CIDR Prefix: " -NoNewline -ForegroundColor Green
        Write-Host "/$($adapter.IPv4Address.PrefixLength)" -ForegroundColor White
        
        Write-Host "SUBNET MASK: " -NoNewline -ForegroundColor Green
        Write-Host "$subnetMaskDotted" -ForegroundColor White -BackgroundColor DarkGreen
        
        Write-Host "Gateway: " -NoNewline -ForegroundColor Magenta
        Write-Host "$($adapter.IPv4DefaultGateway.NextHop)" -ForegroundColor White
        
        Write-Host "DNS Servers: " -NoNewline -ForegroundColor Yellow
        Write-Host "$($adapter.DNSServer | Where-Object {$_.AddressFamily -eq 2} | ForEach-Object {$_.ServerAddresses})" -ForegroundColor White
        
        # Try to get DHCP Server info
        try {
            $dhcpServer = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | 
                Where-Object {$_.Description -eq $adapter.NetAdapter.DriverDescription} | 
                Select-Object -ExpandProperty DHCPServer -ErrorAction SilentlyContinue
            
            Write-Host "DHCP Server: " -NoNewline -ForegroundColor Blue
            Write-Host "$dhcpServer" -ForegroundColor White
        } catch {
            Write-Host "DHCP Server: Unable to retrieve" -ForegroundColor Gray
        }
        
        Write-Host "MAC Address: " -NoNewline -ForegroundColor DarkYellow
        Write-Host "$($adapter.NetAdapter.MacAddress)" -ForegroundColor White
        Write-Host ""
    }
    
    # Calculate network range based on IP and subnet
    $ipAddress = $networkInfo[0].IPv4Address.IPAddress
    $prefixLength = $networkInfo[0].IPv4Address.PrefixLength
    $gateway = $networkInfo[0].IPv4DefaultGateway.NextHop
    
    # Calculate subnet mask from prefix length
    $subnetMaskInt = [UInt32]([UInt32]::MaxValue -shl (32 - $prefixLength))
    $subnetMaskBytes = [BitConverter]::GetBytes($subnetMaskInt)
    [Array]::Reverse($subnetMaskBytes)
    $subnetMask = [IPAddress]$subnetMaskBytes
    
    # Calculate network address
    $ipBytes = ([IPAddress]$ipAddress).GetAddressBytes()
    $maskBytes = $subnetMask.GetAddressBytes()
    
    # Reverse the byte arrays for proper calculation
    [Array]::Reverse($ipBytes)
    [Array]::Reverse($maskBytes)
    
    # Calculate the integer representation of IP
    $ipInt = [BitConverter]::ToUInt32($ipBytes, 0)
    $maskInt = [BitConverter]::ToUInt32($maskBytes, 0)
    
    # Calculate network address int
    $networkInt = $ipInt -band $maskInt
    
    # Convert back to bytes and reverse for IP format
    $networkBytes = [BitConverter]::GetBytes($networkInt)
    [Array]::Reverse($networkBytes)
    $networkAddress = [IPAddress]$networkBytes
    
    # Calculate broadcast address (network + inverse mask)
    $inverseMaskInt = $maskInt -bxor [UInt32]::MaxValue
    $broadcastInt = $networkInt -bor $inverseMaskInt
    
    # Convert back to bytes and reverse for IP format
    $broadcastBytes = [BitConverter]::GetBytes($broadcastInt)
    [Array]::Reverse($broadcastBytes)
    $broadcastAddress = [IPAddress]$broadcastBytes
    
    # Calculate first usable IP (network + 1)
    $firstUsableInt = $networkInt + 1
    $firstUsableBytes = [BitConverter]::GetBytes($firstUsableInt)
    [Array]::Reverse($firstUsableBytes)
    $firstUsableIP = [IPAddress]$firstUsableBytes
    
    # Calculate last usable IP (broadcast - 1)
    $lastUsableInt = $broadcastInt - 1
    $lastUsableBytes = [BitConverter]::GetBytes($lastUsableInt)
    [Array]::Reverse($lastUsableBytes)
    $lastUsableIP = [IPAddress]$lastUsableBytes
    
    # Calculate total usable IPs
    $totalUsableIPs = [Math]::Pow(2, (32 - $prefixLength)) - 2
    
    Write-Host "`n═════════════════ NETWORK RANGE ═════════════════" -ForegroundColor Yellow
    Write-Host "Network Address: " -NoNewline -ForegroundColor Cyan
    Write-Host "$networkAddress" -ForegroundColor White
    Write-Host "Broadcast Address: " -NoNewline -ForegroundColor Cyan
    Write-Host "$broadcastAddress" -ForegroundColor White
    Write-Host "Subnet Mask: " -NoNewline -ForegroundColor Cyan
    Write-Host "$subnetMask" -ForegroundColor White
    Write-Host "First Usable IP: " -NoNewline -ForegroundColor Green
    Write-Host "$firstUsableIP" -ForegroundColor White
    Write-Host "Last Usable IP: " -NoNewline -ForegroundColor Green
    Write-Host "$lastUsableIP" -ForegroundColor White
    Write-Host "Total Usable IPs: " -NoNewline -ForegroundColor Green
    Write-Host "$totalUsableIPs" -ForegroundColor White
    
    # Display a visual indicator showing where your IP is in the range
    $ipAddress = $networkInfo[0].IPv4Address.IPAddress
    Write-Host "`nYour position in network range:" -ForegroundColor Magenta
    Write-Host "  $firstUsableIP " -NoNewline -ForegroundColor Gray
    Write-Host "[" -NoNewline -ForegroundColor Yellow
    
    # Create a simple visual representation of where the IP is in the range
    $ipInt = [BitConverter]::ToUInt32(([IPAddress]$ipAddress).GetAddressBytes(), 0)
    $firstInt = [BitConverter]::ToUInt32($firstUsableBytes, 0)
    $lastInt = [BitConverter]::ToUInt32($lastUsableBytes, 0)
    
    $position = [int](($ipInt - $firstInt) / ($lastInt - $firstInt) * 20)
    $bar = " " * $position + "■" + " " * (19 - $position)
    
    Write-Host $bar -NoNewline -ForegroundColor Green
    Write-Host "] " -NoNewline -ForegroundColor Yellow
    Write-Host "$lastUsableIP" -ForegroundColor Gray
    
    Write-Host "`n═════════════════════════════════════════════`n" -ForegroundColor Cyan
    
    return @{
        FirstIP = $firstUsableIP.ToString()
        LastIP = $lastUsableIP.ToString()
        Gateway = $gateway
    }
}

function Scan-Network {
    param (
        [Parameter(Mandatory=$true)]
        [string]$StartIP,
        
        [Parameter(Mandatory=$true)]
        [string]$EndIP,
        
        [int]$TimeoutMilliseconds = 500,
        
        [int]$MaxThreads = 50
    )
    
    # Convert IP strings to System.Net.IPAddress objects
    $startIPObj = [System.Net.IPAddress]::Parse($StartIP)
    $endIPObj = [System.Net.IPAddress]::Parse($EndIP)
    
    # Convert to integers for enumeration
    $startIPBytes = $startIPObj.GetAddressBytes()
    $endIPBytes = $endIPObj.GetAddressBytes()
    
    # Ensure proper byte order for BitConverter (little-endian)
    [Array]::Reverse($startIPBytes)
    [Array]::Reverse($endIPBytes)
    
    $startIPInt = [BitConverter]::ToUInt32($startIPBytes, 0)
    $endIPInt = [BitConverter]::ToUInt32($endIPBytes, 0)
    
    # Calculate total IPs to scan
    $totalIPs = $endIPInt - $startIPInt + 1
    Write-Host "Preparing to scan " -NoNewline -ForegroundColor White
    Write-Host "$totalIPs " -NoNewline -ForegroundColor Yellow
    Write-Host "IP addresses from " -NoNewline -ForegroundColor White
    Write-Host "$StartIP " -NoNewline -ForegroundColor Green
    Write-Host "to " -NoNewline -ForegroundColor White
    Write-Host "$EndIP" -ForegroundColor Green
    
    # Check if the range is reasonable (prevent huge ranges)
    if ($endIPInt - $startIPInt > 10000) {
        Write-Host "`n[WARNING] Very large IP range detected ($($endIPInt - $startIPInt + 1) addresses)." -ForegroundColor Red
        Write-Host "This may take a very long time to complete." -ForegroundColor Yellow
        $confirm = Read-Host "Continue with this range? (Y/N)"
        if ($confirm -ne "Y" -and $confirm -ne "y") {
            return @()
        }
    }
    
    # Track results
    $results = New-Object System.Collections.ArrayList
    $scanStartTime = Get-Date
    
    # Progress counters
    $totalScanned = 0
    $totalActive = 0
    
    Write-Host "`n[" -NoNewline
    Write-Host "STARTING SCAN" -NoNewline -ForegroundColor Yellow
    Write-Host "] " -NoNewline
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    
    # Create a runspace pool
    $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
    $runspacePool.Open()
    
    # Store all runspaces here
    $runspaces = New-Object System.Collections.ArrayList
    
    # Create scriptblock for runspaces - This is the main scanning function
    $scriptBlock = {
        param (
            [string]$ipAddress,
            [int]$timeout,
            [string]$gateway
        )
        
        # Function to determine basic device type
        function Get-BasicDeviceType {
            param (
                [string]$ip,
                [string]$hostname = "",
                [string]$gw = ""
            )
            
            # Check if it's the gateway
            if ($ip -eq $gw) {
                return "Router/Gateway"
            }
            
            # Basic hostname analysis
            if ($hostname -ne "Unknown" -and $hostname -ne "") {
                $lowercaseHostname = $hostname.ToLower()
                
                if ($lowercaseHostname -match "router|gateway|ap|accesspoint|wifi") {
                    return "Network Device"
                }
                
                if ($lowercaseHostname -match "printer|scanner|mfp") {
                    return "Printer"
                }
                
                if ($lowercaseHostname -match "camera|cam|nvr|dvr") {
                    return "Camera"
                }
                
                if ($lowercaseHostname -match "server|srv") {
                    return "Server"
                }
            }
            
            return "Host"
        }
        
        # Ping the IP to check if it's active
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($ipAddress, $timeout)
        
        if ($reply.Status -eq 'Success') {
            # Try to get hostname
            try {
                $hostname = [System.Net.Dns]::GetHostEntry($ipAddress).HostName
            } catch {
                $hostname = "Unknown"
            }
            
            # Try to get MAC address
            $mac = "Unknown"
            try {
                $arp = arp -a $ipAddress | Select-String $ipAddress
                if ($arp -match '([0-9A-F]{2}[:-]){5}([0-9A-F]{2})') {
                    $mac = $matches[0]
                }
            } catch {
                # Do nothing, keep as "Unknown"
            }
            
            # Determine basic device type
            $deviceType = Get-BasicDeviceType -ip $ipAddress -hostname $hostname -gw $gateway
            
            # Create object with results
            $result = [PSCustomObject]@{
                IPAddress = $ipAddress
                Hostname = $hostname
                MAC = $mac
                Status = "Online"
                ResponseTime = "$($reply.RoundtripTime) ms"
                DeviceType = $deviceType
            }
            
            return $result
        }
        
        return $null
    }
    
    # Loop through each IP in the range
    for ($ipInt = $startIPInt; $ipInt -le $endIPInt; $ipInt++) {
        # Convert integer back to IP address
        $bytes = [BitConverter]::GetBytes($ipInt)
        [Array]::Reverse($bytes)
        $currentIP = [System.Net.IPAddress]::new($bytes).ToString()
        
        # Create a PowerShell instance with needed parameters
        $powershell = [powershell]::Create().AddScript($scriptBlock)
        $powershell.AddParameter("ipAddress", $currentIP)
        $powershell.AddParameter("timeout", $TimeoutMilliseconds)
        $powershell.AddParameter("gateway", $Global:NetworkInfo.Gateway)
        
        # Add the runspace to the PowerShell instance
        $powershell.RunspacePool = $runspacePool
        
        # Begin invoke and add to runspaces collection
        $handle = $powershell.BeginInvoke()
        [void]$runspaces.Add([PSCustomObject]@{
            PowerShell = $powershell
            Handle = $handle
            IPAddress = $currentIP
            Completed = $false
        })
    }
    
    # Poll runspaces for completion
    do {
        # Check for completed runspaces
        foreach ($runspace in $runspaces | Where-Object { -not $_.Completed }) {
            if ($runspace.Handle.IsCompleted) {
                try {
                    # Get result and safely handle any errors
                    $result = $runspace.PowerShell.EndInvoke($runspace.Handle)
                    
                    # Process result if not null
                    if ($result -ne $null) {
                        [void]$results.Add($result)
                        $totalActive++
                        
                        # Display active host found with colorful output
                        Write-Host ("[{0}/{1}] " -f $totalScanned, $totalIPs) -NoNewline -ForegroundColor Gray
                        Write-Host "Found: " -NoNewline -ForegroundColor White
                        Write-Host "$($result.IPAddress)" -NoNewline -ForegroundColor Green
                        
                        if ($result.Hostname -ne "Unknown") {
                            Write-Host " ($($result.Hostname))" -NoNewline -ForegroundColor Cyan
                        }
                        
                        Write-Host " - " -NoNewline
                        
                        # Color-code device types
                        switch -Regex ($result.DeviceType) {
                            "Server" { Write-Host "$($result.DeviceType)" -ForegroundColor Red }
                            "Router|Gateway|Network" { Write-Host "$($result.DeviceType)" -ForegroundColor Magenta }
                            "Printer" { Write-Host "$($result.DeviceType)" -ForegroundColor DarkYellow }
                            "Camera" { Write-Host "$($result.DeviceType)" -ForegroundColor DarkCyan }
                            default { Write-Host "$($result.DeviceType)" -ForegroundColor White }
                        }
                    }
                }
                catch {
                    Write-Host ("[{0}/{1}] " -f $totalScanned, $totalIPs) -NoNewline -ForegroundColor Gray
                    Write-Host "Error processing IP $($runspace.IPAddress): $($_.Exception.Message)" -ForegroundColor Red
                }
                
                # Clean up
                $runspace.PowerShell.Dispose()
                $runspace.Completed = $true
                $totalScanned++
            }
        }
        
        # Update progress
        $percentComplete = [Math]::Min(100, [Math]::Max(0, [int](($totalScanned / $totalIPs) * 100)))
        
        Write-Progress -Activity "Scanning Network" -Status "Progress: $totalScanned of $totalIPs IPs scanned ($percentComplete%)" -PercentComplete $percentComplete
        
        # Sleep briefly to reduce CPU usage
        Start-Sleep -Milliseconds 100
        
    } while ($runspaces | Where-Object { -not $_.Completed } | Select-Object -First 1)
    
    # Clean up the runspace pool
    $runspacePool.Close()
    $runspacePool.Dispose()
    
    $scanEndTime = Get-Date
    $scanDuration = $scanEndTime - $scanStartTime
    
    Write-Progress -Activity "Scanning Network" -Completed
    
    Write-Host "`n[" -NoNewline
    Write-Host "SCAN COMPLETE" -NoNewline -ForegroundColor Green
    Write-Host "] " -NoNewline
    Write-Host "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    
    Write-Host "Scan Duration: " -NoNewline -ForegroundColor White
    Write-Host "$($scanDuration.Minutes) minutes and $($scanDuration.Seconds) seconds" -ForegroundColor Yellow
    Write-Host "Total IPs Scanned: " -NoNewline -ForegroundColor White
    Write-Host "$totalIPs" -ForegroundColor Yellow
    Write-Host "Active Hosts Found: " -NoNewline -ForegroundColor White
    Write-Host "$totalActive" -ForegroundColor Green
    
    # Display scan results directly
    if ($results.Count -gt 0) {
        Write-Host "`nScan Results:" -ForegroundColor Cyan
        $sortedResults = $results | Sort-Object { 
            $octets = $_.IPAddress -split '\.'
            [int]$octets[0]*16777216 + [int]$octets[1]*65536 + [int]$octets[2]*256 + [int]$octets[3]
        }
        
        $sortedResults | Format-Table -Property @{
            Label = "IP"; Expression = {$_.IPAddress}; Width = 15
        }, @{
            Label = "Hostname"; Expression = {$_.Hostname}; Width = 25; Alignment = "Left"
        }, @{
            Label = "Type"; Expression = {$_.DeviceType}; Width = 15
        }, @{
            Label = "Response"; Expression = {$_.ResponseTime}; Width = 10
        }, @{
            Label = "MAC"; Expression = {$_.MAC}; Width = 18
        } -AutoSize
    } else {
        Write-Host "`nNo active hosts found in the specified range." -ForegroundColor Yellow
    }
    
    return $results
}

function Show-Menu {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$NetworkInfo
    )
    
    $header = @"
    
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║                       POWERSWEEP LITE                             ║
║                Simple Network Discovery Tool                      ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

"@
    
    Write-Host $header -ForegroundColor Cyan
    
    $scanOptions = @{
        ScanRange = "1"
        StartIP = $NetworkInfo.FirstIP
        EndIP = $NetworkInfo.LastIP
        Timeout = 300
        ThreadCount = 50
    }
    
    $menuActive = $true
    
    while ($menuActive) {
        # Create a more visually appealing settings display
        Write-Host "`n┌─────────────────────── " -NoNewline -ForegroundColor Cyan
        Write-Host "CURRENT SETTINGS" -NoNewline -ForegroundColor Yellow
        Write-Host " ───────────────────────┐" -ForegroundColor Cyan
        
        Write-Host "│ " -NoNewline -ForegroundColor Cyan
        Write-Host "1. IP Range     : " -NoNewline -ForegroundColor White
        Write-Host ("{0} to {1}" -f $scanOptions.StartIP, $scanOptions.EndIP) -NoNewline -ForegroundColor Green
        Write-Host " ".PadRight(48 - ($scanOptions.StartIP.Length + $scanOptions.EndIP.Length)) -NoNewline
        Write-Host "│" -ForegroundColor Cyan
        
        Write-Host "│ " -NoNewline -ForegroundColor Cyan
        Write-Host "2. Timeout      : " -NoNewline -ForegroundColor White
        Write-Host "$($scanOptions.Timeout) ms" -NoNewline -ForegroundColor Green
        Write-Host " ".PadRight(48 - ($scanOptions.Timeout.ToString().Length + 3)) -NoNewline
        Write-Host "│" -ForegroundColor Cyan
        
        Write-Host "│ " -NoNewline -ForegroundColor Cyan
        Write-Host "3. Thread Count : " -NoNewline -ForegroundColor White
        Write-Host "$($scanOptions.ThreadCount)" -NoNewline -ForegroundColor Green
        Write-Host " ".PadRight(48 - ($scanOptions.ThreadCount.ToString().Length)) -NoNewline
        Write-Host "│" -ForegroundColor Cyan
        
        Write-Host "└──────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
        
        # Actions menu
        Write-Host "`n┌─────────────────────── " -NoNewline -ForegroundColor Cyan
        Write-Host "ACTIONS" -NoNewline -ForegroundColor Yellow
        Write-Host " ──────────────────────────────┐" -ForegroundColor Cyan
        Write-Host "│ " -NoNewline -ForegroundColor Cyan
        Write-Host "S. Start Scan" -NoNewline -ForegroundColor Green
        Write-Host " ".PadRight(53 - 11) -NoNewline
        Write-Host "│" -ForegroundColor Cyan
        Write-Host "│ " -NoNewline -ForegroundColor Cyan
        Write-Host "Q. Quit" -NoNewline -ForegroundColor Red
        Write-Host " ".PadRight(53 - 6) -NoNewline
        Write-Host "│" -ForegroundColor Cyan
        Write-Host "└──────────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
        
        $choice = Read-Host "`nEnter your choice"
        
        switch -Regex ($choice) {
            "1" {
                $customRange = Read-Host "Use custom IP range? (Y/N) Default: Network Range"
                if ($customRange -eq "Y" -or $customRange -eq "y") {
                    $scanOptions.StartIP = Read-Host "Enter start IP"
                    $scanOptions.EndIP = Read-Host "Enter end IP"
                }
            }
            "2" {
                $scanOptions.Timeout = Read-Host "Enter timeout in milliseconds (100-5000)"
                if (-not [int]::TryParse($scanOptions.Timeout, [ref]$null) -or $scanOptions.Timeout -lt 100 -or $scanOptions.Timeout -gt 5000) {
                    $scanOptions.Timeout = 300
                    Write-Host "Invalid input. Reset to default (300ms)" -ForegroundColor Red
                }
            }
            "3" {
                $scanOptions.ThreadCount = Read-Host "Enter thread count (1-100)"
                if (-not [int]::TryParse($scanOptions.ThreadCount, [ref]$null) -or $scanOptions.ThreadCount -lt 1 -or $scanOptions.ThreadCount -gt 100) {
                    $scanOptions.ThreadCount = 50
                    Write-Host "Invalid input. Reset to default (50)" -ForegroundColor Red
                }
            }
            "[Ss]" {
                [void](Scan-Network -StartIP $scanOptions.StartIP -EndIP $scanOptions.EndIP -TimeoutMilliseconds $scanOptions.Timeout -MaxThreads $scanOptions.ThreadCount)
                
                $scanAgain = Read-Host "`nScan again? (Y/N)"
                if ($scanAgain -eq "Y" -or $scanAgain -eq "y") {
                    # Continue in menu
                } else {
                    $menuActive = $false
                }
            }
            "[Qq]" {
                $menuActive = $false
            }
            default {
                Write-Host "Invalid choice. Please try again." -ForegroundColor Red
            }
        }
    }
}

# Main script execution
$banner = @"
                                                                                
 ██████╗  ██████╗ ██╗    ██╗███████╗██████╗ ███████╗██╗    ██╗███████╗███████╗██████╗  
 ██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔══██╗██╔════╝██║    ██║██╔════╝██╔════╝██╔══██╗ 
 ██████╔╝██║   ██║██║ █╗ ██║█████╗  ██████╔╝███████╗██║ █╗ ██║█████╗  █████╗  ██████╔╝ 
 ██╔═══╝ ██║   ██║██║███╗██║██╔══╝  ██╔══██╗╚════██║██║███╗██║██╔══╝  ██╔══╝  ██╔═══╝  
 ██║     ╚██████╔╝╚███╔███╔╝███████╗██║  ██║███████║╚███╔███╔╝███████╗███████╗██║      
 ╚═╝      ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝      
                                         LITE                                          
        Simple PowerShell Network Discovery Tool by Ulises Paiz
"@

Clear-Host
Write-Host $banner -ForegroundColor Cyan

# Generate a fancy ASCII art separator
$separator = "═".PadRight(75, "═")
Write-Host $separator -ForegroundColor Cyan

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    Write-Host "`n[WARNING] This script is not running with administrator privileges." -ForegroundColor Red
    Write-Host "MAC address detection may not work properly." -ForegroundColor Yellow
    Write-Host "Consider restarting the script as administrator for full functionality.`n" -ForegroundColor Yellow
    
    $continue = Read-Host "Continue anyway? (Y/N)"
    if ($continue -ne "Y" -and $continue -ne "y") {
        exit
    }
}

# Get local network information
$Global:NetworkInfo = Get-LocalNetworkInfo

# Show menu and start scanning
Show-Menu -NetworkInfo $Global:NetworkInfo

Write-Host "`n" -NoNewline
Write-Host "╔═════════════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "║                                                                     ║" -ForegroundColor Cyan
Write-Host "║              Thank you for using PowerSweep Lite!                   ║" -ForegroundColor Cyan
Write-Host "║                                                                     ║" -ForegroundColor Cyan
Write-Host "╚═════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
