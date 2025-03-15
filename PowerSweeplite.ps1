#requires -RunAsAdministrator
<#
.SYNOPSIS
    PowerSweep Lite - Simple PowerShell Network Scanner with Enhanced GUI
.DESCRIPTION
    A lightweight network scanning tool that discovers active hosts on the network
    with an improved, user-friendly console interface.
.NOTES
    Author: Ulises Paiz
    Version: 1.1 (Lite)
#>

# Set console properties for better display
$Host.UI.RawUI.WindowTitle = "PowerSweep Lite v1.1"
if ($Host.UI.RawUI.WindowSize.Width -lt 100) {
    try {
        $Host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size(100, 30)
    } catch {
        Write-Host "Window size could not be adjusted automatically. For best experience, please maximize your terminal window." -ForegroundColor Yellow
    }
}

function Show-InfoBox {
    param (
        [string]$Title,
        [string[]]$Content,
        [string]$BorderColor = "Cyan",
        [string]$TitleColor = "Yellow",
        [string]$ContentColor = "White",
        [switch]$Center
    )
    
    # Calculate width based on the longest line in content plus padding
    $titleLength = $Title.Length
    $contentLength = ($Content | Measure-Object -Maximum -Property Length).Maximum
    $width = [Math]::Max($titleLength, $contentLength) + 6
    
    # Create top border with title
    Write-Host "┌─" -NoNewline -ForegroundColor $BorderColor
    Write-Host "".PadRight(($width - $Title.Length) / 2 - 2, "─") -NoNewline -ForegroundColor $BorderColor
    Write-Host " $Title " -NoNewline -ForegroundColor $TitleColor
    Write-Host "".PadRight(($width - $Title.Length) / 2 - 2, "─") -NoNewline -ForegroundColor $BorderColor
    Write-Host "─┐" -ForegroundColor $BorderColor
    
    # Create content lines
    foreach ($line in $Content) {
        Write-Host "│ " -NoNewline -ForegroundColor $BorderColor
        
        if ($Center) {
            $padding = [Math]::Max(0, ($width - $line.Length - 4) / 2)
            Write-Host "".PadRight($padding, " ") -NoNewline
            Write-Host "$line" -NoNewline -ForegroundColor $ContentColor
            Write-Host "".PadRight($width - $line.Length - 4 - $padding, " ") -NoNewline
        } else {
            Write-Host "$line" -NoNewline -ForegroundColor $ContentColor
            Write-Host "".PadRight($width - $line.Length - 4, " ") -NoNewline
        }
        
        Write-Host " │" -ForegroundColor $BorderColor
    }
    
    # Create bottom border
    Write-Host "└" -NoNewline -ForegroundColor $BorderColor
    Write-Host "".PadRight($width, "─") -NoNewline -ForegroundColor $BorderColor
    Write-Host "┘" -ForegroundColor $BorderColor
}

function Show-ProgressBar {
    param (
        [int]$PercentComplete,
        [int]$Width = 50,
        [string]$FillColor = "Green",
        [string]$EmptyColor = "DarkGray",
        [switch]$ShowPercent
    )
    
    $fillWidth = [Math]::Round(($PercentComplete / 100) * $Width)
    $emptyWidth = $Width - $fillWidth
    
    # Create the filled portion
    Write-Host "[" -NoNewline -ForegroundColor White
    if ($fillWidth -gt 0) {
        Write-Host "".PadRight($fillWidth, "■") -NoNewline -ForegroundColor $FillColor
    }
    
    # Create the empty portion
    if ($emptyWidth -gt 0) {
        Write-Host "".PadRight($emptyWidth, "□") -NoNewline -ForegroundColor $EmptyColor
    }
    
    # Close the progress bar
    Write-Host "]" -NoNewline -ForegroundColor White
    
    # Show percentage if requested
    if ($ShowPercent) {
        Write-Host " $PercentComplete%" -NoNewline -ForegroundColor Cyan
    }
}

function Get-LocalNetworkInfo {
    $headerContent = @(
        "",
        "Collecting information about your local network...",
        "This information will be used to determine scan parameters.",
        ""
    )
    
    Show-InfoBox -Title "LOCAL NETWORK INFORMATION" -Content $headerContent -BorderColor Cyan -TitleColor Yellow -ContentColor White
    
    $networkInfo = Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}
    
    foreach ($adapter in $networkInfo) {
        # Calculate subnet mask in dotted decimal format
        $prefixLength = $adapter.IPv4Address.PrefixLength
        $subnetMaskInt = [UInt32]([UInt32]::MaxValue -shl (32 - $prefixLength))
        $subnetMaskBytes = [BitConverter]::GetBytes($subnetMaskInt)
        [Array]::Reverse($subnetMaskBytes)
        $subnetMaskDotted = [IPAddress]$subnetMaskBytes
        
        $adapterContent = @(
            "Interface: $($adapter.InterfaceAlias)",
            "",
            "YOUR IP ADDRESS: $($adapter.IPv4Address.IPAddress)",
            "CIDR Prefix: /$($adapter.IPv4Address.PrefixLength)",
            "SUBNET MASK: $subnetMaskDotted",
            "Gateway: $($adapter.IPv4DefaultGateway.NextHop)",
            "DNS Servers: $($adapter.DNSServer | Where-Object {$_.AddressFamily -eq 2} | ForEach-Object {$_.ServerAddresses})"
        )
        
        # Try to get DHCP Server info
        try {
            $dhcpServer = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | 
                Where-Object {$_.Description -eq $adapter.NetAdapter.DriverDescription} | 
                Select-Object -ExpandProperty DHCPServer -ErrorAction SilentlyContinue
            
            $adapterContent += "DHCP Server: $dhcpServer"
        } catch {
            $adapterContent += "DHCP Server: Unable to retrieve"
        }
        
        $adapterContent += "MAC Address: $($adapter.NetAdapter.MacAddress)"
        
        Show-InfoBox -Title "YOUR MACHINE" -Content $adapterContent -BorderColor Yellow -TitleColor Green -ContentColor White
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
    
    $networkRangeContent = @(
        "Network Address: $networkAddress",
        "Broadcast Address: $broadcastAddress",
        "Subnet Mask: $subnetMask",
        "First Usable IP: $firstUsableIP",
        "Last Usable IP: $lastUsableIP",
        "Total Usable IPs: $totalUsableIPs",
        "",
        "Your position in network range:"
    )
    
    Show-InfoBox -Title "NETWORK RANGE" -Content $networkRangeContent -BorderColor Yellow -TitleColor Cyan
    
    # Display a visual indicator showing where your IP is in the range
    Write-Host "  $firstUsableIP " -NoNewline -ForegroundColor Gray
    
    # Create a simple visual representation of where the IP is in the range
    $ipInt = [BitConverter]::ToUInt32(([IPAddress]$ipAddress).GetAddressBytes(), 0)
    $firstInt = [BitConverter]::ToUInt32($firstUsableBytes, 0)
    $lastInt = [BitConverter]::ToUInt32($lastUsableBytes, 0)
    
    $position = [int](($ipInt - $firstInt) / ($lastInt - $firstInt) * 50)
    
    Show-ProgressBar -PercentComplete (($position / 50) * 100) -Width 50 -FillColor Green -EmptyColor DarkGray
    Write-Host " $lastUsableIP" -ForegroundColor Gray
    Write-Host ""
    
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
    
    $scanInfo = @(
        "Preparing to scan $totalIPs IP addresses",
        "Range: $StartIP to $EndIP",
        "Timeout: $TimeoutMilliseconds ms per host",
        "Thread count: $MaxThreads concurrent scans"
    )
    
    Show-InfoBox -Title "SCAN CONFIGURATION" -Content $scanInfo -BorderColor Magenta -TitleColor Yellow
    
    # Check if the range is reasonable (prevent huge ranges)
    if ($endIPInt - $startIPInt > 10000) {
        $warningContent = @(
            "Very large IP range detected ($($endIPInt - $startIPInt + 1) addresses).",
            "This may take a very long time to complete."
        )
        
        Show-InfoBox -Title "WARNING" -Content $warningContent -BorderColor Red -TitleColor Yellow
        
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
    
    $startingContent = @(
        "Starting network scan at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        "Discovering active hosts on your network...",
        ""
    )
    
    Show-InfoBox -Title "STARTING SCAN" -Content $startingContent -BorderColor Yellow -TitleColor Green -Center
    
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
    
    # Create a hashtable to track device types for summary
    $deviceTypeCounts = @{}
    
    # Last update time
    $lastUpdateTime = Get-Date
    $updateInterval = [TimeSpan]::FromSeconds(1)
    
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
                        
                        # Update device type counts
                        if (-not $deviceTypeCounts.ContainsKey($result.DeviceType)) {
                            $deviceTypeCounts[$result.DeviceType] = 0
                        }
                        $deviceTypeCounts[$result.DeviceType]++
                        
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
        $currentTime = Get-Date
        
        if (($currentTime - $lastUpdateTime) -gt $updateInterval) {
            # Calculate scan rate and ETA
            $elapsedSeconds = ($currentTime - $scanStartTime).TotalSeconds
            $scanRate = if ($elapsedSeconds -gt 0) { $totalScanned / $elapsedSeconds } else { 0 }
            $remainingIPs = $totalIPs - $totalScanned
            $estimatedSecondsRemaining = if ($scanRate -gt 0) { $remainingIPs / $scanRate } else { 0 }
            $estimatedTimeRemaining = [TimeSpan]::FromSeconds($estimatedSecondsRemaining)
            
            # Clear current progress line
            Write-Host "`r".PadRight(100, " ") -NoNewline
            
            # Write new progress line
            Write-Host "`r" -NoNewline
            Write-Host "Scanning progress: " -NoNewline -ForegroundColor White
            Show-ProgressBar -PercentComplete $percentComplete -Width 40 -FillColor Cyan -EmptyColor DarkGray
            Write-Host " $percentComplete% " -NoNewline -ForegroundColor Cyan
            Write-Host "($totalScanned of $totalIPs)" -NoNewline -ForegroundColor White
            
            if ($scanRate -gt 0) {
                Write-Host " | " -NoNewline
                Write-Host "Rate: " -NoNewline -ForegroundColor White
                Write-Host ("{0:0.0}" -f $scanRate) -NoNewline -ForegroundColor Yellow
                Write-Host " IPs/sec" -NoNewline -ForegroundColor White
                Write-Host " | " -NoNewline
                Write-Host "ETA: " -NoNewline -ForegroundColor White
                
                if ($estimatedTimeRemaining.TotalHours -ge 1) {
                    Write-Host ("{0:0}h {1:0}m" -f $estimatedTimeRemaining.Hours, $estimatedTimeRemaining.Minutes) -NoNewline -ForegroundColor Yellow
                } elseif ($estimatedTimeRemaining.TotalMinutes -ge 1) {
                    Write-Host ("{0:0}m {1:0}s" -f $estimatedTimeRemaining.Minutes, $estimatedTimeRemaining.Seconds) -NoNewline -ForegroundColor Yellow
                } else {
                    Write-Host ("{0:0}s" -f $estimatedTimeRemaining.Seconds) -NoNewline -ForegroundColor Yellow
                }
            }
            
            # Update timestamp for the next refresh
            $lastUpdateTime = $currentTime
        }
        
        # Sleep briefly to reduce CPU usage
        Start-Sleep -Milliseconds 20
        
    } while ($runspaces | Where-Object { -not $_.Completed } | Select-Object -First 1)
    
    # Clear the progress line
    Write-Host "`r".PadRight(100, " ")
    
    # Clean up the runspace pool
    $runspacePool.Close()
    $runspacePool.Dispose()
    
    $scanEndTime = Get-Date
    $scanDuration = $scanEndTime - $scanStartTime
    
    Write-Progress -Activity "Scanning Network" -Completed
    
    # Format duration string for display
    $durationStr = ""
    if ($scanDuration.Hours -gt 0) {
        $durationStr += "$($scanDuration.Hours) hours, "
    }
    if ($scanDuration.Minutes -gt 0) {
        $durationStr += "$($scanDuration.Minutes) minutes, "
    }
    $durationStr += "$($scanDuration.Seconds) seconds"
    
    $scanCompleteContent = @(
        "Scan completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        "Duration: $durationStr",
        "Total IPs Scanned: $totalIPs",
        "Active Hosts Found: $totalActive"
    )
    
    Show-InfoBox -Title "SCAN COMPLETE" -Content $scanCompleteContent -BorderColor Green -TitleColor Cyan
    
    # Display device type summary if hosts were found
    if ($totalActive -gt 0) {
        $deviceTypeContent = @("Summary of discovered devices:")
        foreach ($deviceType in $deviceTypeCounts.Keys | Sort-Object) {
            $count = $deviceTypeCounts[$deviceType]
            $percentage = ($count / $totalActive) * 100
            $deviceTypeContent += "  $deviceType : $count ($([Math]::Round($percentage, 1))%)"
        }
        
        Show-InfoBox -Title "DEVICE SUMMARY" -Content $deviceTypeContent -BorderColor Cyan -TitleColor Yellow
    }
    
    # Display scan results
    if ($results.Count -gt 0) {
        Write-Host "`n" -NoNewline
        $frameWidth = 80
        
        # Create a header for results table
        Write-Host "┌" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight($frameWidth - 2, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┐" -ForegroundColor Cyan
        
        Write-Host "│" -NoNewline -ForegroundColor Cyan
        Write-Host " SCAN RESULTS ".PadRight($frameWidth - 2, " ") -NoNewline -ForegroundColor Yellow
        Write-Host "│" -ForegroundColor Cyan
        
        Write-Host "├" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(15, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┬" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(25, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┬" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(15, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┬" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(10, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┬" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight($frameWidth - 70, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┤" -ForegroundColor Cyan
        
        # Header row
        Write-Host "│" -NoNewline -ForegroundColor Cyan
        Write-Host " IP Address".PadRight(15, " ") -NoNewline -ForegroundColor White
        Write-Host "│" -NoNewline -ForegroundColor Cyan
        Write-Host " Hostname".PadRight(25, " ") -NoNewline -ForegroundColor White
        Write-Host "│" -NoNewline -ForegroundColor Cyan
        Write-Host " Device Type".PadRight(15, " ") -NoNewline -ForegroundColor White
        Write-Host "│" -NoNewline -ForegroundColor Cyan
        Write-Host " Response".PadRight(10, " ") -NoNewline -ForegroundColor White
        Write-Host "│" -NoNewline -ForegroundColor Cyan
        Write-Host " MAC Address".PadRight($frameWidth - 70, " ") -NoNewline -ForegroundColor White
        Write-Host "│" -ForegroundColor Cyan
        
        Write-Host "├" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(15, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┼" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(25, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┼" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(15, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┼" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(10, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┼" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight($frameWidth - 70, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┤" -ForegroundColor Cyan
        
        # Sort results by IP address
        $sortedResults = $results | Sort-Object { 
            $octets = $_.IPAddress -split '\.'
            [int]$octets[0]*16777216 + [int]$octets[1]*65536 + [int]$octets[2]*256 + [int]$octets[3]
        }
        
        # Display each result in a consistent format
        foreach ($result in $sortedResults) {
            # Truncate long hostnames
            $displayHostname = if ($result.Hostname.Length -gt 23) { $result.Hostname.Substring(0, 20) + "..." } else { $result.Hostname }
            
            Write-Host "│" -NoNewline -ForegroundColor Cyan
            Write-Host " $($result.IPAddress)".PadRight(15, " ") -NoNewline -ForegroundColor Green
            Write-Host "│" -NoNewline -ForegroundColor Cyan
            Write-Host " $displayHostname".PadRight(25, " ") -NoNewline -ForegroundColor Cyan
            Write-Host "│" -NoNewline -ForegroundColor Cyan
            
            # Color-code device types
            Write-Host " " -NoNewline
            $deviceTypePadded = "$($result.DeviceType)".PadRight(14, " ")
            switch -Regex ($result.DeviceType) {
                "Server" { Write-Host $deviceTypePadded -NoNewline -ForegroundColor Red }
                "Router|Gateway|Network" { Write-Host $deviceTypePadded -NoNewline -ForegroundColor Magenta }
                "Printer" { Write-Host $deviceTypePadded -NoNewline -ForegroundColor DarkYellow }
                "Camera" { Write-Host $deviceTypePadded -NoNewline -ForegroundColor DarkCyan }
                default { Write-Host $deviceTypePadded -NoNewline -ForegroundColor White }
            }
            
            Write-Host "│" -NoNewline -ForegroundColor Cyan
            Write-Host " $($result.ResponseTime)".PadRight(10, " ") -NoNewline -ForegroundColor Yellow
            Write-Host "│" -NoNewline -ForegroundColor Cyan
            Write-Host " $($result.MAC)".PadRight($frameWidth - 70, " ") -NoNewline -ForegroundColor Gray
            Write-Host "│" -ForegroundColor Cyan
        }
        
        # Bottom border
        Write-Host "└" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(15, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┴" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(25, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┴" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(15, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┴" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(10, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┴" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight($frameWidth - 70, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┘" -ForegroundColor Cyan
        
    } else {
        $noHostsContent = @(
            "No active hosts were found in the specified range.",
            "You may want to try:",
            "  - Increasing the timeout value",
            "  - Checking your network configuration",
            "  - Scanning a different IP range"
        )
        
        Show-InfoBox -Title "NO RESULTS" -Content $noHostsContent -BorderColor Yellow -TitleColor Red
    }
    
    return $results
}

function Show-Menu {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$NetworkInfo
    )
    
    # Animation for banner display
    function Show-AnimatedBanner {
        $banner = @"
                                                                                
 ██████╗  ██████╗ ██╗    ██╗███████╗██████╗ ███████╗██╗    ██╗███████╗███████╗██████╗  
 ██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔══██╗██╔════╝██║    ██║██╔════╝██╔════╝██╔══██╗ 
 ██████╔╝██║   ██║██║ █╗ ██║█████╗  ██████╔╝███████╗██║ █╗ ██║█████╗  █████╗  ██████╔╝ 
 ██╔═══╝ ██║   ██║██║███╗██║██╔══╝  ██╔══██╗╚════██║██║███╗██║██╔══╝  ██╔══╝  ██╔═══╝  
 ██║     ╚██████╔╝╚███╔███╔╝███████╗██║  ██║███████║╚███╔███╔╝███████╗███████╗██║      
 ╚═╝      ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝      
                                         LITE v1.1                                     
        Simple PowerShell Network Discovery Tool by Ulises Paiz
"@

        $rainbowColors = @(
            "Red", "Yellow", "Green", "Cyan", "Blue", "Magenta"
        )
        
        $lines = $banner -split "`n"
        
        foreach ($line in $lines) {
            $color = $rainbowColors[(Get-Random -Maximum $rainbowColors.Count)]
            Write-Host $line -ForegroundColor $color
            Start-Sleep -Milliseconds 50
        }
        
        # Create a fancy separator
        Write-Host "┌" -NoNewline -ForegroundColor Cyan
        for ($i = 0; $i -lt 78; $i++) {
            Start-Sleep -Milliseconds 5
            Write-Host "─" -NoNewline -ForegroundColor Cyan
        }
        Write-Host "┐" -ForegroundColor Cyan
    }
    
    Clear-Host
    Show-AnimatedBanner
    
    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        $adminWarning = @(
            "This script is not running with administrator privileges.",
            "MAC address detection may not work properly.",
            "Consider restarting the script as administrator for full functionality."
        )
        
        Show-InfoBox -Title "WARNING" -Content $adminWarning -BorderColor Red -TitleColor Yellow
        
        $continue = Read-Host "Continue anyway? (Y/N)"
        if ($continue -ne "Y" -and $continue -ne "y") {
            exit
        }
    }
    
    $scanOptions = @{
        ScanRange = "1"
        StartIP = $NetworkInfo.FirstIP
        EndIP = $NetworkInfo.LastIP
        Timeout = 300
        ThreadCount = 50
    }
    
    $menuActive = $true
    
    while ($menuActive) {
        Clear-Host
        Show-AnimatedBanner
        
        # Create a visually appealing settings display
        $settingsContent = @(
            "1. IP Range     : $($scanOptions.StartIP) to $($scanOptions.EndIP)",
            "2. Timeout      : $($scanOptions.Timeout) ms",
            "3. Thread Count : $($scanOptions.ThreadCount)"
        )
        
        Show-InfoBox -Title "CURRENT SETTINGS" -Content $settingsContent -BorderColor Cyan -TitleColor Yellow
        
        # Actions menu
        $actionsContent = @(
            "S. Start Network Scan",
            "C. Change IP Range to Custom Values",
            "N. Reset IP Range to Network Range",
            "T. Configure Advanced Settings",
            "H. Help & About Information",
            "Q. Quit PowerSweep Lite"
        )
        
        Show-InfoBox -Title "ACTIONS" -Content $actionsContent -BorderColor Cyan -TitleColor Green
        
        # Get user choice with highlighted prompt
        Write-Host "┌" -NoNewline -ForegroundColor Yellow
        Write-Host "".PadRight(78, "─") -NoNewline -ForegroundColor Yellow
        Write-Host "┐" -ForegroundColor Yellow
        
        Write-Host "│" -NoNewline -ForegroundColor Yellow
        Write-Host " Enter your choice: " -NoNewline -ForegroundColor White -BackgroundColor DarkBlue
        $choice = Read-Host
        Write-Host "".PadRight(62 - $choice.Length, " ") -NoNewline
        Write-Host "│" -ForegroundColor Yellow
        
        Write-Host "└" -NoNewline -ForegroundColor Yellow
        Write-Host "".PadRight(78, "─") -NoNewline -ForegroundColor Yellow
        Write-Host "┘" -ForegroundColor Yellow
        
        switch -Regex ($choice) {
            "1|[Cc]" {
                Clear-Host
                $customTitle = "CUSTOM IP RANGE CONFIGURATION"
                $customContent = @(
                    "Enter the start and end IP addresses for your custom scan range.",
                    "Current range: $($scanOptions.StartIP) to $($scanOptions.EndIP)",
                    ""
                )
                
                Show-InfoBox -Title $customTitle -Content $customContent -BorderColor Magenta -TitleColor Yellow
                $scanOptions.StartIP = Read-Host "Enter start IP"
                $scanOptions.EndIP = Read-Host "Enter end IP"
            }
            "2|[Tt]" {
                Clear-Host
                $advancedTitle = "ADVANCED CONFIGURATION"
                $advancedContent = @(
                    "Configure advanced scan settings",
                    "",
                    "Timeout: Higher values may find more hosts but scan slower",
                    "Threads: Higher values scan faster but use more resources",
                    ""
                )
                
                Show-InfoBox -Title $advancedTitle -Content $advancedContent -BorderColor Blue -TitleColor Cyan
                
                $timeout = Read-Host "Enter timeout in milliseconds (100-5000) [Current: $($scanOptions.Timeout)]"
                if ([int]::TryParse($timeout, [ref]$null) -and [int]$timeout -ge 100 -and [int]$timeout -le 5000) {
                    $scanOptions.Timeout = [int]$timeout
                } else {
                    Write-Host "Invalid input. Keeping current value ($($scanOptions.Timeout)ms)" -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }
                
                $threads = Read-Host "Enter thread count (1-100) [Current: $($scanOptions.ThreadCount)]"
                if ([int]::TryParse($threads, [ref]$null) -and [int]$threads -ge 1 -and [int]$threads -le 100) {
                    $scanOptions.ThreadCount = [int]$threads
                } else {
                    Write-Host "Invalid input. Keeping current value ($($scanOptions.ThreadCount))" -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }
            }
            "3|[Nn]" {
                $scanOptions.StartIP = $NetworkInfo.FirstIP
                $scanOptions.EndIP = $NetworkInfo.LastIP
                Write-Host "IP range reset to network range" -ForegroundColor Green
                Start-Sleep -Seconds 1
            }
            "[Ss]" {
                Clear-Host
                [void](Scan-Network -StartIP $scanOptions.StartIP -EndIP $scanOptions.EndIP -TimeoutMilliseconds $scanOptions.Timeout -MaxThreads $scanOptions.ThreadCount)
                
                $postScanContent = @(
                    "Options:",
                    "  Y - Run another scan",
                    "  N - Return to main menu"
                )
                
                Show-InfoBox -Title "SCAN AGAIN?" -Content $postScanContent -BorderColor Yellow -TitleColor Green
                
                $scanAgain = Read-Host "Your choice (Y/N)"
                if ($scanAgain -ne "Y" -and $scanAgain -ne "y") {
                    # Just continue in menu
                }
            }
            "[Hh]" {
                Clear-Host
                $aboutContent = @(
                    "PowerSweep Lite v1.1",
                    "A simple PowerShell network discovery tool",
                    "",
                    "Author: Ulises Paiz",
                    "License: GNU GPL v3",
                    "",
                    "This tool scans your network to discover active hosts",
                    "and provides basic information about them.",
                    "",
                    "USAGE:",
                    "- Configure scan settings from the main menu",
                    "- Start a scan to discover hosts on your network",
                    "- Results show IP, hostname, device type, and MAC addresses",
                    "",
                    "Press any key to return to the main menu..."
                )
                
                Show-InfoBox -Title "ABOUT POWERSWEEP LITE" -Content $aboutContent -BorderColor Cyan -TitleColor Magenta -Center
                
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "[Qq]" {
                $menuActive = $false
            }
            default {
                Write-Host "Invalid choice. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 1
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
                                         LITE v1.1                                    
        Simple PowerShell Network Discovery Tool by Ulises Paiz
"@

Clear-Host
Write-Host $banner -ForegroundColor Cyan

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

# Farewell message with animation
$farewellContent = @(
    "",
    "Thank you for using PowerSweep Lite!",
    "",
    "Press any key to exit..."
)

Show-InfoBox -Title "GOODBYE" -Content $farewellContent -BorderColor Cyan -TitleColor Magenta -Center

# Wait for a key press before exiting
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
