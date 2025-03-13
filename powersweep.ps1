#requires -RunAsAdministrator
<#
.SYNOPSIS
    PowerSweep - Advanced PowerShell Network Scanner
.DESCRIPTION
    A comprehensive network scanning tool that discovers active hosts,
    performs port scanning, identifies services, discovers shares,
    attempts to determine device types, and performs basic vulnerability assessment.
.NOTES
    Author: Ulises Paiz
    Version: 3.4
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

function Test-Port {
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress,
        
        [Parameter(Mandatory=$true)]
        [int]$Port,
        
        [int]$Timeout = 500
    )
    
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    try {
        $result = $tcpClient.BeginConnect($IPAddress, $Port, $null, $null)
        $success = $result.AsyncWaitHandle.WaitOne($Timeout, $false)
        if ($success -and $tcpClient.Connected) {
            return $true
        }
        return $false
    } catch {
        return $false
    } finally {
        $tcpClient.Close()
    }
}

function Scan-Network {
    param (
        [Parameter(Mandatory=$true)]
        [string]$StartIP,
        
        [Parameter(Mandatory=$true)]
        [string]$EndIP,
        
        [int]$TimeoutMilliseconds = 500,
        
        [int]$MaxThreads = 50,
        
        [bool]$ScanPorts = $true,
        
        [bool]$DiscoverShares = $true,
        
        [Parameter(Mandatory=$true)]
        [bool]$ExportResults,
        
        [string]$ExportPath = "$env:USERPROFILE\Desktop\NetworkScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
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
    $runspaces = @()
    
    # Common ports to scan
    $commonPorts = @(
        20, 21, 22, 23, 25, 53, 80, 88, 110, 123, 135, 139, 143, 
        389, 443, 445, 465, 587, 636, 993, 995, 1433, 1434, 
        3306, 3389, 5900, 8080
    )
    
    # Service names lookup
    $serviceNames = @{
        20 = "FTP Data"
        21 = "FTP Control"
        22 = "SSH"
        23 = "Telnet"
        25 = "SMTP"
        53 = "DNS"
        80 = "HTTP"
        88 = "Kerberos"
        110 = "POP3"
        123 = "NTP"
        135 = "RPC"
        139 = "NetBIOS"
        143 = "IMAP"
        389 = "LDAP"
        443 = "HTTPS"
        445 = "SMB"
        465 = "SMTPS"
        587 = "SMTP Submission"
        636 = "LDAPS"
        993 = "IMAPS"
        995 = "POP3S"
        1433 = "MS SQL"
        1434 = "MS SQL Browser"
        3306 = "MySQL"
        3389 = "RDP"
        5900 = "VNC"
        8080 = "HTTP Proxy"
    }
    
    # Create scriptblock for runspaces - This is the main scanning function
    $scriptBlock = {
        param (
            [string]$ipAddress,
            [int]$timeout,
            [bool]$scanPorts,
            [bool]$discoverShares,
            [array]$ports,
            [hashtable]$serviceDict,
            [string]$gateway
        )
        
        # Define the device type function within this scriptblock for scope access
        function Get-DeviceType {
            param (
                [string]$ip,
                [array]$openPorts,
                [string]$hostname = "",
                [string]$gw = ""
            )
            
            # Initialize with Unknown
            $deviceType = "Unknown"
            $osType = "Unknown"
            $deviceRole = "Unknown"
            
            # Check if it's the gateway
            if ($ip -eq $gw) {
                return "Router/Gateway"
            }
            
            # Advanced port pattern recognition
            $portSignatures = @{
                # Web services
                "WebServer" = @(80, 443, 8080, 8443)
                "ProxyServer" = @(3128, 8080, 8118)
                
                # File sharing
                "FileServer" = @(139, 445, 2049)
                
                # Email services
                "MailServer" = @(25, 110, 143, 465, 587, 993, 995)
                
                # Database
                "DatabaseServer" = @(1433, 1521, 3306, 5432)
                
                # Directory services
                "DirectoryServer" = @(389, 636, 88)
                
                # Remote access
                "RemoteAccess" = @(22, 23, 3389, 5900)
                
                # Media servers
                "MediaServer" = @(1900, 8096, 32469)
                
                # IoT and smart home
                "IoT" = @(1883, 8883, 5683)
                
                # VoIP
                "VoIP" = @(5060, 5061)
                
                # Print services
                "PrintServer" = @(515, 631, 9100)
                
                # Monitoring
                "MonitoringServer" = @(161, 162, 199)
            }
            
            # OS detection by port patterns
            $osSignatures = @{
                "Windows" = @(135, 139, 445, 3389, 5985)
                "Linux" = @(22, 111, 2049)
                "macOS" = @(548, 5000, 7000)
                "Network" = @(22, 23, 161, 162, 443, 830)
            }
            
            # Identify device role based on open ports
            foreach ($signature in $portSignatures.GetEnumerator()) {
                $matchCount = 0
                foreach ($port in $signature.Value) {
                    if ($openPorts -contains $port) {
                        $matchCount++
                    }
                }
                
                # If we have at least 2 matching ports or a significant percentage
                if (($matchCount -ge 2) -or 
                    ($signature.Value.Count -gt 0 -and $matchCount -gt 0 -and ($matchCount / $signature.Value.Count) -ge 0.3)) {
                    $deviceRole = $signature.Key
                    break
                }
            }
            
            # Identify OS based on open ports
            foreach ($signature in $osSignatures.GetEnumerator()) {
                $matchCount = 0
                foreach ($port in $signature.Value) {
                    if ($openPorts -contains $port) {
                        $matchCount++
                    }
                }
                
                # If we have at least 2 matching ports or a significant percentage
                if (($matchCount -ge 2) -or 
                    ($signature.Value.Count -gt 0 -and $matchCount -gt 0 -and ($matchCount / $signature.Value.Count) -ge 0.3)) {
                    $osType = $signature.Key
                    break
                }
            }
            
            # Special case checks
            if ($openPorts -contains 80 -and $openPorts -contains 443) {
                if ($openPorts -contains 8080 -or $openPorts -contains 8443) {
                    $deviceRole = "WebServer"
                } else {
                    $deviceRole = "Web-enabled Device"
                }
            }
            
            # Enhanced hostname analysis
            if ($hostname -ne "Unknown" -and $hostname -ne "") {
                $lowercaseHostname = $hostname.ToLower()
                
                # Router/Network devices
                if ($lowercaseHostname -match "router|gateway|ap|accesspoint|wifi|ubnt|unifi|mikrotik|cisco|juniper|tplink|dlink|netgear|asus") {
                    $deviceRole = "NetworkDevice"
                    $osType = "Network"
                }
                
                # Printers
                if ($lowercaseHostname -match "printer|hpprinter|epson|canon|brother|lexmark|zebra|dymo|print|mfp") {
                    $deviceRole = "Printer"
                    $osType = "Embedded"
                }
                
                # Cameras/Security
                if ($lowercaseHostname -match "cam|camera|ipcam|nvr|dvr|dahua|hikvision|axis|bosch|cctv|surveillan|security") {
                    $deviceRole = "Camera"
                    $osType = "Embedded"
                }
                
                # Media devices
                if ($lowercaseHostname -match "tv|roku|firetv|appletv|chromecast|shield|media|smart-tv|smarttv|samsung|lg|sony|philips|hisense") {
                    $deviceRole = "MediaDevice"
                    $osType = "Embedded"
                }
                
                # Mobile devices
                if ($lowercaseHostname -match "phone|iphone|android|ipad|tablet|mobile|pixel|galaxy|oneplus|xiaomi") {
                    $deviceRole = "MobileDevice"
                    if ($lowercaseHostname -match "iphone|ipad|ipod") {
                        $osType = "iOS"
                    }
                    elseif ($lowercaseHostname -match "android|pixel|galaxy|oneplus|xiaomi") {
                        $osType = "Android"
                    }
                }
                
                # Servers
                if ($lowercaseHostname -match "server|srv|dc|domain|ad|exchange|sql|web|mail|dns|dhcp|ftp|app|backup|db") {
                    $deviceRole = "Server"
                    if ($lowercaseHostname -match "win") {
                        $osType = "Windows"
                    }
                    elseif ($lowercaseHostname -match "lnx|linux|ubuntu|debian|centos|rhel|fedora") {
                        $osType = "Linux"
                    }
                }
                
                # IoT devices
                if ($lowercaseHostname -match "iot|smart|nest|hue|echo|alexa|google-home|ring|blink|wyze|eufy") {
                    $deviceRole = "IoT"
                    $osType = "Embedded"
                }
            }
            
            # Combine OS and role for detailed device type
            if ($osType -ne "Unknown" -and $deviceRole -ne "Unknown") {
                $deviceType = "$osType $deviceRole"
            }
            elseif ($osType -ne "Unknown") {
                $deviceType = $osType
            }
            elseif ($deviceRole -ne "Unknown") {
                $deviceType = $deviceRole
            }
            
            return $deviceType
        }
        
        # Ping the IP to check if it's active (with faster timeout)
        $ping = New-Object System.Net.NetworkInformation.Ping
        $reply = $ping.Send($ipAddress, [Math]::Min(300, $timeout))
        
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
            
            $openPorts = @()
            $openPortNumbers = @()
            
            if ($scanPorts) {
                foreach ($port in $ports) {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    try {
                        $connectResult = $tcpClient.BeginConnect($ipAddress, $port, $null, $null)
                        $connected = $connectResult.AsyncWaitHandle.WaitOne([Math]::Min(200, $timeout), $false)
                        
                        if ($connected -and $tcpClient.Connected) {
                            $service = if ($serviceDict.ContainsKey($port)) { $serviceDict[$port] } else { "Unknown" }
                            $openPorts += "$port ($service)"
                            $openPortNumbers += $port
                        }
                    } catch {
                        # Connection failed, port is closed or filtered
                    } finally {
                        if ($tcpClient.Connected) { $tcpClient.Close() }
                    }
                }
            }
            
            # Determine device type - Use our locally scoped function with proper parameters
            $deviceType = Get-DeviceType -ip $ipAddress -openPorts $openPortNumbers -hostname $hostname -gw $gateway
            
            # Discover network shares
            $shares = @()
            if ($discoverShares -and ($openPortNumbers -contains 445 -or $openPortNumbers -contains 139)) {
                try {
                    $netView = net view $ipAddress 2>$null | Select-String -Pattern "^\\.*" | ForEach-Object { $_.ToString().Trim() }
                    foreach ($share in $netView) {
                        if ($share -match "\\\\.*\\(.*)") {
                            $shareName = $matches[1]
                            if ($shareName -notmatch "IPC\$|ADMIN\$|.*\$$") {
                                $shares += $shareName
                            }
                        }
                    }
                } catch {
                    # Do nothing if shares can't be enumerated
                }
            }
            
            # Create object with results
            $result = [PSCustomObject]@{
                IPAddress = $ipAddress
                Hostname = $hostname
                MAC = $mac
                Status = "Online"
                ResponseTime = "$($reply.RoundtripTime) ms"
                OpenPorts = ($openPorts -join ", ")
                DeviceType = $deviceType
                Shares = ($shares -join ", ")
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
        
        # Create a PowerShell instance with all needed parameters
        $powershell = [powershell]::Create().AddScript($scriptBlock)
        $powershell.AddParameter("ipAddress", $currentIP)
        $powershell.AddParameter("timeout", $TimeoutMilliseconds)
        $powershell.AddParameter("scanPorts", $ScanPorts)
        $powershell.AddParameter("discoverShares", $DiscoverShares)
        $powershell.AddParameter("ports", $commonPorts)
        $powershell.AddParameter("serviceDict", $serviceNames)
        $powershell.AddParameter("gateway", $Global:NetworkInfo.Gateway)
        
        # Add the runspace to the PowerShell instance
        $powershell.RunspacePool = $runspacePool
        
        # Begin invoke and add to runspaces collection
        $handle = $powershell.BeginInvoke()
        $runspaces += [PSCustomObject]@{
            PowerShell = $powershell
            Handle = $handle
            IPAddress = $currentIP
            Completed = $false
        }
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
                        
                        # Display active host found with colorful output and better formatting
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
                            "Windows" { Write-Host "$($result.DeviceType)" -ForegroundColor Blue }
                            "Linux|Unix" { Write-Host "$($result.DeviceType)" -ForegroundColor Yellow }
                            "Web" { Write-Host "$($result.DeviceType)" -ForegroundColor Cyan }
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
        $progressColor = switch ($percentComplete) {
            {$_ -lt 25} { "Red" }
            {$_ -lt 50} { "Yellow" }
            {$_ -lt 75} { "Cyan" }
            default { "Green" }
        }
        
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
    
    # If export option was selected, save results
    if ($ExportResults) {
        try {
            # Ensure the directory exists
            $directory = Split-Path -Path $ExportPath -Parent
            if (-not (Test-Path -Path $directory)) {
                New-Item -Path $directory -ItemType Directory -Force | Out-Null
                Write-Host "Created directory: $directory" -ForegroundColor Yellow
            }
            
            # Sort by IP address numerically
            $sortedResults = $results | Sort-Object { 
                $octets = $_.IPAddress -split '\.'
                [int]$octets[0]*16777216 + [int]$octets[1]*65536 + [int]$octets[2]*256 + [int]$octets[3]
            }
            $sortedResults | Export-Csv -Path $ExportPath -NoTypeInformation
            Write-Host "Results exported to: " -NoNewline -ForegroundColor White
            Write-Host "$ExportPath" -ForegroundColor Green
        } catch {
            Write-Host "Error exporting results: $($_.Exception.Message)" -ForegroundColor Red
            
            # Suggest an alternative location
            $alternativePath = "$env:USERPROFILE\Documents\NetworkScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $tryAlternative = Read-Host "Would you like to try saving to $alternativePath instead? (Y/N)"
            if ($tryAlternative -eq "Y" -or $tryAlternative -eq "y") {
                try {
                    $sortedResults | Export-Csv -Path $alternativePath -NoTypeInformation
                    Write-Host "Results exported to: " -NoNewline -ForegroundColor White
                    Write-Host "$alternativePath" -ForegroundColor Green
                } catch {
                    Write-Host "Error exporting to alternative location: $($_.Exception.Message)" -ForegroundColor Red
                }
            }
        }
    }
    
    # Return sorted results - this is the fix for IP address ordering
    return $results | Sort-Object { 
        $octets = $_.IPAddress -split '\.'
        [int]$octets[0]*16777216 + [int]$octets[1]*65536 + [int]$octets[2]*256 + [int]$octets[3]
    }
}

function Scan-Vulnerabilities {
    param (
        [Parameter(Mandatory=$true)]
        [array]$Results
    )
    
    Write-Host "`n═════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "          VULNERABILITY ASSESSMENT           " -ForegroundColor Yellow
    Write-Host "═════════════════════════════════════════════`n" -ForegroundColor Cyan
    
    $vulnerabilities = New-Object System.Collections.ArrayList
    
    # FIXED: Changed $host to $hostItem to avoid conflict with reserved variable
    foreach ($hostItem in $Results) {
        $hostVulns = @()
        
        # Parse open ports
        $openPortsList = @()
        if ($hostItem.OpenPorts -ne "") {
            $hostItem.OpenPorts -split ", " | ForEach-Object {
                if ($_ -match "(\d+) \((.+)\)") {
                    $openPortsList += [int]$matches[1]
                }
            }
        }
        
        # Check for insecure protocols
        if ($openPortsList -contains 21) {
            $hostVulns += [PSCustomObject]@{
                Severity = "Medium"
                Type = "Insecure Protocol"
                Description = "FTP service detected (port 21). FTP transmits data in cleartext."
                Recommendation = "Replace with SFTP (port 22) or FTPS (port 990)"
            }
        }
        
        if ($openPortsList -contains 23) {
            $hostVulns += [PSCustomObject]@{
                Severity = "High"
                Type = "Insecure Protocol"
                Description = "Telnet service detected (port 23). Telnet transmits credentials in cleartext."
                Recommendation = "Replace with SSH (port 22)"
            }
        }
        
        if ($openPortsList -contains 80 -and -not ($openPortsList -contains 443)) {
            $hostVulns += [PSCustomObject]@{
                Severity = "Medium"
                Type = "Insecure Protocol"
                Description = "HTTP without HTTPS detected. Data transmitted in cleartext."
                Recommendation = "Implement HTTPS with valid certificates"
            }
        }
        
        # Check for risky services
        if ($openPortsList -contains 3389) {
            $hostVulns += [PSCustomObject]@{
                Severity = "Medium"
                Type = "Remote Access"
                Description = "RDP service exposed (port 3389)."
                Recommendation = "Restrict RDP access with firewall rules, use strong passwords and NLA"
            }
        }
        
        if ($openPortsList -contains 5900) {
            $hostVulns += [PSCustomObject]@{
                Severity = "Medium"
                Type = "Remote Access"
                Description = "VNC service exposed (port 5900)."
                Recommendation = "Use SSH tunneling, strong passwords, and access controls for VNC"
            }
        }
        
        # SMB checks
        if ($openPortsList -contains 445) {
            $hostVulns += [PSCustomObject]@{
                Severity = "Medium"
                Type = "File Sharing"
                Description = "SMB service exposed (port 445)."
                Recommendation = "Restrict SMB access with firewall rules, disable SMBv1"
            }
            
            # Check for open shares
            if ($hostItem.Shares -ne "") {
                $hostVulns += [PSCustomObject]@{
                    Severity = "High"
                    Type = "Excessive Exposure"
                    Description = "Open network shares detected: $($hostItem.Shares)"
                    Recommendation = "Review and secure shared folders with appropriate permissions"
                }
            }
        }
        
        # Database exposure checks
        if ($openPortsList -contains 1433) {
            $hostVulns += [PSCustomObject]@{
                Severity = "High"
                Type = "Database Exposure"
                Description = "MS SQL Server exposed (port 1433)."
                Recommendation = "Restrict database access with firewall rules, use strong authentication"
            }
        }
        
        if ($openPortsList -contains 3306) {
            $hostVulns += [PSCustomObject]@{
                Severity = "High"
                Type = "Database Exposure"
                Description = "MySQL/MariaDB exposed (port 3306)."
                Recommendation = "Restrict database access with firewall rules, use strong authentication"
            }
        }
        
        # Only add hosts with vulnerabilities
        if ($hostVulns.Count -gt 0) {
            [void]$vulnerabilities.Add([PSCustomObject]@{
                IPAddress = $hostItem.IPAddress
                Hostname = $hostItem.Hostname
                DeviceType = $hostItem.DeviceType
                Vulnerabilities = $hostVulns
            })
        }
    }
    
    # Display vulnerability summary
    if ($vulnerabilities.Count -gt 0) {
        Write-Host "Found potential vulnerabilities on " -NoNewline -ForegroundColor White
        Write-Host "$($vulnerabilities.Count)" -NoNewline -ForegroundColor Red
        Write-Host " hosts:`n" -ForegroundColor White
        
        foreach ($vulnHost in $vulnerabilities) {
            Write-Host "Host: " -NoNewline -ForegroundColor White
            Write-Host "$($vulnHost.IPAddress)" -NoNewline -ForegroundColor Green
            
            if ($vulnHost.Hostname -ne "Unknown") {
                Write-Host " ($($vulnHost.Hostname))" -NoNewline -ForegroundColor Cyan
            }
            
            Write-Host " - $($vulnHost.DeviceType)" -ForegroundColor Yellow
            
            foreach ($vuln in $vulnHost.Vulnerabilities) {
                # Set color based on severity
                $severityColor = switch ($vuln.Severity) {
                    "High" { "Red" }
                    "Medium" { "Yellow" }
                    "Low" { "Cyan" }
                    default { "White" }
                }
                
                Write-Host "  [" -NoNewline -ForegroundColor White
                Write-Host "$($vuln.Severity)" -NoNewline -ForegroundColor $severityColor
                Write-Host "] " -NoNewline -ForegroundColor White
                Write-Host "$($vuln.Type): " -NoNewline -ForegroundColor Magenta
                Write-Host "$($vuln.Description)" -ForegroundColor White
                Write-Host "     → Recommendation: " -NoNewline -ForegroundColor DarkCyan
                Write-Host "$($vuln.Recommendation)" -ForegroundColor White
            }
            Write-Host ""
        }
    } else {
        Write-Host "No obvious vulnerabilities detected in the scanned hosts." -ForegroundColor Green
        Write-Host "Note: This is a basic assessment and does not replace a professional security audit." -ForegroundColor Yellow
    }
    
    Write-Host "`n═════════════════════════════════════════════`n" -ForegroundColor Cyan
    
    return $vulnerabilities
}

function Show-ResultSummary {
    param (
        [Parameter(Mandatory=$true)]
        [array]$Results
    )
    
    Write-Host "`n═════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "             SCAN RESULTS SUMMARY             " -ForegroundColor Yellow
    Write-Host "═════════════════════════════════════════════`n" -ForegroundColor Cyan
    
    # Device types summary
    $deviceTypes = $Results | Group-Object -Property DeviceType | Sort-Object -Property Count -Descending
    
    Write-Host "Device Types:" -ForegroundColor Magenta
    foreach ($type in $deviceTypes) {
        # Color-code device types
        $color = switch -Regex ($type.Name) {
            "Server" { "Red" }
            "Router|Gateway|Network" { "Magenta" }
            "Windows" { "Blue" }
            "Linux|Unix" { "Yellow" }
            "Web" { "Cyan" }
            "Printer" { "DarkYellow" }
            "Camera" { "DarkCyan" }
            default { "White" }
        }
        
        Write-Host "  $($type.Name): " -NoNewline -ForegroundColor $color
        Write-Host "$($type.Count)" -ForegroundColor Green
    }
    
    # Open ports summary
    $allPorts = @()
    foreach ($result in $Results) {
        if ($result.OpenPorts -ne "") {
            $ports = $result.OpenPorts -split ", "
            foreach ($port in $ports) {
                if ($port -match "(\d+) \((.+)\)") {
                    $allPorts += [PSCustomObject]@{
                        Port = $matches[1]
                        Service = $matches[2]
                    }
                }
            }
        }
    }
    
    # Correctly count and group the ports found
    $portSummary = $allPorts | Group-Object -Property Service | Sort-Object -Property Count -Descending
    
    if ($portSummary.Count -gt 0) {
        Write-Host "`nCommon Services:" -ForegroundColor Magenta
        foreach ($service in $portSummary | Select-Object -First 10) {
            # Color services based on security implications
            $color = switch -Regex ($service.Name) {
                "SSH|HTTPS|SFTP" { "Green" }
                "HTTP|FTP|Telnet" { "Yellow" }
                "NetBIOS|SMB|RPC" { "Cyan" }
                "SQL|MySQL" { "Magenta" }
                "RDP|VNC" { "Red" }
                default { "White" }
            }
            
            Write-Host "  $($service.Name): " -NoNewline -ForegroundColor $color
            Write-Host "$($service.Count)" -ForegroundColor Green
        }
    }
    
    # Shares summary
    $hostsWithShares = $Results | Where-Object { $_.Shares -ne "" -and $_.Shares -ne $null }
    if ($hostsWithShares.Count -gt 0) {
        Write-Host "`nHosts with Shares: " -NoNewline -ForegroundColor Magenta
        Write-Host "$($hostsWithShares.Count)" -ForegroundColor Green
        
        # Show the hosts with shares for clarity
        foreach ($shareHost in $hostsWithShares) {
            Write-Host "  $($shareHost.IPAddress) " -NoNewline -ForegroundColor Green
            if ($shareHost.Hostname -ne "Unknown") {
                Write-Host "($($shareHost.Hostname)) " -NoNewline -ForegroundColor Cyan
            }
            Write-Host "- " -NoNewline
            Write-Host "$($shareHost.Shares)" -ForegroundColor Yellow
        }
    }
    
    Write-Host "`n═════════════════════════════════════════════`n" -ForegroundColor Cyan
}

function Show-Menu {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$NetworkInfo
    )
    
    $header = @"
    
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║                         POWERSWEEP                                ║
║                   Network Discovery Tool                          ║
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
        ScanPorts = $true
        DiscoverShares = $true
        VulnerabilityScan = $true
        ExportResults = $false
        ExportPath = "$env:USERPROFILE\Desktop\NetworkScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
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
        
        Write-Host "│ " -NoNewline -ForegroundColor Cyan
        Write-Host "4. Scan Ports   : " -NoNewline -ForegroundColor White
        $portColor = if ($scanOptions.ScanPorts) { "Green" } else { "Red" }
        Write-Host "$($scanOptions.ScanPorts)" -NoNewline -ForegroundColor $portColor
        Write-Host " ".PadRight(48 - ($scanOptions.ScanPorts.ToString().Length)) -NoNewline
        Write-Host "│" -ForegroundColor Cyan
        
        Write-Host "│ " -NoNewline -ForegroundColor Cyan
        Write-Host "5. Find Shares  : " -NoNewline -ForegroundColor White
        $shareColor = if ($scanOptions.DiscoverShares) { "Green" } else { "Red" }
        Write-Host "$($scanOptions.DiscoverShares)" -NoNewline -ForegroundColor $shareColor
        Write-Host " ".PadRight(48 - ($scanOptions.DiscoverShares.ToString().Length)) -NoNewline
        Write-Host "│" -ForegroundColor Cyan
        
        Write-Host "│ " -NoNewline -ForegroundColor Cyan
        Write-Host "6. Vuln Scan    : " -NoNewline -ForegroundColor White
        $vulnColor = if ($scanOptions.VulnerabilityScan) { "Green" } else { "Red" }
        Write-Host "$($scanOptions.VulnerabilityScan)" -NoNewline -ForegroundColor $vulnColor
        Write-Host " ".PadRight(48 - ($scanOptions.VulnerabilityScan.ToString().Length)) -NoNewline
        Write-Host "│" -ForegroundColor Cyan
        
        Write-Host "│ " -NoNewline -ForegroundColor Cyan
        Write-Host "7. Export       : " -NoNewline -ForegroundColor White
        $exportColor = if ($scanOptions.ExportResults) { "Green" } else { "Red" }
        Write-Host "$($scanOptions.ExportResults)" -NoNewline -ForegroundColor $exportColor
        Write-Host " ".PadRight(48 - ($scanOptions.ExportResults.ToString().Length)) -NoNewline
        Write-Host "│" -ForegroundColor Cyan
        
        if ($scanOptions.ExportResults) {
            Write-Host "│ " -NoNewline -ForegroundColor Cyan
            Write-Host "8. Export Path  : " -NoNewline -ForegroundColor White
            # Shorten path display if it's too long
            $pathDisplay = $scanOptions.ExportPath
            if ($pathDisplay.Length > 45) {
                $pathDisplay = "..." + $pathDisplay.Substring($pathDisplay.Length - 42)
            }
            Write-Host "$pathDisplay" -NoNewline -ForegroundColor Green
            Write-Host " ".PadRight(48 - $pathDisplay.Length) -NoNewline
            Write-Host "│" -ForegroundColor Cyan
        }
        
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
            "4" {
                $scanOptions.ScanPorts = -not $scanOptions.ScanPorts
            }
            "5" {
                $scanOptions.DiscoverShares = -not $scanOptions.DiscoverShares
            }
            "6" {
                $scanOptions.VulnerabilityScan = -not $scanOptions.VulnerabilityScan
            }
            "7" {
                $scanOptions.ExportResults = -not $scanOptions.ExportResults
            }
            "8" {
                if ($scanOptions.ExportResults) {
                    $scanOptions.ExportPath = Read-Host "Enter export path"
                }
            }
            "[Ss]" {
                $menuActive = $false
                $results = Scan-Network -StartIP $scanOptions.StartIP -EndIP $scanOptions.EndIP -TimeoutMilliseconds $scanOptions.Timeout -MaxThreads $scanOptions.ThreadCount -ScanPorts $scanOptions.ScanPorts -DiscoverShares $scanOptions.DiscoverShares -ExportResults $scanOptions.ExportResults -ExportPath $scanOptions.ExportPath
                
                if ($results.Count -gt 0) {
                    Show-ResultSummary -Results $results
                    
                    $viewDetails = Read-Host "View detailed results? (Y/N)"
                    if ($viewDetails -eq "Y" -or $viewDetails -eq "y") {
                        # More compact table format
                        $results | Format-Table -Property @{
                            Label = "IP"; Expression = {$_.IPAddress}; Width = 15
                        }, @{
                            Label = "Hostname"; Expression = {$_.Hostname}; Width = 25; Alignment = "Left"
                        }, @{
                            Label = "Type"; Expression = {$_.DeviceType}; Width = 15
                        }, @{
                            Label = "Response"; Expression = {$_.ResponseTime}; Width = 10
                        }, @{
                            Label = "Open Ports"; Expression = {$_.OpenPorts}; Width = 30
                        } -AutoSize -Wrap
                    }
                    
                    # Run vulnerability assessment if enabled
                    if ($scanOptions.VulnerabilityScan) {
                        $vulnerabilities = Scan-Vulnerabilities -Results $results
                    }
                    
                    # Add CSV export prompt if not already exporting
                    if (-not $scanOptions.ExportResults) {
                        $exportNow = Read-Host "Would you like to export these results to a CSV file? (Y/N)"
                        if ($exportNow -eq "Y" -or $exportNow -eq "y") {
                            $defaultPath = "$env:USERPROFILE\Desktop\NetworkScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                            $exportPath = Read-Host "Enter export path or press Enter to use default [$defaultPath]"
                            
                            if ([string]::IsNullOrWhiteSpace($exportPath)) {
                                $exportPath = $defaultPath
                            }
                            
                            try {
                                # Ensure the directory exists
                                $directory = Split-Path -Path $exportPath -Parent
                                if (-not (Test-Path -Path $directory)) {
                                    New-Item -Path $directory -ItemType Directory -Force | Out-Null
                                    Write-Host "Created directory: $directory" -ForegroundColor Yellow
                                }
                                
                                # Sort results by IP address numerically
                                $sortedResults = $results | Sort-Object { 
                                    $octets = $_.IPAddress -split '\.'
                                    [int]$octets[0]*16777216 + [int]$octets[1]*65536 + [int]$octets[2]*256 + [int]$octets[3]
                                }
                                $sortedResults | Export-Csv -Path $exportPath -NoTypeInformation
                                Write-Host "Results exported to: " -NoNewline -ForegroundColor White
                                Write-Host "$exportPath" -ForegroundColor Green
                            } catch {
                                Write-Host "Error exporting results: $($_.Exception.Message)" -ForegroundColor Red
                                
                                # Suggest an alternative location
                                $alternativePath = "$env:USERPROFILE\Documents\NetworkScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                                $tryAlternative = Read-Host "Would you like to try saving to $alternativePath instead? (Y/N)"
                                if ($tryAlternative -eq "Y" -or $tryAlternative -eq "y") {
                                    try {
                                        $sortedResults | Export-Csv -Path $alternativePath -NoTypeInformation
                                        Write-Host "Results exported to: " -NoNewline -ForegroundColor White
                                        Write-Host "$alternativePath" -ForegroundColor Green
                                    } catch {
                                        Write-Host "Error exporting to alternative location: $($_.Exception.Message)" -ForegroundColor Red
                                    }
                                }
                            }
                        }
                    }
                } else {
                    Write-Host "No active hosts found in the specified range." -ForegroundColor Yellow
                }
                
                $scanAgain = Read-Host "Scan again? (Y/N)"
                if ($scanAgain -eq "Y" -or $scanAgain -eq "y") {
                    $menuActive = $true
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
                                                                                         
        Advanced PowerShell Network Discovery Tool by Ulises Paiz
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
    Write-Host "Some features like MAC address detection and share discovery may not work properly." -ForegroundColor Yellow
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
Write-Host "║                Thank you for using PowerSweep!                      ║" -ForegroundColor Cyan
Write-Host "║                                                                     ║" -ForegroundColor Cyan
Write-Host "╚═════════════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
