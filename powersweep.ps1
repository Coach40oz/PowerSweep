#requires -RunAsAdministrator
<#
.SYNOPSIS
    PowerSweep - Advanced PowerShell Network Scanner with Enhanced GUI
.DESCRIPTION
    A comprehensive network scanning tool that discovers active hosts,
    performs port scanning, identifies services, discovers shares,
    determines device types, and performs vulnerability assessment,
    all with an improved, user-friendly console interface.
.NOTES
    Author: Ulises Paiz
    Version: 4.0
#>

# Set console properties for better display
$Host.UI.RawUI.WindowTitle = "PowerSweep v4.0"
if ($Host.UI.RawUI.WindowSize.Width -lt 120) {
    try {
        $Host.UI.RawUI.WindowSize = New-Object System.Management.Automation.Host.Size(120, 40)
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
    
    # Create a visual representation of where the IP is in the range
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

function Get-DeviceType {
    param (
        [string]$ip,
        [array]$openPorts = @(),
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
    
    $portScanStatus = if ($ScanPorts) { "Enabled" } else { "Disabled" }
    $shareDiscoveryStatus = if ($DiscoverShares) { "Enabled" } else { "Disabled" }
    
    $scanInfo = @(
        "Preparing to scan $totalIPs IP addresses",
        "Range: $StartIP to $EndIP",
        "Timeout: $TimeoutMilliseconds ms per host",
        "Thread count: $MaxThreads concurrent scans",
        "Port scanning: $portScanStatus",
        "Share discovery: $shareDiscoveryStatus"
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
    
    # Common ports to scan
    $commonPorts = @(
        20, 21, 22, 23, 25, 53, 80, 88, 110, 123, 135, 139, 143, 
        389, 443, 445, 465, 587, 636, 993, 995, 1433, 1434, 
        3306, 3389, 5900, 8080, 8443, 9100
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
        8443 = "HTTPS Alt"
        9100 = "Printer"
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
            
            $openPorts = @()
            $openPortNumbers = @()
            
            if ($scanPorts) {
                foreach ($port in $ports) {
                    $tcpClient = New-Object System.Net.Sockets.TcpClient
                    try {
                        $connectResult = $tcpClient.BeginConnect($ipAddress, $port, $null, $null)
                        $connected = $connectResult.AsyncWaitHandle.WaitOne([Math]::Min(200, $timeout), $false)
                        
                        if ($connected -and $tcpClient.Connected) {
                            $service = "Unknown"
                            if ($serviceDict -ne $null -and $port -ne $null -and $serviceDict.ContainsKey($port)) { 
                                $service = $serviceDict[$port] 
                            }
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
            
            # Determine device type
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
        
        # Create a PowerShell instance with needed parameters
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
        $currentTime = Get-Date
        
        if (($currentTime - $lastUpdateTime) -gt $updateInterval) {
            # Calculate scan rate and ETA
            $elapsedSeconds = ($currentTime - $scanStartTime).TotalSeconds
            $scanRate = if ($elapsedSeconds -gt 0) { $totalScanned / $elapsedSeconds } else { 0 }
            $remainingIPs = $totalIPs - $totalScanned
            $estimatedSecondsRemaining = if ($scanRate -gt 0) { $remainingIPs / $scanRate } else { 0 }
            $estimatedTimeRemaining = [TimeSpan]::FromSeconds($estimatedSecondsRemaining)
            
            # Clear current progress line
            Write-Host "`r".PadRight(120, " ") -NoNewline
            
            # Write new progress line
            Write-Host "`r" -NoNewline
            Write-Host "Scanning progress: " -NoNewline -ForegroundColor White
            Show-ProgressBar -PercentComplete $percentComplete -Width 50 -FillColor Cyan -EmptyColor DarkGray
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
    Write-Host "`r".PadRight(120, " ")
    
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
    
    $portScanStatus = if ($ScanPorts) { "Enabled" } else { "Disabled" }
    $shareDiscoveryStatus = if ($DiscoverShares) { "Enabled" } else { "Disabled" }
    
    $scanCompleteContent = @(
        "Scan completed at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        "Duration: $durationStr",
        "Total IPs Scanned: $totalIPs",
        "Active Hosts Found: $totalActive",
        "Port Scanning: $portScanStatus",
        "Share Discovery: $shareDiscoveryStatus"
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
    
    # If export option was selected, save results
    if ($ExportResults) {
        try {
            # Ensure the directory exists
            $directory = Split-Path -Path $ExportPath -Parent
            if (-not (Test-Path -Path $directory)) {
                New-Item -Path $directory -ItemType Directory -Force | Out-Null
            }
            
            # Sort results by IP address numerically
            $sortedResults = $results | Sort-Object { 
                $octets = $_.IPAddress -split '\.'
                [int]$octets[0]*16777216 + [int]$octets[1]*65536 + [int]$octets[2]*256 + [int]$octets[3]
            }
            $sortedResults | Export-Csv -Path $ExportPath -NoTypeInformation
            
            $exportContent = @(
                "Results exported to:",
                "$ExportPath"
            )
            
            Show-InfoBox -Title "EXPORT COMPLETE" -Content $exportContent -BorderColor Green -TitleColor White
        } catch {
            $errorContent = @(
                "Error exporting results:",
                "$($_.Exception.Message)",
                "",
                "Would you like to try an alternative location?"
            )
            
            Show-InfoBox -Title "EXPORT ERROR" -Content $errorContent -BorderColor Red -TitleColor Yellow
            
            # Suggest an alternative location
            $alternativePath = "$env:USERPROFILE\Documents\NetworkScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
            $tryAlternative = Read-Host "Save to $alternativePath instead? (Y/N)"
            if ($tryAlternative -eq "Y" -or $tryAlternative -eq "y") {
                try {
                    $sortedResults | Export-Csv -Path $alternativePath -NoTypeInformation
                    
                    $altExportContent = @(
                        "Results exported to alternative location:",
                        "$alternativePath"
                    )
                    
                    Show-InfoBox -Title "EXPORT COMPLETE" -Content $altExportContent -BorderColor Green -TitleColor White
                } catch {
                    $altErrorContent = @(
                        "Error exporting to alternative location:",
                        "$($_.Exception.Message)"
                    )
                    
                    Show-InfoBox -Title "EXPORT ERROR" -Content $altErrorContent -BorderColor Red -TitleColor Yellow
                }
            }
        }
    }
    
    # Display scan results
    if ($results.Count -gt 0) {
        Write-Host "`n" -NoNewline
        $frameWidth = 110
        
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
        Write-Host "".PadRight(18, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┬" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(10, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┬" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight($frameWidth - 73, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┤" -ForegroundColor Cyan
        
        # Header row
        Write-Host "│" -NoNewline -ForegroundColor Cyan
        Write-Host " IP Address".PadRight(15, " ") -NoNewline -ForegroundColor White
        Write-Host "│" -NoNewline -ForegroundColor Cyan
        Write-Host " Hostname".PadRight(25, " ") -NoNewline -ForegroundColor White
        Write-Host "│" -NoNewline -ForegroundColor Cyan
        Write-Host " Device Type".PadRight(18, " ") -NoNewline -ForegroundColor White
        Write-Host "│" -NoNewline -ForegroundColor Cyan
        Write-Host " Response".PadRight(10, " ") -NoNewline -ForegroundColor White
        Write-Host "│" -NoNewline -ForegroundColor Cyan
        Write-Host " Open Ports/Shares".PadRight($frameWidth - 73, " ") -NoNewline -ForegroundColor White
        Write-Host "│" -ForegroundColor Cyan
        
        Write-Host "├" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(15, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┼" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(25, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┼" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(18, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┼" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(10, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┼" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight($frameWidth - 73, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┤" -ForegroundColor Cyan
        
        # Sort results by IP address numerically
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
            $deviceTypePadded = "$($result.DeviceType)".PadRight(17, " ")
            switch -Regex ($result.DeviceType) {
                "Server" { Write-Host $deviceTypePadded -NoNewline -ForegroundColor Red }
                "Router|Gateway|Network" { Write-Host $deviceTypePadded -NoNewline -ForegroundColor Magenta }
                "Windows" { Write-Host $deviceTypePadded -NoNewline -ForegroundColor Blue }
                "Linux|Unix" { Write-Host $deviceTypePadded -NoNewline -ForegroundColor Yellow }
                "Web" { Write-Host $deviceTypePadded -NoNewline -ForegroundColor Cyan }
                "Printer" { Write-Host $deviceTypePadded -NoNewline -ForegroundColor DarkYellow }
                "Camera" { Write-Host $deviceTypePadded -NoNewline -ForegroundColor DarkCyan }
                default { Write-Host $deviceTypePadded -NoNewline -ForegroundColor White }
            }
            
            Write-Host "│" -NoNewline -ForegroundColor Cyan
            Write-Host " $($result.ResponseTime)".PadRight(10, " ") -NoNewline -ForegroundColor Yellow
            Write-Host "│" -NoNewline -ForegroundColor Cyan
            
            # Display ports and shares
            $portsShares = ""
            if ($result.OpenPorts -ne "") {
                $portsShares = "Ports: $($result.OpenPorts)"
            }
            
            if ($result.Shares -ne "") {
                if ($portsShares -ne "") {
                    $portsShares += " | "
                }
                $portsShares += "Shares: $($result.Shares)"
            }
            
            # Truncate if too long
            $maxLength = $frameWidth - 73 - 2
            if ($portsShares.Length -gt $maxLength) {
                $portsShares = $portsShares.Substring(0, $maxLength - 3) + "..."
            }
            
            Write-Host " $portsShares".PadRight($frameWidth - 73, " ") -NoNewline -ForegroundColor Gray
            Write-Host "│" -ForegroundColor Cyan
        }
        
        # Bottom border
        Write-Host "└" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(15, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┴" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(25, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┴" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(18, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┴" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight(10, "─") -NoNewline -ForegroundColor Cyan
        Write-Host "┴" -NoNewline -ForegroundColor Cyan
        Write-Host "".PadRight($frameWidth - 73, "─") -NoNewline -ForegroundColor Cyan
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

function Scan-Vulnerabilities {
    param (
        [Parameter(Mandatory=$true)]
        [array]$Results
    )
    
    $vulnerabilityHeaderContent = @(
        "Analyzing discovered hosts for potential security issues...",
        "This basic assessment checks for common misconfigurations and exposures.",
        "Note: This does not replace a professional security audit.",
        ""
    )
    
    Show-InfoBox -Title "VULNERABILITY ASSESSMENT" -Content $vulnerabilityHeaderContent -BorderColor Red -TitleColor Yellow -ContentColor White
    
    $vulnerabilities = New-Object System.Collections.ArrayList
    
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
                References = "NIST SP 800-52, PCI DSS 4.0 Req 4.2.1"
            }
        }
        
        if ($openPortsList -contains 23) {
            $hostVulns += [PSCustomObject]@{
                Severity = "High"
                Type = "Insecure Protocol"
                Description = "Telnet service detected (port 23). Telnet transmits credentials in cleartext."
                Recommendation = "Replace with SSH (port 22)"
                References = "CIS Controls 4.5, NIST SP 800-53 IA-2(1)"
            }
        }
        
        if ($openPortsList -contains 80 -and -not ($openPortsList -contains 443)) {
            $hostVulns += [PSCustomObject]@{
                Severity = "Medium"
                Type = "Insecure Protocol"
                Description = "HTTP without HTTPS detected. Data transmitted in cleartext."
                Recommendation = "Implement HTTPS with valid certificates"
                References = "OWASP Top 10 A02:2021, PCI DSS 4.0 Req 4.2.1"
            }
        }
        
        # Check for risky services
        if ($openPortsList -contains 3389) {
            $hostVulns += [PSCustomObject]@{
                Severity = "Medium"
                Type = "Remote Access"
                Description = "RDP service exposed (port 3389)."
                Recommendation = "Restrict RDP access with firewall rules, use strong passwords and Network Level Authentication (NLA)"
                References = "CIS Controls 4.5, NIST SP 800-46"
            }
        }
        
        if ($openPortsList -contains 5900) {
            $hostVulns += [PSCustomObject]@{
                Severity = "Medium"
                Type = "Remote Access"
                Description = "VNC service exposed (port 5900)."
                Recommendation = "Use SSH tunneling, strong passwords, and access controls for VNC"
                References = "CIS Controls 4.3, NIST SP 800-46"
            }
        }
        
        # SMB checks
        if ($openPortsList -contains 445) {
            $hostVulns += [PSCustomObject]@{
                Severity = "Medium"
                Type = "File Sharing"
                Description = "SMB service exposed (port 445)."
                Recommendation = "Restrict SMB access with firewall rules, disable SMBv1, apply latest patches"
                References = "MS17-010, CVE-2017-0143 to CVE-2017-0148"
            }
            
            # Check for open shares
            if ($hostItem.Shares -ne "") {
                $hostVulns += [PSCustomObject]@{
                    Severity = "High"
                    Type = "Excessive Exposure"
                    Description = "Open network shares detected: $($hostItem.Shares)"
                    Recommendation = "Review and secure shared folders with appropriate permissions"
                    References = "CIS Controls 13.4, NIST SP 800-53 AC-3, AC-6"
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
                References = "CIS Controls 4.5, NIST SP 800-53 SC-7"
            }
        }
        
        if ($openPortsList -contains 3306) {
            $hostVulns += [PSCustomObject]@{
                Severity = "High"
                Type = "Database Exposure"
                Description = "MySQL/MariaDB exposed (port 3306)."
                Recommendation = "Restrict database access with firewall rules, use strong authentication"
                References = "CIS Controls 4.5, NIST SP 800-53 SC-7"
            }
        }
        
        # Web server checks 
        if ($openPortsList -contains 8080) {
            $hostVulns += [PSCustomObject]@{
                Severity = "Medium"
                Type = "Web Application"
                Description = "HTTP Proxy or alternate web port (8080) detected."
                Recommendation = "Ensure the web application is patched and properly configured. Consider using HTTPS."
                References = "OWASP Top 10, CIS Controls 18.1"
            }
        }
        
        # Printer access
        if ($openPortsList -contains 9100) {
            $hostVulns += [PSCustomObject]@{
                Severity = "Low"
                Type = "Printer Access"
                Description = "Printer port (9100) directly accessible."
                Recommendation = "Restrict printer port access to authorized systems only."
                References = "CIS Controls 12, NIST SP 800-53 AC-3"
            }
        }
        
        # Multiple high-risk ports
        $highRiskPorts = @(21, 23, 3389, 5900, 1433, 3306)
        $detectedHighRiskPorts = $openPortsList | Where-Object { $highRiskPorts -contains $_ }
        if ($detectedHighRiskPorts.Count -ge 3) {
            $hostVulns += [PSCustomObject]@{
                Severity = "High"
                Type = "Multiple Exposures"
                Description = "Multiple high-risk services exposed: $($detectedHighRiskPorts -join ', ')"
                Recommendation = "Review and minimize exposed services. Implement network segmentation and strict access controls."
                References = "CIS Controls 4.5, NIST SP 800-53 CM-7, SC-7"
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
        # Count vulnerability severities
        $highVulns = 0
        $mediumVulns = 0
        $lowVulns = 0
        
        foreach ($vulnHost in $vulnerabilities) {
            foreach ($vuln in $vulnHost.Vulnerabilities) {
                if ($vuln.Severity -eq "High") {
                    $highVulns++
                } elseif ($vuln.Severity -eq "Medium") {
                    $mediumVulns++
                } elseif ($vuln.Severity -eq "Low") {
                    $lowVulns++
                }
            }
        }
        
        $vulnSummaryContent = @(
            "Found potential vulnerabilities on $($vulnerabilities.Count) out of $($Results.Count) hosts",
            "Potential security issues by severity:",
            "  High: $highVulns",
            "  Medium: $mediumVulns",
            "  Low: $lowVulns"
        )
        
        Show-InfoBox -Title "VULNERABILITY SUMMARY" -Content $vulnSummaryContent -BorderColor Red -TitleColor Yellow
        
        foreach ($vulnHost in $vulnerabilities) {
            $hostContent = @(
                "IP Address: $($vulnHost.IPAddress)",
                "Hostname: $($vulnHost.Hostname)",
                "Device Type: $($vulnHost.DeviceType)",
                "Detected Issues: $($vulnHost.Vulnerabilities.Count)"
            )
            
            Show-InfoBox -Title "HOST VULNERABILITIES" -Content $hostContent -BorderColor Yellow -TitleColor Red
            
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
                if ($vuln.References) {
                    Write-Host "     → References: " -NoNewline -ForegroundColor DarkCyan
                    Write-Host "$($vuln.References)" -ForegroundColor Gray
                }
                Write-Host ""
            }
        }
    } else {
        $noVulnsContent = @(
            "No obvious vulnerabilities detected in the scanned hosts.",
            "This does not guarantee security - a professional audit is recommended",
            "for critical systems and networks.",
            "",
            "Best practices to consider:",
            " - Regularly update and patch all systems",
            " - Implement network segmentation",
            " - Use strong authentication mechanisms",
            " - Monitor systems for suspicious activity",
            " - Create and test incident response procedures"
        )
        
        Show-InfoBox -Title "NO VULNERABILITIES DETECTED" -Content $noVulnsContent -BorderColor Green -TitleColor White
    }
    
    return $vulnerabilities
}

function Export-HtmlReport {
    param (
        [Parameter(Mandatory=$true)]
        [array]$Results,
        
        [array]$Vulnerabilities = @(),
        
        [string]$ExportPath = "$env:USERPROFILE\Desktop\NetworkScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    )
    
    $reportHeaderContent = @(
        "Creating HTML report of scan results...",
        "This will generate a detailed report you can view in any web browser.",
        "",
        "Report will be saved to:",
        "$ExportPath"
    )
    
    Show-InfoBox -Title "HTML REPORT GENERATION" -Content $reportHeaderContent -BorderColor Magenta -TitleColor Yellow
    
    # Create HTML content with proper formatting - using a StringBuilder for better performance
    $htmlHeadContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PowerSweep Network Scan Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
            background-color: #f5f5f5;
        }
        h1, h2, h3 {
            color: #0066cc;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 20px;
            box-shadow: 0 0 10px rgba(0,0,0,0.1);
            border-radius: 5px;
        }
        .header {
            background-color: #0066cc;
            color: white;
            padding: 10px 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            text-align: center;
        }
        .section {
            margin-bottom: 30px;
            padding-bottom: 20px;
            border-bottom: 1px solid #eee;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        th, td {
            padding: 10px;
            text-align: left;
            border: 1px solid #ddd;
        }
        th {
            background-color: #f2f2f2;
            font-weight: bold;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        tr:hover {
            background-color: #f0f0f0;
        }
        .host-online {
            color: green;
            font-weight: bold;
        }
        .hostname {
            color: #0066cc;
        }
        .vulnerability-high {
            background-color: #ffdddd;
        }
        .vulnerability-medium {
            background-color: #ffffcc;
        }
        .vulnerability-low {
            background-color: #e6f3ff;
        }
        .device-server {
            color: #cc0000;
        }
        .device-network {
            color: #9900cc;
        }
        .device-printer {
            color: #cc6600;
        }
        .device-camera {
            color: #006666;
        }
        .meta-info {
            font-size: 0.9em;
            color: #666;
            margin-bottom: 10px;
        }
        .footer {
            text-align: center;
            margin-top: 20px;
            font-size: 0.8em;
            color: #666;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>PowerSweep Network Scan Report</h1>
            <p>Generated on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
        </div>
        
        <div class="section">
            <h2>Scan Summary</h2>
            <p class="meta-info">
                Scan range: $($Results[0].IPAddress) to $($Results[-1].IPAddress)<br>
                Total hosts discovered: $($Results.Count)<br>
                Scan date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
            </p>
        </div>
        
        <div class="section">
            <h2>Device Types Summary</h2>
            <table>
                <tr>
                    <th>Device Type</th>
                    <th>Count</th>
                    <th>Percentage</th>
                </tr>
"@

    # Create device type summary rows
    $deviceTypeSummary = $Results | Group-Object -Property DeviceType | Sort-Object -Property Count -Descending
    $deviceTypeRows = ""
    
    foreach ($type in $deviceTypeSummary) {
        $percentage = [Math]::Round(($type.Count / $Results.Count) * 100, 1)
        $cssClass = "device-other"
        
        if ($type.Name -match "Server") {
            $cssClass = "device-server"
        } elseif ($type.Name -match "Router|Gateway|Network") {
            $cssClass = "device-network"
        } elseif ($type.Name -match "Printer") {
            $cssClass = "device-printer"
        } elseif ($type.Name -match "Camera") {
            $cssClass = "device-camera"
        }
        
        $deviceTypeRows += @"
                <tr>
                    <td class="$cssClass">$($type.Name)</td>
                    <td>$($type.Count)</td>
                    <td>$percentage%</td>
                </tr>
"@
    }
    
    $hostTableHeader = @"
            </table>
        </div>
        
        <div class="section">
            <h2>Discovered Hosts</h2>
            <table>
                <tr>
                    <th>IP Address</th>
                    <th>Hostname</th>
                    <th>Device Type</th>
                    <th>Response Time</th>
                    <th>MAC Address</th>
                    <th>Open Ports</th>
                    <th>Shares</th>
                </tr>
"@
    
    # Create host rows
    $hostRows = ""
    foreach ($hostItem in $Results) {
        $cssClass = "device-other"
        
        if ($hostItem.DeviceType -match "Server") {
            $cssClass = "device-server"
        } elseif ($hostItem.DeviceType -match "Router|Gateway|Network") {
            $cssClass = "device-network"
        } elseif ($hostItem.DeviceType -match "Printer") {
            $cssClass = "device-printer"
        } elseif ($hostItem.DeviceType -match "Camera") {
            $cssClass = "device-camera"
        }
        
        $hostRows += @"
                <tr>
                    <td class="host-online">$($hostItem.IPAddress)</td>
                    <td class="hostname">$($hostItem.Hostname)</td>
                    <td class="$cssClass">$($hostItem.DeviceType)</td>
                    <td>$($hostItem.ResponseTime)</td>
                    <td>$($hostItem.MAC)</td>
                    <td>$($hostItem.OpenPorts)</td>
                    <td>$($hostItem.Shares)</td>
                </tr>
"@
    }
    
    $vulnerabilitySection = ""
    if ($Vulnerabilities.Count -gt 0) {
        $vulnerabilityTableHeader = @"
            </table>
        </div>
        
        <div class="section">
            <h2>Vulnerability Assessment</h2>
            <p class="meta-info">
                Hosts with potential vulnerabilities: $($Vulnerabilities.Count) out of $($Results.Count)
            </p>
"@
        
        $vulnerabilityRows = ""
        foreach ($vulnHost in $Vulnerabilities) {
            $vulnerabilityRows += @"
            <h3>$($vulnHost.IPAddress) - $($vulnHost.Hostname)</h3>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Description</th>
                    <th>Recommendation</th>
                </tr>
"@
            
            foreach ($vuln in $vulnHost.Vulnerabilities) {
                $severityCssClass = "vulnerability-medium"
                
                if ($vuln.Severity -eq "High") {
                    $severityCssClass = "vulnerability-high"
                } elseif ($vuln.Severity -eq "Low") {
                    $severityCssClass = "vulnerability-low"
                }
                
                $vulnerabilityRows += @"
                <tr class="$severityCssClass">
                    <td>$($vuln.Severity)</td>
                    <td>$($vuln.Type)</td>
                    <td>$($vuln.Description)</td>
                    <td>$($vuln.Recommendation)</td>
                </tr>
"@
            }
            
            $vulnerabilityRows += @"
            </table>
"@
        }
        
        $vulnerabilitySection = $vulnerabilityTableHeader + $vulnerabilityRows
    }
    
    $htmlFooter = @"
        </div>
        
        <div class="footer">
            <p>Generated by PowerSweep v4.0 | Author: Ulises Paiz</p>
        </div>
    </div>
</body>
</html>
"@
    
    # Combine all HTML content
    $htmlContent = $htmlHeadContent + $deviceTypeRows + $hostTableHeader + $hostRows + $vulnerabilitySection + $htmlFooter
    
    # Write HTML content to file
    try {
        # Ensure the directory exists
        $directory = Split-Path -Path $ExportPath -Parent
        if (-not (Test-Path -Path $directory)) {
            New-Item -Path $directory -ItemType Directory -Force | Out-Null
        }
        
        # Write the HTML content to the file
        $htmlContent | Out-File -FilePath $ExportPath -Encoding UTF8
        
        $successContent = @(
            "HTML report generated successfully!",
            "",
            "Saved to: $ExportPath",
            "",
            "You can open this file in any web browser to view the detailed report."
        )
        
        Show-InfoBox -Title "REPORT GENERATION COMPLETE" -Content $successContent -BorderColor Green -TitleColor White
        
        return $true
    }
    catch {
        $errorContent = @(
            "Error generating HTML report:",
            "$($_.Exception.Message)",
            "",
            "Please check the path and permissions and try again."
        )
        
        Show-InfoBox -Title "REPORT GENERATION ERROR" -Content $errorContent -BorderColor Red -TitleColor Yellow
        
        return $false
    }
}

function Show-ResultSummary {
    param (
        [Parameter(Mandatory=$true)]
        [array]$Results
    )
    
    $summaryHeaderContent = @(
        "Analysis of scan results",
        "Active hosts discovered: $($Results.Count)",
        ""
    )
    
    Show-InfoBox -Title "SCAN RESULTS SUMMARY" -Content $summaryHeaderContent -BorderColor Cyan -TitleColor Yellow -ContentColor White
    
    # Device types summary
    $deviceTypes = $Results | Group-Object -Property DeviceType | Sort-Object -Property Count -Descending
    
    $deviceTypeContent = @("Device Types Found:")
    foreach ($type in $deviceTypes) {
        $deviceTypeContent += "  $($type.Name): $($type.Count) ($([Math]::Round(($type.Count / $Results.Count) * 100, 1))%)"
    }
    
    Show-InfoBox -Title "DEVICE ANALYSIS" -Content $deviceTypeContent -BorderColor Blue -TitleColor White
    
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
        $serviceContent = @("Common Services Detected:")
        foreach ($service in $portSummary | Select-Object -First 10) {
            $serviceContent += "  $($service.Name): $($service.Count) hosts"
        }
        
        Show-InfoBox -Title "SERVICE ANALYSIS" -Content $serviceContent -BorderColor Magenta -TitleColor White
    }
    
    # Shares summary
    $hostsWithShares = $Results | Where-Object { $_.Shares -ne "" -and $_.Shares -ne $null }
    if ($hostsWithShares.Count -gt 0) {
        $shareContent = @(
            "Hosts with Shares: $($hostsWithShares.Count)",
            ""
        )
        
        foreach ($shareHost in $hostsWithShares) {
            $hostDisplay = "$($shareHost.IPAddress)"
            if ($shareHost.Hostname -ne "Unknown") {
                $hostDisplay += " ($($shareHost.Hostname))"
            }
            $shareContent += "$hostDisplay - Shares: $($shareHost.Shares)"
        }
        
        Show-InfoBox -Title "NETWORK SHARES" -Content $shareContent -BorderColor Yellow -TitleColor White
    }
    
    # Security analysis
    $insecureProtocolHosts = $Results | Where-Object { 
        $_.OpenPorts -match "21 \(FTP Control\)" -or 
        $_.OpenPorts -match "23 \(Telnet\)" -or 
        ($_.OpenPorts -match "80 \(HTTP\)" -and -not $_.OpenPorts -match "443 \(HTTPS\)")
    }
    
    $remoteAccessHosts = $Results | Where-Object { 
        $_.OpenPorts -match "3389 \(RDP\)" -or 
        $_.OpenPorts -match "5900 \(VNC\)"
    }
    
    $databaseHosts = $Results | Where-Object { 
        $_.OpenPorts -match "1433 \(MS SQL\)" -or 
        $_.OpenPorts -match "3306 \(MySQL\)"
    }
    
    if ($insecureProtocolHosts.Count -gt 0 -or $remoteAccessHosts.Count -gt 0 -or $databaseHosts.Count -gt 0) {
        $securityContent = @(
            "Quick Security Analysis:",
            "",
            "Hosts with insecure protocols: $($insecureProtocolHosts.Count)",
            "Hosts with remote access services: $($remoteAccessHosts.Count)",
            "Hosts with exposed databases: $($databaseHosts.Count)",
            "",
            "Run a vulnerability scan for detailed analysis"
        )
        
        Show-InfoBox -Title "SECURITY OVERVIEW" -Content $securityContent -BorderColor Red -TitleColor Yellow
    }
}

function Show-AnimatedBanner {
    $banner = @"
                                                                                
 ██████╗  ██████╗ ██╗    ██╗███████╗██████╗ ███████╗██╗    ██╗███████╗███████╗██████╗  
 ██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔══██╗██╔════╝██║    ██║██╔════╝██╔════╝██╔══██╗ 
 ██████╔╝██║   ██║██║ █╗ ██║█████╗  ██████╔╝███████╗██║ █╗ ██║█████╗  █████╗  ██████╔╝ 
 ██╔═══╝ ██║   ██║██║███╗██║██╔══╝  ██╔══██╗╚════██║██║███╗██║██╔══╝  ██╔══╝  ██╔═══╝  
 ██║     ╚██████╔╝╚███╔███╔╝███████╗██║  ██║███████║╚███╔███╔╝███████╗███████╗██║      
 ╚═╝      ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝      
                                         v4.0                                    
        Advanced PowerShell Network Discovery Tool by Ulises Paiz
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
    for ($i = 0; $i -lt 118; $i++) {
        Start-Sleep -Milliseconds 5
        Write-Host "─" -NoNewline -ForegroundColor Cyan
    }
    Write-Host "┐" -ForegroundColor Cyan
}

function Show-Menu {
    param (
        [Parameter(Mandatory=$true)]
        [hashtable]$NetworkInfo
    )
    
    Clear-Host
    Show-AnimatedBanner
    
    # Check if running as administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        $adminWarning = @(
            "This script is not running with administrator privileges.",
            "MAC address detection and share enumeration may not work properly.",
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
        ScanPorts = $true
        DiscoverShares = $true
        VulnerabilityScan = $true
        ExportResults = $false
        ExportPath = "$env:USERPROFILE\Desktop\NetworkScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    }
    
    $menuActive = $true
    
    while ($menuActive) {
        Clear-Host
        Show-AnimatedBanner
        
        # Create a visually appealing settings display
        $settingsContent = @(
            "1. IP Range     : $($scanOptions.StartIP) to $($scanOptions.EndIP)",
            "2. Timeout      : $($scanOptions.Timeout) ms",
            "3. Thread Count : $($scanOptions.ThreadCount)",
            "4. Scan Ports   : $($scanOptions.ScanPorts)",
            "5. Find Shares  : $($scanOptions.DiscoverShares)",
            "6. Vuln Scan    : $($scanOptions.VulnerabilityScan)",
            "7. Export       : $($scanOptions.ExportResults)",
            "8. Export Path  : $($scanOptions.ExportPath)"
        )
        
        Show-InfoBox -Title "CURRENT SETTINGS" -Content $settingsContent -BorderColor Cyan -TitleColor Yellow
        
        # Actions menu
        $actionsContent = @(
            "S. Start Network Scan",
            "C. Change IP Range to Custom Values",
            "N. Reset IP Range to Network Range",
            "T. Toggle Port Scanning",
            "H. Toggle Share Discovery",
            "V. Toggle Vulnerability Scanning",
            "E. Toggle Export Results",
            "P. Change Export Path",
            "A. About PowerSweep",
            "Q. Quit PowerSweep"
        )
        
        Show-InfoBox -Title "ACTIONS" -Content $actionsContent -BorderColor Cyan -TitleColor Green
        
        # Get user choice with highlighted prompt
        Write-Host "┌" -NoNewline -ForegroundColor Yellow
        Write-Host "".PadRight(118, "─") -NoNewline -ForegroundColor Yellow
        Write-Host "┐" -ForegroundColor Yellow
        
        Write-Host "│" -NoNewline -ForegroundColor Yellow
        Write-Host " Enter your choice: " -NoNewline -ForegroundColor White -BackgroundColor DarkBlue
        $choice = Read-Host
        Write-Host "".PadRight(102 - $choice.Length, " ") -NoNewline
        Write-Host "│" -ForegroundColor Yellow
        
        Write-Host "└" -NoNewline -ForegroundColor Yellow
        Write-Host "".PadRight(118, "─") -NoNewline -ForegroundColor Yellow
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
            "2" {
                Clear-Host
                $timeoutTitle = "TIMEOUT CONFIGURATION"
                $timeoutContent = @(
                    "Set the timeout value in milliseconds for host discovery.",
                    "Higher values may find more hosts but scan slower.",
                    "Current value: $($scanOptions.Timeout) ms",
                    "Recommended range: 100-5000 ms",
                    ""
                )
                
                Show-InfoBox -Title $timeoutTitle -Content $timeoutContent -BorderColor Blue -TitleColor Cyan
                
                $timeout = Read-Host "Enter timeout in milliseconds (100-5000)"
                if ([int]::TryParse($timeout, [ref]$null) -and [int]$timeout -ge 100 -and [int]$timeout -le 5000) {
                    $scanOptions.Timeout = [int]$timeout
                } else {
                    Write-Host "Invalid input. Keeping current value ($($scanOptions.Timeout)ms)" -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }
            }
            "3" {
                Clear-Host
                $threadTitle = "THREAD COUNT CONFIGURATION"
                $threadContent = @(
                    "Set the number of concurrent scanning threads.",
                    "Higher values scan faster but use more system resources.",
                    "Current value: $($scanOptions.ThreadCount) threads",
                    "Recommended range: 10-100 threads",
                    ""
                )
                
                Show-InfoBox -Title $threadTitle -Content $threadContent -BorderColor Blue -TitleColor Cyan
                
                $threads = Read-Host "Enter thread count (1-100)"
                if ([int]::TryParse($threads, [ref]$null) -and [int]$threads -ge 1 -and [int]$threads -le 100) {
                    $scanOptions.ThreadCount = [int]$threads
                } else {
                    Write-Host "Invalid input. Keeping current value ($($scanOptions.ThreadCount))" -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }
            }
            "[Nn]" {
                $scanOptions.StartIP = $NetworkInfo.FirstIP
                $scanOptions.EndIP = $NetworkInfo.LastIP
                
                $resetContent = @(
                    "IP range reset to network range:",
                    "$($NetworkInfo.FirstIP) to $($NetworkInfo.LastIP)"
                )
                
                Show-InfoBox -Title "RANGE RESET" -Content $resetContent -BorderColor Green -TitleColor White
                Start-Sleep -Seconds 1
            }
            "[Tt]" {
                $scanOptions.ScanPorts = -not $scanOptions.ScanPorts
                
                $toggleStatus = if ($scanOptions.ScanPorts) { "ENABLED" } else { "DISABLED" }
                $toggleContent = @(
                    "Port scanning is now $toggleStatus",
                    "",
                    "Port scanning detects open services on hosts",
                    "Disabling will make scans faster but less informative"
                )
                
                Show-InfoBox -Title "PORT SCANNING TOGGLED" -Content $toggleContent -BorderColor Yellow -TitleColor White
                Start-Sleep -Seconds 1
            }
            "[Hh]" {
                $scanOptions.DiscoverShares = -not $scanOptions.DiscoverShares
                
                $toggleStatus = if ($scanOptions.DiscoverShares) { "ENABLED" } else { "DISABLED" }
                $toggleContent = @(
                    "Share discovery is now $toggleStatus",
                    "",
                    "Share discovery enumerates accessible network shares",
                    "Disabling will make scans faster but less informative"
                )
                
                Show-InfoBox -Title "SHARE DISCOVERY TOGGLED" -Content $toggleContent -BorderColor Yellow -TitleColor White
                Start-Sleep -Seconds 1
            }
            "[Vv]" {
                $scanOptions.VulnerabilityScan = -not $scanOptions.VulnerabilityScan
                
                $toggleStatus = if ($scanOptions.VulnerabilityScan) { "ENABLED" } else { "DISABLED" }
                $toggleContent = @(
                    "Vulnerability scanning is now $toggleStatus",
                    "",
                    "Vulnerability scanning checks for common security issues",
                    "Disabling will skip the security assessment after scanning"
                )
                
                Show-InfoBox -Title "VULNERABILITY SCANNING TOGGLED" -Content $toggleContent -BorderColor Yellow -TitleColor White
                Start-Sleep -Seconds 1
            }
            "[Ee]" {
                $scanOptions.ExportResults = -not $scanOptions.ExportResults
                
                $toggleStatus = if ($scanOptions.ExportResults) { "ENABLED" } else { "DISABLED" }
                $toggleContent = @(
                    "Results export is now $toggleStatus",
                    "",
                    "When enabled, scan results will be saved to a CSV file",
                    "Current export path: $($scanOptions.ExportPath)"
                )
                
                Show-InfoBox -Title "EXPORT TOGGLED" -Content $toggleContent -BorderColor Yellow -TitleColor White
                Start-Sleep -Seconds 1
            }
            "[Pp]" {
                Clear-Host
                $exportPathTitle = "EXPORT PATH CONFIGURATION"
                $exportPathContent = @(
                    "Set the path where scan results will be saved as CSV.",
                    "Current path: $($scanOptions.ExportPath)",
                    "",
                    "Enter the full path including filename and .csv extension",
                    "Example: C:\Temp\ScanResults.csv",
                    ""
                )
                
                Show-InfoBox -Title $exportPathTitle -Content $exportPathContent -BorderColor Blue -TitleColor Cyan
                
                $newPath = Read-Host "Enter export path"
                if ($newPath -ne "") {
                    # Ensure it has .csv extension
                    if (-not $newPath.EndsWith(".csv", [StringComparison]::OrdinalIgnoreCase)) {
                        $newPath = "$newPath.csv"
                    }
                    $scanOptions.ExportPath = $newPath
                    
                    $pathContent = @(
                        "Export path updated:",
                        "$($scanOptions.ExportPath)"
                    )
                    
                    Show-InfoBox -Title "PATH UPDATED" -Content $pathContent -BorderColor Green -TitleColor White
                    Start-Sleep -Seconds 1
                }
            }
            "[Aa]" {
                Clear-Host
                $aboutContent = @(
                    "PowerSweep v4.0",
                    "Advanced PowerShell Network Discovery Tool",
                    "",
                    "Author: Ulises Paiz",
                    "License: GNU GPL v3",
                    "",
                    "Features:",
                    "- Network host discovery",
                    "- Port scanning and service detection",
                    "- Network share enumeration",
                    "- Device type identification",
                    "- Basic vulnerability assessment",
                    "- Results export to CSV",
                    "",
                    "This tool helps administrators discover and assess",
                    "devices on their networks. Use responsibly and only",
                    "on networks you are authorized to scan.",
                    "",
                    "Press any key to return to the main menu..."
                )
                
                Show-InfoBox -Title "ABOUT POWERSWEEP" -Content $aboutContent -BorderColor Cyan -TitleColor Magenta -Center
                
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "[Ss]" {
                Clear-Host
                $results = Scan-Network -StartIP $scanOptions.StartIP -EndIP $scanOptions.EndIP -TimeoutMilliseconds $scanOptions.Timeout -MaxThreads $scanOptions.ThreadCount -ScanPorts $scanOptions.ScanPorts -DiscoverShares $scanOptions.DiscoverShares -ExportResults $scanOptions.ExportResults -ExportPath $scanOptions.ExportPath
                
                if ($results.Count -gt 0) {
                    Show-ResultSummary -Results $results
                    
                    # Store vulnerabilities if vulnerability scanning is enabled
                    $vulnerabilities = @()
                    if ($scanOptions.VulnerabilityScan) {
                        $vulnerabilities = Scan-Vulnerabilities -Results $results
                    }
                    
                    # Ask about HTML report
                    $htmlReportContent = @(
                        "Would you like to generate an HTML report of scan results?",
                        "This creates a detailed report viewable in any web browser.",
                        "",
                        "The report will include all scan data and any vulnerabilities found."
                    )
                    
                    Show-InfoBox -Title "GENERATE HTML REPORT?" -Content $htmlReportContent -BorderColor Cyan -TitleColor White
                    
                    $generateHtml = Read-Host "Generate HTML report? (Y/N)"
                    if ($generateHtml -eq "Y" -or $generateHtml -eq "y") {
                        $htmlPath = "$env:USERPROFILE\Desktop\PowerSweep_Report_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                        $htmlPathPrompt = Read-Host "Enter HTML path or press Enter for default [$htmlPath]"
                        
                        $htmlPathToUse = if ([string]::IsNullOrWhiteSpace($htmlPathPrompt)) {
                            $htmlPath
                        } else {
                            $htmlPathPrompt
                        }
                        
                        Export-HtmlReport -Results $results -Vulnerabilities $vulnerabilities -ExportPath $htmlPathToUse
                    }
                    
                    # Ask about CSV export if not already exporting
                    if (-not $scanOptions.ExportResults) {
                        $exportContent = @(
                            "Would you like to export the scan results to a CSV file?",
                            "This allows you to import the data into other tools for further analysis.",
                            "",
                            "Suggested path: $($scanOptions.ExportPath)"
                        )
                        
                        Show-InfoBox -Title "EXPORT RESULTS?" -Content $exportContent -BorderColor Yellow -TitleColor White
                        
                        $exportNow = Read-Host "Export results? (Y/N)"
                        if ($exportNow -eq "Y" -or $exportNow -eq "y") {
                            $exportPathPrompt = Read-Host "Enter export path or press Enter to use default [$($scanOptions.ExportPath)]"
                            
                            $exportPathToUse = if ([string]::IsNullOrWhiteSpace($exportPathPrompt)) {
                                $scanOptions.ExportPath
                            } else {
                                $exportPathPrompt
                            }
                            
                            try {
                                # Ensure the directory exists
                                $directory = Split-Path -Path $exportPathToUse -Parent
                                if (-not (Test-Path -Path $directory)) {
                                    New-Item -Path $directory -ItemType Directory -Force | Out-Null
                                }
                                
                                # Sort results by IP address numerically
                                $sortedResults = $results | Sort-Object { 
                                    $octets = $_.IPAddress -split '\.'
                                    [int]$octets[0]*16777216 + [int]$octets[1]*65536 + [int]$octets[2]*256 + [int]$octets[3]
                                }
                                $sortedResults | Export-Csv -Path $exportPathToUse -NoTypeInformation
                                
                                $exportSuccessContent = @(
                                    "Results successfully exported to:",
                                    "$exportPathToUse"
                                )
                                
                                Show-InfoBox -Title "EXPORT SUCCESSFUL" -Content $exportSuccessContent -BorderColor Green -TitleColor White
                            } catch {
                                $exportErrorContent = @(
                                    "Error exporting results:",
                                    "$($_.Exception.Message)",
                                    "",
                                    "Please try a different path."
                                )
                                
                                Show-InfoBox -Title "EXPORT ERROR" -Content $exportErrorContent -BorderColor Red -TitleColor Yellow
                                Start-Sleep -Seconds 2
                            }
                        }
                    }
                }
                
                $postScanContent = @(
                    "Scan completed.",
                    "",
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
            "[Qq]" {
                $menuActive = $false
            }
            default {
                $invalidContent = @(
                    "Invalid selection: $choice",
                    "Please choose a valid option from the menu."
                )
                
                Show-InfoBox -Title "INVALID CHOICE" -Content $invalidContent -BorderColor Red -TitleColor Yellow
                Start-Sleep -Seconds 1
            }
        }
    }
}

# Main script execution
Clear-Host
Show-AnimatedBanner

# Check if running as administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $isAdmin) {
    $adminWarningContent = @(
        "This script is not running with administrator privileges.",
        "MAC address detection and share enumeration may not work properly.",
        "Consider restarting the script as administrator for full functionality."
    )
    
    Show-InfoBox -Title "WARNING" -Content $adminWarningContent -BorderColor Red -TitleColor Yellow
    
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
    "Thank you for using PowerSweep!",
    "Advanced Network Scanning Tool",
    "",
    "Press any key to exit..."
)

Show-InfoBox -Title "GOODBYE" -Content $farewellContent -BorderColor Cyan -TitleColor Magenta -Center

# Wait for a key press before exiting
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
