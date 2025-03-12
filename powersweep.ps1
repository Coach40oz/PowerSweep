#requires -RunAsAdministrator
<#
.SYNOPSIS
    PowerSweep - Advanced PowerShell Network Scanner
.DESCRIPTION
    A comprehensive network scanning tool that discovers active hosts,
    performs port scanning, identifies services, discovers shares,
    and attempts to determine device types.
.NOTES
    Author: Ulises Paiz
    Version: 1.17
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
    $networkBytes = New-Object Byte[] 4
    
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

function Get-DeviceType {
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress,
        [Parameter(Mandatory=$true)]
        [array]$OpenPorts,
        [Parameter(Mandatory=$false)]
        [string]$Hostname = "",
        [Parameter(Mandatory=$false)]
        [string]$Gateway = ""
    )
    
    # Simple fingerprinting based on open ports and hostname
    $deviceType = "Unknown"
    
    # Check if it's the gateway
    if ($IPAddress -eq $Gateway) {
        return "Router/Gateway"
    }
    
    # Check port patterns
    if ($OpenPorts -contains 80 -or $OpenPorts -contains 443) {
        if ($OpenPorts -contains 8080 -or $OpenPorts -contains 8443) {
            $deviceType = "Web Server"
        } else {
            $deviceType = "Web-enabled Device"
        }
    }
    
    if ($OpenPorts -contains 445 -or $OpenPorts -contains 139) {
        $deviceType = "Windows Device"
    }
    
    if ($OpenPorts -contains 22) {
        $deviceType = "Linux/Unix Device"
    }
    
    if ($OpenPorts -contains 3389) {
        $deviceType = "Windows PC/Server"
    }
    
    if ($OpenPorts -contains 53) {
        $deviceType = "DNS Server"
    }
    
    if ($OpenPorts -contains 5900) {
        $deviceType = "VNC Server"
    }
    
    if ($OpenPorts -contains 1433 -or $OpenPorts -contains 3306) {
        $deviceType = "Database Server"
    }
    
    if ($OpenPorts -contains 25 -or $OpenPorts -contains 465 -or $OpenPorts -contains 587) {
        $deviceType = "Mail Server"
    }
    
    # Check hostname patterns
    if ($Hostname -ne "Unknown" -and $Hostname -ne "") {
        $lowercaseHostname = $Hostname.ToLower()
        
        if ($lowercaseHostname -match "printer|hpprinter|epson|canon|brother|lexmark") {
            $deviceType = "Printer"
        }
        
        if ($lowercaseHostname -match "router|gateway|ap|accesspoint|wifi|ubnt|unifi|mikrotik") {
            $deviceType = "Network Device"
        }
        
        if ($lowercaseHostname -match "cam|camera|ipcam|nvr|dahua|hikvision|axis") {
            $deviceType = "IP Camera"
        }
        
        if ($lowercaseHostname -match "tv|roku|firetv|appletv|chromecast|shield") {
            $deviceType = "Media Device"
        }
        
        if ($lowercaseHostname -match "phone|iphone|android") {
            $deviceType = "Mobile Device"
        }
        
        if ($lowercaseHostname -match "server|dc|domain|ad|exchange|sql") {
            $deviceType = "Server"
        }
    }
    
    return $deviceType
}

function Get-NetworkShares {
    param (
        [Parameter(Mandatory=$true)]
        [string]$IPAddress
    )
    
    try {
        $shares = net view $IPAddress 2>$null | Select-String -Pattern "^\\.*" | ForEach-Object { $_.ToString().Trim() }
        if (!$shares -or $shares.Count -eq 0) {
            return @()
        }
        
        $shareDetails = @()
        foreach ($share in $shares) {
            if ($share -match "\\\\.*\\(.*)") {
                $shareName = $matches[1]
                if ($shareName -notmatch "IPC\$|ADMIN\$|.*\$$") {
                    $shareDetails += [PSCustomObject]@{
                        Name = $shareName
                        Path = "\\$IPAddress\$shareName"
                    }
                }
            }
        }
        return $shareDetails
    } catch {
        return @()
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
    
    # Create scriptblock for runspaces
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
                        $connected = $connectResult.AsyncWaitHandle.WaitOne($timeout, $false)
                        
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
            
            # Determine device type
            $deviceType = Get-DeviceType -IPAddress $ipAddress -OpenPorts $openPortNumbers -Hostname $hostname -Gateway $gateway
            
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
    
    # Create a scriptblock for getting device type (used inside the main scriptblock)
    $getDeviceTypeScriptblock = ${function:Get-DeviceType}.ToString()
    
    # Loop through each IP in the range
    for ($ipInt = $startIPInt; $ipInt -le $endIPInt; $ipInt++) {
        # Convert integer back to IP address
        $bytes = [BitConverter]::GetBytes($ipInt)
        [Array]::Reverse($bytes)
        $currentIP = [System.Net.IPAddress]::new($bytes).ToString()
        
        # Create a PowerShell instance
        $powershell = [powershell]::Create().AddScript($getDeviceTypeScriptblock).AddScript($scriptBlock).AddParameter("ipAddress", $currentIP).AddParameter("timeout", $TimeoutMilliseconds).AddParameter("scanPorts", $ScanPorts).AddParameter("discoverShares", $DiscoverShares).AddParameter("ports", $commonPorts).AddParameter("serviceDict", $serviceNames).AddParameter("gateway", $Global:NetworkInfo.Gateway)
        
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
                # Get result
                $result = $runspace.PowerShell.EndInvoke($runspace.Handle)
                
                # Process result if not null
                if ($result -ne $null) {
                    [void]$results.Add($result)
                    $totalActive++
                    
                    # Display active host found
                    Write-Host ("[{0}/{1}] " -f $totalScanned, $totalIPs) -NoNewline -ForegroundColor Gray
                    Write-Host "Found: " -NoNewline -ForegroundColor White
                    Write-Host "$($result.IPAddress)" -NoNewline -ForegroundColor Green
                    
                    if ($result.Hostname -ne "Unknown") {
                        Write-Host " ($($result.Hostname))" -NoNewline -ForegroundColor Cyan
                    }
                    
                    Write-Host " - $($result.DeviceType)" -ForegroundColor Yellow
                }
                
                # Clean up
                $runspace.PowerShell.Dispose()
                $runspace.Completed = $true
                $totalScanned++
            }
        }
        
        # Update progress
        $percentComplete = [Math]::Min(100, [Math]::Max(0, [int](($totalScanned / $totalIPs) * 100)))
        Write-Progress -Activity "Scanning Network" -Status "Progress: $totalScanned of $totalIPs IPs scanned" -PercentComplete $percentComplete
        
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
            $sortedResults = $results | Sort-Object { [System.Version]::new($_.IPAddress) }
            $sortedResults | Export-Csv -Path $ExportPath -NoTypeInformation
            Write-Host "Results exported to: " -NoNewline -ForegroundColor White
            Write-Host "$ExportPath" -ForegroundColor Green
        } catch {
            Write-Host "Error exporting results: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
    
    # Return sorted results
    return $results | Sort-Object { [System.Version]::new($_.IPAddress) }
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
        Write-Host "  $($type.Name): " -NoNewline -ForegroundColor White
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
    
    $portSummary = $allPorts | Group-Object -Property Service | Sort-Object -Property Count -Descending
    
    if ($portSummary.Count -gt 0) {
        Write-Host "`nCommon Services:" -ForegroundColor Magenta
        foreach ($service in $portSummary | Select-Object -First 10) {
            Write-Host "  $($service.Name): " -NoNewline -ForegroundColor White
            Write-Host "$($service.Count)" -ForegroundColor Green
        }
    }
    
    # Shares summary
    $hostsWithShares = $Results | Where-Object { $_.Shares -ne "" }
    if ($hostsWithShares.Count -gt 0) {
        Write-Host "`nHosts with Shares: " -NoNewline -ForegroundColor Magenta
        Write-Host "$($hostsWithShares.Count)" -ForegroundColor Green
    }
    
    Write-Host "`nTop 10 Fastest Responding Hosts:" -ForegroundColor Magenta
    $fastestHosts = $Results | Sort-Object { [int]($_.ResponseTime -replace ' ms', '') } | Select-Object -First 10
    foreach ($host in $fastestHosts) {
        Write-Host "  $($host.IPAddress) " -NoNewline -ForegroundColor Green
        if ($host.Hostname -ne "Unknown") {
            Write-Host "($($host.Hostname)) " -NoNewline -ForegroundColor Cyan
        }
        Write-Host "- " -NoNewline
        Write-Host "$($host.ResponseTime)" -ForegroundColor Yellow
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
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝

"@
    
    Write-Host $header -ForegroundColor Cyan
    
    $scanOptions = @{
        ScanRange = "1"
        StartIP = $NetworkInfo.FirstIP
        EndIP = $NetworkInfo.LastIP
        Timeout = 1000
        ThreadCount = 50
        ScanPorts = $true
        DiscoverShares = $true
        ExportResults = $false
        ExportPath = "$env:USERPROFILE\Desktop\NetworkScan_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    }
    
    $menuActive = $true
    
    while ($menuActive) {
        Write-Host "Current Scan Settings:" -ForegroundColor Yellow
        Write-Host "  1. IP Range: " -NoNewline -ForegroundColor White
        Write-Host "$($scanOptions.StartIP) to $($scanOptions.EndIP)" -ForegroundColor Green
        Write-Host "  2. Timeout: " -NoNewline -ForegroundColor White
        Write-Host "$($scanOptions.Timeout) ms" -ForegroundColor Green
        Write-Host "  3. Thread Count: " -NoNewline -ForegroundColor White
        Write-Host "$($scanOptions.ThreadCount)" -ForegroundColor Green
        Write-Host "  4. Scan Ports: " -NoNewline -ForegroundColor White
        Write-Host "$($scanOptions.ScanPorts)" -ForegroundColor Green
        Write-Host "  5. Discover Shares: " -NoNewline -ForegroundColor White
        Write-Host "$($scanOptions.DiscoverShares)" -ForegroundColor Green
        Write-Host "  6. Export Results: " -NoNewline -ForegroundColor White
        Write-Host "$($scanOptions.ExportResults)" -ForegroundColor Green
        
        if ($scanOptions.ExportResults) {
            Write-Host "  7. Export Path: " -NoNewline -ForegroundColor White
            Write-Host "$($scanOptions.ExportPath)" -ForegroundColor Green
        }
        
        Write-Host "`nActions:" -ForegroundColor Yellow
        Write-Host "  S. Start Scan" -ForegroundColor Green
        Write-Host "  Q. Quit" -ForegroundColor Red
        
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
                    $scanOptions.Timeout = 1000
                    Write-Host "Invalid input. Reset to default (1000ms)" -ForegroundColor Red
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
                $scanOptions.ExportResults = -not $scanOptions.ExportResults
            }
            "7" {
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
                        $results | Format-Table -Property IPAddress, Hostname, DeviceType, MAC, ResponseTime, OpenPorts, Shares -AutoSize
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
Write-Host "═════════════════════════════════════════════════════════════════════" -ForegroundColor Cyan

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

Write-Host "`nThank you for using PowerSweep!" -ForegroundColor Cyan
