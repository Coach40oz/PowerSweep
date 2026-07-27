<#
.SYNOPSIS
    PowerSweep Lite - Lightweight PowerShell network discovery tool.
.DESCRIPTION
    Discovers active hosts on the local network and reports IP address,
    hostname, MAC address, response time and a best-effort device type.

    Discovery uses an ICMP sweep, seeded from the local ARP/neighbour table
    and optionally backed by a short TCP connect fallback so that hosts which
    drop ping (the Windows Firewall default on Public and Domain profiles)
    are still found.

    Administrator rights are recommended: MAC address resolution is
    unreliable without them. The script checks at runtime and lets you
    continue either way.
.NOTES
    Author  : Ulises Paiz
    Version : 1.2 (Lite)
    License : MIT
    Requires: Windows PowerShell 5.1 or later, on Windows.
#>

# Every function in this script was written and audited to be clean under
# strict mode: reads of foreign CIM/Net object properties go through guarded
# helpers, and Read-Host results are null-coalesced before use. Enabling it
# turns a latent $null (from a typo or an unexpected object shape) into an
# immediate, locatable error instead of silently wrong output.
Set-StrictMode -Version Latest

function Show-InfoBox {
    <#
    .SYNOPSIS
        Displays a formatted information box in the console
    .DESCRIPTION
        Renders a box whose top border, content rows and bottom border are all
        exactly the same rendered width. The box is capped to the width of the
        console window (when one is available) and any content line that is too
        long is truncated with an ellipsis so the borders never scatter.
        Empty strings inside -Content are honoured as blank spacer lines.
    .PARAMETER Title
        The title to display in the box header
    .PARAMETER Content
        Array of strings to display as content lines
    .PARAMETER BorderColor
        Color for the box border (default: Cyan)
    .PARAMETER TitleColor
        Color for the title text (default: Yellow)
    .PARAMETER ContentColor
        Color for the content text (default: White)
    .PARAMETER Center
        Switch to center-align the content
    .EXAMPLE
        Show-InfoBox -Title "STATUS" -Content @("", "All good", "") -Center
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]
        [string]$Title,

        # NOTE: AllowEmptyString/AllowEmptyCollection are load-bearing. A
        # Mandatory array parameter implicitly rejects empty-string ELEMENTS,
        # which is what broke the blank spacer lines the callers pass. Keep
        # ValidateNotNull (rejects a null array) but never add a validator that
        # rejects empty strings.
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [AllowEmptyCollection()]
        [ValidateNotNull()]
        [string[]]$Content,

        [ValidateSet("Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow",
                     "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White")]
        [string]$BorderColor = "Cyan",

        [ValidateSet("Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow",
                     "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White")]
        [string]$TitleColor = "Yellow",

        [ValidateSet("Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow",
                     "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White")]
        [string]$ContentColor = "White",

        [switch]$Center
    )

    # Normalize the content up front so a $null element can never blow up on
    # .Length (Set-StrictMode would turn that into a terminating error).
    $lines = @()
    foreach ($rawLine in $Content) {
        if ($null -eq $rawLine) {
            $lines += ""
        } else {
            $lines += [string]$rawLine
        }
    }

    # Longest content line, computed without Measure-Object so an empty
    # -Content array simply yields 0 instead of $null.
    $contentLength = 0
    foreach ($line in $lines) {
        if ($line.Length -gt $contentLength) {
            $contentLength = $line.Length
        }
    }

    # Widest thing we have to fit, plus the padding the original box used.
    # $innerWidth is the span between the two vertical bars, so every rendered
    # row is exactly $innerWidth + 2 characters wide.
    $titleLength = $Title.Length
    $innerWidth = [Math]::Max($titleLength, $contentLength) + 6

    # Discover the console width so the box can be capped. A redirected or
    # otherwise non-interactive host may not expose WindowSize at all.
    $consoleWidth = 0
    try {
        if ($null -ne $Host -and $null -ne $Host.UI -and $null -ne $Host.UI.RawUI) {
            $windowSize = $Host.UI.RawUI.WindowSize
            if ($null -ne $windowSize) {
                $consoleWidth = [int]$windowSize.Width
            }
        }
    } catch {
        # No usable RawUI (redirected host, remoting, ISE quirks) - fall through.
        $consoleWidth = 0
    }
    if ($consoleWidth -lt 20) {
        # Unknown or nonsensical width: fall back to a sane fixed maximum.
        $consoleWidth = 121
    }

    # Cap the total rendered width at (console width - 1) so the terminal never
    # wraps a row onto the next line and scatters the borders.
    $maxInnerWidth = $consoleWidth - 1 - 2
    if ($maxInnerWidth -lt 4) { $maxInnerWidth = 4 }
    if ($innerWidth -gt $maxInnerWidth) { $innerWidth = $maxInnerWidth }

    # Usable text area: one space of padding on each side of the content.
    $textWidth = $innerWidth - 2
    if ($textWidth -lt 1) { $textWidth = 1 }

    # Truncate the title if the cap left no room for it (border + 2 spaces).
    $boxTitle = $Title
    if ($boxTitle.Length -gt $textWidth) {
        if ($textWidth -gt 3) {
            $boxTitle = $boxTitle.Substring(0, $textWidth - 3) + "..."
        } else {
            $boxTitle = $boxTitle.Substring(0, $textWidth)
        }
    }

    # Create top border with title - the dash counts are floored explicitly so
    # the left and right runs always sum to exactly the remaining width.
    $dashTotal = [Math]::Max(0, $innerWidth - $boxTitle.Length - 2)
    $leftDashes = [int][Math]::Floor($dashTotal / 2)
    $rightDashes = $dashTotal - $leftDashes

    Write-Host "┌" -NoNewline -ForegroundColor $BorderColor
    Write-Host "".PadRight($leftDashes, "─") -NoNewline -ForegroundColor $BorderColor
    Write-Host " $boxTitle " -NoNewline -ForegroundColor $TitleColor
    Write-Host "".PadRight($rightDashes, "─") -NoNewline -ForegroundColor $BorderColor
    Write-Host "┐" -ForegroundColor $BorderColor

    # Create content lines
    foreach ($line in $lines) {
        # Truncate anything that would overflow the capped box.
        if ($line.Length -gt $textWidth) {
            if ($textWidth -gt 3) {
                $line = $line.Substring(0, $textWidth - 3) + "..."
            } else {
                $line = $line.Substring(0, $textWidth)
            }
        }

        # Remaining space is split between left and right padding. Both are
        # clamped at 0 so PadRight can never receive a negative count.
        $slack = [Math]::Max(0, $textWidth - $line.Length)
        if ($Center) {
            $leftPad = [int][Math]::Floor($slack / 2)
        } else {
            $leftPad = 0
        }
        $rightPad = [Math]::Max(0, $slack - $leftPad)

        Write-Host "│ " -NoNewline -ForegroundColor $BorderColor
        Write-Host "".PadRight($leftPad, " ") -NoNewline
        Write-Host "$line" -NoNewline -ForegroundColor $ContentColor
        Write-Host "".PadRight($rightPad, " ") -NoNewline
        Write-Host " │" -ForegroundColor $BorderColor
    }

    # Create bottom border
    Write-Host "└" -NoNewline -ForegroundColor $BorderColor
    Write-Host "".PadRight($innerWidth, "─") -NoNewline -ForegroundColor $BorderColor
    Write-Host "┘" -ForegroundColor $BorderColor
}

function Show-ProgressBar {
    <#
    .SYNOPSIS
        Displays a progress bar in the console
    .DESCRIPTION
        The filled and empty runs are derived with integer floor division so
        their sum is exactly -Width at every percentage from 0 to 100 and the
        bar never changes size as it fills.
    .PARAMETER PercentComplete
        Percentage of completion (0-100)
    .PARAMETER Width
        Width of the progress bar in characters
    .PARAMETER FillColor
        Color for the filled portion
    .PARAMETER EmptyColor
        Color for the empty portion
    .PARAMETER ShowPercent
        Switch to display the percentage value
    .EXAMPLE
        Show-ProgressBar -PercentComplete 42 -Width 40 -ShowPercent
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateRange(0, 100)]
        [int]$PercentComplete,

        [ValidateRange(10, 200)]
        [int]$Width = 50,

        [ValidateSet("Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow",
                     "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White")]
        [string]$FillColor = "Green",

        [ValidateSet("Black", "DarkBlue", "DarkGreen", "DarkCyan", "DarkRed", "DarkMagenta", "DarkYellow",
                     "Gray", "DarkGray", "Blue", "Green", "Cyan", "Red", "Magenta", "Yellow", "White")]
        [string]$EmptyColor = "DarkGray",

        [switch]$ShowPercent
    )

    # Floor rather than [Math]::Round - Round uses banker's rounding, which let
    # the two halves drift and changed the total bar width by a character.
    $fillWidth = [int][Math]::Floor(($PercentComplete * $Width) / 100.0)
    if ($fillWidth -lt 0) { $fillWidth = 0 }
    if ($fillWidth -gt $Width) { $fillWidth = $Width }
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

function Show-Banner {
    <#
    .SYNOPSIS
        Displays the PowerSweep Lite banner and separator rule
    .DESCRIPTION
        Single home for the banner art, which used to be duplicated verbatim in
        two places. Renders instantly by default with a stable colour gradient
        so repeated menu redraws neither stall nor flicker. Pass -Animate for
        the original per-line rainbow reveal (startup only).
    .PARAMETER Animate
        Switch to draw the banner line by line with the random rainbow colouring
    .EXAMPLE
        Show-Banner -Animate
    #>
    [CmdletBinding()]
    param (
        [switch]$Animate
    )

    $banner = @"
                                                                                
 ██████╗  ██████╗ ██╗    ██╗███████╗██████╗ ███████╗██╗    ██╗███████╗███████╗██████╗  
 ██╔══██╗██╔═══██╗██║    ██║██╔════╝██╔══██╗██╔════╝██║    ██║██╔════╝██╔════╝██╔══██╗ 
 ██████╔╝██║   ██║██║ █╗ ██║█████╗  ██████╔╝███████╗██║ █╗ ██║█████╗  █████╗  ██████╔╝ 
 ██╔═══╝ ██║   ██║██║███╗██║██╔══╝  ██╔══██╗╚════██║██║███╗██║██╔══╝  ██╔══╝  ██╔═══╝  
 ██║     ╚██████╔╝╚███╔███╔╝███████╗██║  ██║███████║╚███╔███╔╝███████╗███████╗██║      
 ╚═╝      ╚═════╝  ╚══╝╚══╝ ╚══════╝╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚══════╝╚══════╝╚═╝      
                                         LITE v1.2                                     
        Simple PowerShell Network Discovery Tool by Ulises Paiz
"@

    # Split on both CRLF and LF so the art is not left with stray carriage
    # returns when the script is saved with Windows line endings.
    $bannerLines = $banner -split "`r?`n"

    if ($Animate) {
        # Original startup reveal: a random rainbow colour per line.
        $rainbowColors = @(
            "Red", "Yellow", "Green", "Cyan", "Blue", "Magenta"
        )

        foreach ($line in $bannerLines) {
            $color = $rainbowColors[(Get-Random -Maximum $rainbowColors.Count)]
            Write-Host $line -ForegroundColor $color
            Start-Sleep -Milliseconds 50
        }

        # Create a fancy separator, drawn one character at a time
        Write-Host "┌" -NoNewline -ForegroundColor Cyan
        for ($i = 0; $i -lt 78; $i++) {
            Start-Sleep -Milliseconds 5
            Write-Host "─" -NoNewline -ForegroundColor Cyan
        }
        Write-Host "┐" -ForegroundColor Cyan
    } else {
        # Instant path: a fixed top-to-bottom gradient. Deliberately stable so
        # the banner looks identical on every menu redraw instead of flickering
        # a new random colour after each keypress.
        $gradient = @(
            "Cyan", "Cyan", "DarkCyan", "Cyan", "DarkCyan", "Cyan", "DarkCyan", "Yellow", "White"
        )

        for ($i = 0; $i -lt $bannerLines.Count; $i++) {
            $color = $gradient[$i % $gradient.Count]
            Write-Host $bannerLines[$i] -ForegroundColor $color
        }

        # Same separator rule, written in one shot
        Write-Host ("┌" + "".PadRight(78, "─") + "┐") -ForegroundColor Cyan
    }
}

function Get-SafeMemberValue {
    # Reads a property without tripping Set-StrictMode -Version Latest, which
    # turns a reference to a missing property into a terminating error. CIM
    # instances from the Get-Net* cmdlets vary across Windows builds, adapter
    # types and driver stacks, so every property read in this region goes
    # through here.
    #
    # No try/catch around .Value: PowerShell already swallows an exception
    # thrown by a property getter (script or CLR) and yields $null, so a
    # guard here would be dead code. Verified on 5.1 and 7.x.
    param ($InputObject, [string]$Name)

    if ($null -eq $InputObject) {
        return $null
    }

    # Indexing the property collection is safe for an absent name; direct
    # member access is not.
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) {
        return $null
    }

    return $property.Value
}

function ConvertTo-IPv4Number {
    # Dotted-decimal -> [Int64] in 0..4294967295, or $null when the text is
    # not a valid IPv4 address.
    #
    # The number is built straight from the network-order (big-endian) bytes.
    # It deliberately does NOT go through [BitConverter]::ToUInt32, which
    # reads little-endian and byte-swaps the result - that was the original
    # defect that made the position indicator wrong at every prefix but /24.
    # Int64 throughout: Windows PowerShell promotes UInt32 operands to signed
    # types during arithmetic and shifts, so Int64 keeps every intermediate
    # value exact and non-negative.
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$IPAddress
    )

    if ([string]::IsNullOrWhiteSpace($IPAddress)) {
        return $null
    }

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($IPAddress.Trim(), [ref]$parsed)) {
        return $null
    }

    # IPv6 is out of scope for this region.
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $null
    }

    $value = [Int64]0
    foreach ($addressByte in $parsed.GetAddressBytes()) {
        $value = ($value * 256) + [Int64]$addressByte
    }

    return $value
}

function ConvertFrom-IPv4Number {
    # [Int64] -> dotted-decimal. Masked to 32 bits so an out-of-range value
    # still produces a syntactically valid address rather than nonsense.
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [Int64]$Number
    )

    $value = $Number -band [Int64]4294967295

    $octet1 = ($value -shr 24) -band 255
    $octet2 = ($value -shr 16) -band 255
    $octet3 = ($value -shr 8) -band 255
    $octet4 = $value -band 255

    return "$octet1.$octet2.$octet3.$octet4"
}

function Get-IPv4SubnetMaskNumber {
    # Numeric subnet mask for a CIDR prefix, correct across the whole 0..32
    # range. Shifting a 64-bit value and masking back to 32 bits avoids the
    # Windows PowerShell trap where a 32-bit shift of a 32-bit value is
    # undefined and wraps - which is why the original
    # "[UInt32]::MaxValue -shl (32 - $prefix)" returned 0xFFFFFFFF at /0
    # instead of 0.
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateRange(0, 32)]
        [int]$PrefixLength
    )

    return (([Int64]4294967295 -shl (32 - $PrefixLength)) -band [Int64]4294967295)
}

function Select-PrimaryIPv4Address {
    # Collapses an adapter's IPv4 addresses to one deterministic choice.
    # $config.IPv4Address can be an array, which makes .PrefixLength an array
    # too and turns every downstream calculation into garbage.
    #   1. the address whose own subnet contains the default gateway
    #   2. otherwise the first routable address, in Windows' own order
    # Link-local, loopback and 0.0.0.0 are never usable scan origins, so an
    # adapter left with none of them returns $null. That is the point: a
    # 169.254 address means DHCP never answered, and reporting a broken
    # network beats sweeping 65534 guaranteed-dead hosts.
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [AllowNull()]
        $Configuration,

        [Parameter(Mandatory=$false)]
        [AllowEmptyString()]
        [AllowNull()]
        [string]$Gateway = ''
    )

    $candidates = @()
    foreach ($entry in @(Get-SafeMemberValue -InputObject $Configuration -Name 'IPv4Address')) {
        $addressText = [string](Get-SafeMemberValue -InputObject $entry -Name 'IPAddress')
        if ([string]::IsNullOrWhiteSpace($addressText)) {
            continue
        }
        $addressText = $addressText.Trim()

        $addressNumber = ConvertTo-IPv4Number -IPAddress $addressText
        if ($null -eq $addressNumber) {
            continue
        }

        # Rejected numerically rather than by text prefix, so odd formatting
        # cannot smuggle one through: 0.0.0.0, loopback 127/8 (2130706432 -
        # 2147483647), link-local 169.254/16 (2851995648 - 2852061183).
        if ($addressNumber -eq 0) {
            continue
        }
        if ($addressNumber -ge 2130706432 -and $addressNumber -le 2147483647) {
            continue
        }
        if ($addressNumber -ge 2851995648 -and $addressNumber -le 2852061183) {
            continue
        }

        # A missing or out-of-range prefix falls back to /32 (host route).
        $prefixLength = 32
        $parsedPrefix = 0
        if ([int]::TryParse([string](Get-SafeMemberValue -InputObject $entry -Name 'PrefixLength'), [ref]$parsedPrefix)) {
            if ($parsedPrefix -ge 0 -and $parsedPrefix -le 32) {
                $prefixLength = $parsedPrefix
            }
        }

        $candidates += [PSCustomObject]@{
            IPAddress    = $addressText
            PrefixLength = $prefixLength
            Number       = $addressNumber
        }
    }

    if ($candidates.Count -eq 0) {
        return $null
    }

    # Preference 1: the address that actually shares a subnet with the gateway.
    $gatewayNumber = ConvertTo-IPv4Number -IPAddress $Gateway
    if ($null -ne $gatewayNumber) {
        foreach ($candidate in $candidates) {
            $maskNumber = Get-IPv4SubnetMaskNumber -PrefixLength $candidate.PrefixLength
            if (($candidate.Number -band $maskNumber) -eq ($gatewayNumber -band $maskNumber)) {
                return $candidate
            }
        }
    }

    # Preference 2: first routable address in the order Windows reported them.
    return $candidates[0]
}

function Get-IPv4RouteMetricMap {
    # Maps interface index -> effective IPv4 default-route metric, which is
    # the ranking Windows itself routes by (route metric + interface metric).
    # A docked laptop routinely has Wi-Fi and Ethernet up at once, so deriving
    # the scan range from whichever adapter is enumerated first can silently
    # scan the wrong subnet - a clean-looking scan of a network the operator
    # never meant to touch.
    #
    # Advisory only. Each cmdlet call is individually guarded; on failure the
    # map comes back empty and the caller falls back to enumeration order.
    # This must never become a crash path.
    [CmdletBinding()]
    param ()

    $routeMetrics = @{}
    try {
        foreach ($defaultRoute in @(Get-NetRoute -DestinationPrefix '0.0.0.0/0' -AddressFamily IPv4 -ErrorAction Stop)) {
            $routeIndex = 0
            $routeMetric = 0
            if (-not [int]::TryParse([string](Get-SafeMemberValue -InputObject $defaultRoute -Name 'InterfaceIndex'), [ref]$routeIndex)) {
                continue
            }
            if (-not [int]::TryParse([string](Get-SafeMemberValue -InputObject $defaultRoute -Name 'RouteMetric'), [ref]$routeMetric)) {
                continue
            }

            # One interface can carry several default routes; the lowest wins.
            if ((-not $routeMetrics.ContainsKey($routeIndex)) -or ($routeMetric -lt $routeMetrics[$routeIndex])) {
                $routeMetrics[$routeIndex] = [Int64]$routeMetric
            }
        }
    } catch {
        $routeMetrics = @{}
    }

    $interfaceMetrics = @{}
    try {
        foreach ($ipInterface in @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction Stop)) {
            $interfaceIndex = 0
            $interfaceMetric = 0
            if (-not [int]::TryParse([string](Get-SafeMemberValue -InputObject $ipInterface -Name 'InterfaceIndex'), [ref]$interfaceIndex)) {
                continue
            }
            if (-not [int]::TryParse([string](Get-SafeMemberValue -InputObject $ipInterface -Name 'InterfaceMetric'), [ref]$interfaceMetric)) {
                continue
            }

            if ((-not $interfaceMetrics.ContainsKey($interfaceIndex)) -or ($interfaceMetric -lt $interfaceMetrics[$interfaceIndex])) {
                $interfaceMetrics[$interfaceIndex] = [Int64]$interfaceMetric
            }
        }
    } catch {
        $interfaceMetrics = @{}
    }

    # Every score in the map must be built the same way, or adapters end up
    # compared on different bases and the wrong one wins. When both sources
    # have data, an index missing from either is left out of the map entirely
    # rather than scored on half the inputs - a missing index sorts last and
    # falls back to enumeration order, which is honest about not knowing.
    $metricMap = @{}
    if ($routeMetrics.Count -gt 0 -and $interfaceMetrics.Count -gt 0) {
        foreach ($routeIndex in $routeMetrics.Keys) {
            if ($interfaceMetrics.ContainsKey($routeIndex)) {
                $metricMap[$routeIndex] = [Int64]($routeMetrics[$routeIndex] + $interfaceMetrics[$routeIndex])
            }
        }
    } elseif ($routeMetrics.Count -gt 0) {
        foreach ($routeIndex in $routeMetrics.Keys) {
            $metricMap[$routeIndex] = [Int64]$routeMetrics[$routeIndex]
        }
    } else {
        foreach ($interfaceIndex in $interfaceMetrics.Keys) {
            $metricMap[$interfaceIndex] = [Int64]$interfaceMetrics[$interfaceIndex]
        }
    }

    return $metricMap
}

function Get-LocalNetworkInfo {
    <#
    .SYNOPSIS
        Collects, displays and returns the local IPv4 network parameters.
    .DESCRIPTION
        Enumerates connected adapters that have an IPv4 default gateway and a
        routable IPv4 address, prints a summary box per adapter, then derives
        the scan range (network address, broadcast address, first and last
        usable host) from the primary adapter and shows where this machine
        sits inside that range.

        The primary adapter - the one the scan range comes from - is the
        qualifying adapter with the lowest effective IPv4 route metric, which
        is the adapter Windows itself would route through. A docked laptop
        commonly has Wi-Fi and Ethernet up simultaneously, and taking the
        first adapter Windows enumerates would silently scan the wrong subnet.
        Ties, and the case where metric data cannot be read at all, fall back
        to enumeration order so the choice stays deterministic.

        When more than one adapter qualifies, each adapter box states whether
        it is the one the scan range came from, so the operator can see that a
        choice was made and override it from the menu.

        All address arithmetic is done in [Int64] host order, so the range and
        the position indicator are correct at any prefix length, not just /24.
        The /31 and /32 edge cases follow RFC 3021: a /31 has two usable
        addresses and a /32 has one, instead of the zero and minus one that
        the naive 2^(32-prefix)-2 formula produces.

        Adapters holding only a link-local (169.254.x.x), loopback or 0.0.0.0
        address are rejected rather than scanned. Such an address means DHCP
        never answered, so the network is down and there is nothing to find.
    .OUTPUTS
        [hashtable] with FirstIP, LastIP, Gateway, LocalIP, PrefixLength,
        SubnetMask, NetworkAddress, BroadcastAddress, TotalUsableIPs,
        InterfaceAlias and InterfaceMetric. InterfaceMetric is $null when no
        metric information was available. Returns $null if no usable adapter
        was found; the caller is responsible for handling that.
    .EXAMPLE
        $networkInfo = Get-LocalNetworkInfo
        if ($null -eq $networkInfo) { return }
    #>
    [CmdletBinding()]
    param ()

    $headerContent = @(
        "",
        "Collecting information about your local network...",
        "This information will be used to determine scan parameters.",
        ""
    )

    Show-InfoBox -Title "LOCAL NETWORK INFORMATION" -Content $headerContent -BorderColor Cyan -TitleColor Yellow -ContentColor White

    # ------------------------------------------------------------------
    # Discover adapters. Get-NetIPConfiguration can legitimately return
    # nothing at all (everything disconnected, VPN-only machine, no
    # default gateway), so nothing below may assume an element exists.
    # ------------------------------------------------------------------
    $configurations = @()
    try {
        $configurations = @(Get-NetIPConfiguration -ErrorAction Stop)
    } catch {
        $failureContent = @(
            "",
            "Could not read the local network configuration.",
            "",
            "Get-NetIPConfiguration failed with:",
            "  $($_.Exception.Message)",
            "",
            "This command requires Windows and the NetTCPIP module.",
            ""
        )

        Show-InfoBox -Title "NETWORK ERROR" -Content $failureContent -BorderColor Red -TitleColor Red -ContentColor White
        return $null
    }

    # Advisory - an empty map just degrades the ranking to enumeration order.
    $metricMap = Get-IPv4RouteMetricMap

    # Keep only adapters that are connected AND have an IPv4 default gateway
    # AND expose a routable IPv4 address. Each survivor carries its own
    # pre-resolved gateway, single chosen address, route metric and the
    # position Windows enumerated it in (the deterministic tie-break).
    $usableAdapters = @()
    $enumerationOrder = 0
    foreach ($configuration in $configurations) {
        $enumerationOrder++

        $netAdapter = Get-SafeMemberValue -InputObject $configuration -Name 'NetAdapter'
        if ([string](Get-SafeMemberValue -InputObject $netAdapter -Name 'Status') -eq 'Disconnected') {
            continue
        }

        # IPv4DefaultGateway can be absent, $null, or an array of routes. The
        # value is validated as real IPv4 before use: Start-NetworkScan labels
        # hosts "Router/Gateway" by matching this string, so an IPv6 or
        # malformed next hop would silently mislabel a device.
        $gatewayAddress = ''
        foreach ($route in @(Get-SafeMemberValue -InputObject $configuration -Name 'IPv4DefaultGateway')) {
            $nextHop = [string](Get-SafeMemberValue -InputObject $route -Name 'NextHop')
            if ([string]::IsNullOrWhiteSpace($nextHop)) {
                continue
            }
            if ($null -eq (ConvertTo-IPv4Number -IPAddress $nextHop)) {
                continue
            }

            $gatewayAddress = $nextHop.Trim()
            break
        }

        if ([string]::IsNullOrWhiteSpace($gatewayAddress)) {
            continue
        }

        $primaryAddress = Select-PrimaryIPv4Address -Configuration $configuration -Gateway $gatewayAddress
        if ($null -eq $primaryAddress) {
            continue
        }

        # Unknown metrics sort last via [Int64]::MaxValue rather than being
        # treated as zero, which would wrongly promote an adapter we know
        # nothing about above one we have real data for.
        $routeMetric = $null
        $sortMetric = [Int64]::MaxValue
        $interfaceIndex = 0
        if ([int]::TryParse([string](Get-SafeMemberValue -InputObject $configuration -Name 'InterfaceIndex'), [ref]$interfaceIndex)) {
            if ($metricMap.ContainsKey($interfaceIndex)) {
                $routeMetric = [Int64]$metricMap[$interfaceIndex]
                $sortMetric = $routeMetric
            }
        }

        $usableAdapters += [PSCustomObject]@{
            Configuration = $configuration
            Gateway       = $gatewayAddress
            Address       = $primaryAddress
            RouteMetric   = $routeMetric
            SortMetric    = $sortMetric
            Order         = $enumerationOrder
        }
    }

    # ------------------------------------------------------------------
    # Unrecoverable: nothing to scan from. Explain, then hand control back.
    # ------------------------------------------------------------------
    if ($usableAdapters.Count -eq 0) {
        $failureContent = @(
            "",
            "No usable network adapter was found.",
            "",
            "Need: a connected adapter with an IPv4 default gateway and a",
            "routable IPv4 address. Adapters seen: $($configurations.Count).",
            "",
            "A 169.254.x.x address means no DHCP server answered - the network",
            "itself is down, so there is nothing to scan.",
            ""
        )

        Show-InfoBox -Title "NETWORK ERROR" -Content $failureContent -BorderColor Red -TitleColor Red -ContentColor White
        return $null
    }

    # ------------------------------------------------------------------
    # Lowest effective route metric wins, so the scan range comes from the
    # adapter Windows actually routes through rather than whichever one it
    # happened to enumerate first. Order is unique, so sorting on
    # (SortMetric, Order) is a total order - the result is deterministic
    # even though Sort-Object is not a stable sort in Windows PowerShell.
    # ------------------------------------------------------------------
    $usableAdapters = @($usableAdapters | Sort-Object -Property SortMetric, Order)

    # ------------------------------------------------------------------
    # One summary box per qualifying adapter. Index 0 is the primary.
    # ------------------------------------------------------------------
    $showSelection = ($usableAdapters.Count -gt 1)
    $adapterPosition = 0
    foreach ($usableAdapter in $usableAdapters) {
        $configuration = $usableAdapter.Configuration
        $address = $usableAdapter.Address

        $interfaceAlias = [string](Get-SafeMemberValue -InputObject $configuration -Name 'InterfaceAlias')
        if ([string]::IsNullOrWhiteSpace($interfaceAlias)) {
            $interfaceAlias = '(unknown)'
        }

        # Mask from the single chosen address, never from an array.
        $subnetMaskText = ConvertFrom-IPv4Number -Number (Get-IPv4SubnetMaskNumber -PrefixLength $address.PrefixLength)

        # DNS: IPv4 only (AddressFamily 2 = InterNetwork), flattened to one line.
        $dnsAddresses = @()
        foreach ($dnsEntry in @(Get-SafeMemberValue -InputObject $configuration -Name 'DNSServer')) {
            $familyValue = 0
            if (-not [int]::TryParse([string](Get-SafeMemberValue -InputObject $dnsEntry -Name 'AddressFamily'), [ref]$familyValue)) {
                continue
            }
            if ($familyValue -ne 2) {
                continue
            }

            foreach ($serverAddress in @(Get-SafeMemberValue -InputObject $dnsEntry -Name 'ServerAddresses')) {
                if (-not [string]::IsNullOrWhiteSpace([string]$serverAddress)) {
                    $dnsAddresses += ([string]$serverAddress).Trim()
                }
            }
        }

        $dnsText = '(none configured)'
        if ($dnsAddresses.Count -gt 0) {
            $dnsText = ($dnsAddresses -join ', ')
        }

        # DHCP server, matched on interface index rather than on a description
        # string - Description and NetAdapter.DriverDescription do not reliably
        # agree. Always one value, and honest text when there is none to name.
        # "-ne $true" not "-not [bool]": [bool]'False' is $true in PowerShell.
        $dhcpText = '(unavailable)'
        $dhcpIndex = 0
        if ([int]::TryParse([string](Get-SafeMemberValue -InputObject $configuration -Name 'InterfaceIndex'), [ref]$dhcpIndex)) {
            try {
                $dhcpConfigs = @(Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "InterfaceIndex=$dhcpIndex" -ErrorAction Stop)
                if ($dhcpConfigs.Count -eq 0) {
                    $dhcpText = '(unable to retrieve)'
                } elseif ((Get-SafeMemberValue -InputObject $dhcpConfigs[0] -Name 'DHCPEnabled') -ne $true) {
                    $dhcpText = '(static configuration)'
                } else {
                    $dhcpText = '(DHCP enabled, server not reported)'
                    foreach ($server in @(Get-SafeMemberValue -InputObject $dhcpConfigs[0] -Name 'DHCPServer')) {
                        if (-not [string]::IsNullOrWhiteSpace([string]$server)) {
                            $dhcpText = ([string]$server).Trim()
                            break
                        }
                    }
                }
            } catch {
                $dhcpText = '(unable to retrieve)'
            }
        }

        # MSFT_NetAdapter exposes MacAddress; some stacks only fill LinkLayerAddress.
        $macAddress = [string](Get-SafeMemberValue -InputObject $netAdapter -Name 'MacAddress')
        if ([string]::IsNullOrWhiteSpace($macAddress)) {
            $macAddress = [string](Get-SafeMemberValue -InputObject $netAdapter -Name 'LinkLayerAddress')
        }
        if ([string]::IsNullOrWhiteSpace($macAddress)) {
            $macAddress = '(unavailable)'
        }

        $metricText = '(unavailable)'
        if ($null -ne $usableAdapter.RouteMetric) {
            $metricText = [string]$usableAdapter.RouteMetric
        }

        $adapterContent = @(
            "Interface: $interfaceAlias",
            "",
            "YOUR IP ADDRESS: $($address.IPAddress)",
            "CIDR Prefix: /$($address.PrefixLength)",
            "SUBNET MASK: $subnetMaskText",
            "Gateway: $($usableAdapter.Gateway)",
            "Route Metric: $metricText",
            "DNS Servers: $dnsText",
            "DHCP Server: $dhcpText",
            "MAC Address: $macAddress"
        )

        # With one adapter there is no choice to disclose. With several, say
        # plainly which one the scan range came from and how to change it.
        if ($showSelection) {
            if ($adapterPosition -eq 0) {
                $adapterContent += "Used for scan range: YES (lowest route metric)"
            } else {
                $adapterContent += "Used for scan range: no  (menu C sets a custom range)"
            }
        }

        $adapterPosition++

        Show-InfoBox -Title "YOUR MACHINE" -Content $adapterContent -BorderColor Yellow -TitleColor Green -ContentColor White
    }

    # ------------------------------------------------------------------
    # Derive the scan range from the primary adapter - index 0 after the
    # metric sort, i.e. the adapter Windows would route through.
    # ------------------------------------------------------------------
    $primaryAdapter = $usableAdapters[0]
    $localAddress = $primaryAdapter.Address
    $gateway = $primaryAdapter.Gateway

    $localNumber = $localAddress.Number
    $prefixLength = $localAddress.PrefixLength
    $maskNumber = Get-IPv4SubnetMaskNumber -PrefixLength $prefixLength

    $networkNumber = $localNumber -band $maskNumber
    $broadcastNumber = $networkNumber -bor ((-bnot $maskNumber) -band [Int64]4294967295)

    # RFC 3021: a /31 is a point-to-point link with two usable addresses and
    # no broadcast; a /32 is a single host. Everything wider reserves the
    # network and broadcast addresses.
    if ($prefixLength -ge 32) {
        $firstUsableNumber = $networkNumber
        $lastUsableNumber = $networkNumber
        $totalUsableIPs = [Int64]1
    } elseif ($prefixLength -eq 31) {
        $firstUsableNumber = $networkNumber
        $lastUsableNumber = $networkNumber + 1
        $totalUsableIPs = [Int64]2
    } else {
        $firstUsableNumber = $networkNumber + 1
        $lastUsableNumber = $broadcastNumber - 1
        $totalUsableIPs = [Int64][Math]::Pow(2, (32 - $prefixLength)) - 2
    }

    $networkAddress = ConvertFrom-IPv4Number -Number $networkNumber
    $broadcastAddress = ConvertFrom-IPv4Number -Number $broadcastNumber
    $subnetMask = ConvertFrom-IPv4Number -Number $maskNumber
    $firstUsableIP = ConvertFrom-IPv4Number -Number $firstUsableNumber
    $lastUsableIP = ConvertFrom-IPv4Number -Number $lastUsableNumber

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

    # ------------------------------------------------------------------
    # Position indicator. All three numbers are in the same host byte
    # order, so the ratio is meaningful at /8 and /16 as well as /24.
    # ------------------------------------------------------------------
    Write-Host "  $firstUsableIP " -NoNewline -ForegroundColor Gray

    $rangeSpan = $lastUsableNumber - $firstUsableNumber
    $percentComplete = 0
    if ($rangeSpan -gt 0) {
        $ratio = [double]($localNumber - $firstUsableNumber) / [double]$rangeSpan

        # Clamp: the local address sits outside [first, last] on a /31 or /32,
        # and Show-ProgressBar validates its input to 0-100.
        if ($ratio -lt 0) { $ratio = 0 }
        if ($ratio -gt 1) { $ratio = 1 }

        $percentComplete = [int][Math]::Round($ratio * 100)
    }

    Show-ProgressBar -PercentComplete $percentComplete -Width 50 -FillColor Green -EmptyColor DarkGray
    Write-Host " $lastUsableIP" -ForegroundColor Gray
    Write-Host ""

    $primaryAlias = [string](Get-SafeMemberValue -InputObject $primaryAdapter.Configuration -Name 'InterfaceAlias')
    if ([string]::IsNullOrWhiteSpace($primaryAlias)) {
        $primaryAlias = '(unknown)'
    }

    return @{
        FirstIP          = $firstUsableIP
        LastIP           = $lastUsableIP
        Gateway          = $gateway
        LocalIP          = $localAddress.IPAddress
        PrefixLength     = [int]$prefixLength
        SubnetMask       = $subnetMask
        NetworkAddress   = $networkAddress
        BroadcastAddress = $broadcastAddress
        TotalUsableIPs   = $totalUsableIPs
        InterfaceAlias   = $primaryAlias
        InterfaceMetric  = $primaryAdapter.RouteMetric
    }
}

# Strict a.b.c.d IPv4 test. [IPAddress]::TryParse is far too permissive to use as
# a gate on its own: it accepts "10", "1.2", "192.168.1", "010.0.0.1" and
# "2130706433" and silently rewrites every one of them into a different address.
# Round-tripping the parsed address back to text rejects all of those, plus IPv6.
function Test-IPv4AddressText {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text
    )

    if ([string]::IsNullOrWhiteSpace($Text)) {
        return $false
    }

    $candidate = $Text.Trim()

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($candidate, [ref]$parsed)) {
        return $false
    }

    if ($null -eq $parsed) {
        return $false
    }

    # IPv4 only - the whole scan engine is IPv4
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $false
    }

    # The round-trip is the real test: octal, short-form and integer notations
    # all parse, but none of them come back as the text that went in
    if ($parsed.ToString() -ne $candidate) {
        return $false
    }

    return $true
}

# Basic device type from address, hostname and gateway. Hoisted out of the
# per-host runspace scriptblock so it is parsed once for the whole scan instead of
# once per host - classification runs in the calling thread after each harvest.
function Get-BasicDeviceType {
    [CmdletBinding()]
    param (
        [string]$IPAddressText = "",

        [string]$Hostname = "",

        [string]$Gateway = ""
    )

    # Check if it's the gateway (only when a gateway was actually supplied)
    if ($Gateway -ne "" -and $IPAddressText -eq $Gateway) {
        return "Router/Gateway"
    }

    # Basic hostname analysis
    if ($Hostname -ne "Unknown" -and $Hostname -ne "") {
        $lowercaseHostname = $Hostname.ToLower()

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

# One device-type colour map for the whole tool. A bare 'switch -Regex' without
# 'break' runs EVERY matching branch, so a type like "Network Print Server" gets
# written twice and wrecks the table alignment. Returning from inside the switch
# guarantees exactly one colour comes back.
function Get-DeviceTypeColor {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [AllowEmptyString()]
        [string]$DeviceType
    )

    if ([string]::IsNullOrEmpty($DeviceType)) {
        return "White"
    }

    switch -Regex ($DeviceType) {
        "Server"                 { return "Red" }
        "Router|Gateway|Network" { return "Magenta" }
        "Printer"                { return "DarkYellow" }
        "Camera"                 { return "DarkCyan" }
    }

    return "White"
}

# IP -> MAC hashtable from the neighbour (ARP) table. One single Get-NetNeighbor
# call for the whole scan instead of one arp.exe process per host. Returns an empty
# hashtable when the cmdlet is unavailable, so callers fall back to MAC "Unknown".
function Get-NeighborMacTable {
    [CmdletBinding()]
    param ()

    $table = @{}

    # Get-NetNeighbor lives in the NetTCPIP module - not guaranteed to be present
    $neighborCmd = Get-Command -Name Get-NetNeighbor -ErrorAction SilentlyContinue
    if ($null -eq $neighborCmd) {
        return $table
    }

    $neighbors = $null
    try {
        $neighbors = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.State -ne "Unreachable" -and $_.State -ne "Incomplete" }
    } catch {
        return $table
    }

    if ($null -eq $neighbors) {
        return $table
    }

    foreach ($neighbor in $neighbors) {
        $neighborIP = [string]$neighbor.IPAddress
        $neighborMAC = [string]$neighbor.LinkLayerAddress

        if ([string]::IsNullOrWhiteSpace($neighborIP) -or [string]::IsNullOrWhiteSpace($neighborMAC)) {
            continue
        }

        $neighborMAC = $neighborMAC.ToUpper()

        # Skip null, broadcast and multicast layer-2 addresses - they are not hosts
        if ($neighborMAC -eq "00-00-00-00-00-00" -or $neighborMAC -eq "FF-FF-FF-FF-FF-FF") {
            continue
        }
        if ($neighborMAC.StartsWith("01-00-5E") -or $neighborMAC.StartsWith("33-33")) {
            continue
        }

        if (-not $table.ContainsKey($neighborIP)) {
            $table[$neighborIP] = $neighborMAC
        }
    }

    return $table
}

# Usable console width, or 80 when it cannot be determined.
function Get-ScanConsoleWidth {
    [CmdletBinding()]
    param ()

    $width = 80

    try {
        if ($null -ne $Host.UI -and $null -ne $Host.UI.RawUI) {
            $rawWidth = [int]$Host.UI.RawUI.WindowSize.Width
            if ($rawWidth -gt 20) {
                $width = $rawWidth
            }
        }
    } catch {
        $width = 80
    }

    return $width
}

# Wipes the current console row so the refreshing progress bar never collides with
# a discovery line. LineWidth must be at least as wide as the longest thing ever
# written to that row, or the leftovers are stranded on screen.
function Clear-ConsoleLine {
    [CmdletBinding()]
    param (
        [int]$LineWidth = 78
    )

    if ($LineWidth -lt 1) {
        $LineWidth = 78
    }

    # Carriage return, pad the whole row with spaces, carriage return again
    Write-Host ("`r" + "".PadRight($LineWidth, " ") + "`r") -NoNewline
}

# One "Found: <ip> (<hostname>) - <DeviceType>" line.
function Write-DiscoveryLine {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [long]$Scanned,

        [Parameter(Mandatory=$true)]
        [long]$Total,

        [Parameter(Mandatory=$true)]
        [PSObject]$Result
    )

    Write-Host ("[{0}/{1}] " -f $Scanned, $Total) -NoNewline -ForegroundColor Gray
    Write-Host "Found: " -NoNewline -ForegroundColor White
    Write-Host "$($Result.IPAddress)" -NoNewline -ForegroundColor Green

    if ($Result.Hostname -ne "Unknown") {
        Write-Host " ($($Result.Hostname))" -NoNewline -ForegroundColor Cyan
    }

    Write-Host " - " -NoNewline
    Write-Host "$($Result.DeviceType)" -NoNewline -ForegroundColor (Get-DeviceTypeColor -DeviceType $Result.DeviceType)

    # Only annotate the non-obvious discoveries so ICMP lines look exactly as before
    if ($Result.DiscoveryMethod -ne "ICMP") {
        Write-Host " [$($Result.DiscoveryMethod)]" -NoNewline -ForegroundColor DarkGray
    }

    Write-Host ""
}

# The in-place progress row: bar, percent, count, rate and ETA.
#
# Every segment is fixed width for a given scan, so the rendered line is the same
# length from the first refresh to the last and one carriage return always
# overwrites all of it. The line is budgeted to fit LineWidth - the bar shrinks
# first, then the ETA is dropped, then the rate. It must NEVER wrap: a wrapped line
# cannot be erased with a single carriage return, and the stranded head of the bar
# is left sitting above every discovery line for the rest of the scan.
function Write-ScanProgressLine {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [long]$Scanned,

        [Parameter(Mandatory=$true)]
        [long]$Total,

        [Parameter(Mandatory=$true)]
        [double]$ElapsedSeconds,

        [int]$LineWidth = 78
    )

    if ($LineWidth -lt 20) {
        $LineWidth = 20
    }

    $percentComplete = 0
    if ($Total -gt 0) {
        $percentComplete = [Math]::Min(100, [Math]::Max(0, [int](($Scanned / $Total) * 100)))
    }

    $scanRate = 0
    if ($ElapsedSeconds -gt 0) {
        $scanRate = $Scanned / $ElapsedSeconds
    }

    # Compact hh:mm:ss instead of the old three-branch "1h 2m" / "3m 4s" / "5s"
    # block - one line, constant width, and it buys back display columns
    $etaText = "--:--:--"
    if ($scanRate -gt 0) {
        $secondsRemaining = ($Total - $Scanned) / $scanRate
        if ($secondsRemaining -lt 0) {
            $secondsRemaining = 0
        }
        if ($secondsRemaining -gt 356399) {
            $secondsRemaining = 356399
        }
        $span = [TimeSpan]::FromSeconds($secondsRemaining)
        $etaText = "{0:00}:{1:00}:{2:00}" -f [int]$span.TotalHours, $span.Minutes, $span.Seconds
    }

    $label = "Scanning progress: "
    $pctText = "{0,3}%" -f $percentComplete

    # Right-align the running count against the width of the total so the segment
    # never changes length while the scan runs
    $totalText = [string]$Total
    $countFormat = "({0," + $totalText.Length + "}/{1})"
    $countText = $countFormat -f $Scanned, $totalText

    $rateText = "{0,6:0.0}/s" -f $scanRate
    $etaSegment = "ETA $etaText"

    # Budget the row. Shrink the bar before sacrificing any readout, then give up
    # the ETA, then the rate.
    $showRate = $true
    $showEta = $true

    $fixedLength = $label.Length + 1 + $pctText.Length + 1 + $countText.Length + 1 + $rateText.Length + 1 + $etaSegment.Length
    $barWidth = $LineWidth - $fixedLength - 2

    if ($barWidth -lt 10) {
        $showEta = $false
        $fixedLength = $label.Length + 1 + $pctText.Length + 1 + $countText.Length + 1 + $rateText.Length
        $barWidth = $LineWidth - $fixedLength - 2
    }

    if ($barWidth -lt 10) {
        $showRate = $false
        $fixedLength = $label.Length + 1 + $pctText.Length + 1 + $countText.Length
        $barWidth = $LineWidth - $fixedLength - 2
    }

    if ($barWidth -gt 40) {
        $barWidth = 40
    }

    # Console too narrow for a bar at all - fall back to plain text, truncated
    if ($barWidth -lt 10) {
        $plainLine = $label + " " + $pctText + " " + $countText
        if ($plainLine.Length -gt $LineWidth) {
            $plainLine = $plainLine.Substring(0, $LineWidth)
        }
        Write-Host "`r" -NoNewline
        Write-Host $plainLine -NoNewline -ForegroundColor White
        return
    }

    Write-Host "`r" -NoNewline
    Write-Host $label -NoNewline -ForegroundColor White
    Show-ProgressBar -PercentComplete $percentComplete -Width $barWidth -FillColor Cyan -EmptyColor DarkGray
    Write-Host " $pctText" -NoNewline -ForegroundColor Cyan
    Write-Host " $countText" -NoNewline -ForegroundColor White

    if ($showRate) {
        Write-Host " $rateText" -NoNewline -ForegroundColor Yellow
    }

    if ($showEta) {
        Write-Host " $etaSegment" -NoNewline -ForegroundColor Yellow
    }
}

# Total rendered width of a column spec, borders included.
function Get-TableTotalWidth {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [hashtable[]]$Columns
    )

    # One separator between every pair of columns, plus the two outer edges
    $total = $Columns.Count + 1
    foreach ($column in $Columns) {
        $total += $column.Width
    }

    return $total
}

# One table cell: leading space, value, truncated with an ellipsis, padded to width.
function Format-CellText {
    [CmdletBinding()]
    param (
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Text,

        [Parameter(Mandatory=$true)]
        [int]$Width
    )

    $cell = " "
    if (-not [string]::IsNullOrEmpty($Text)) {
        $cell = " " + $Text
    }

    if ($cell.Length -gt $Width) {
        if ($Width -gt 3) {
            $cell = $cell.Substring(0, $Width - 3) + "..."
        } else {
            $cell = $cell.Substring(0, $Width)
        }
    }

    return $cell.PadRight($Width, " ")
}

# One box-drawn border row, derived from the column spec.
function Write-TableBorder {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [hashtable[]]$Columns,

        [Parameter(Mandatory=$true)]
        [string]$Left,

        [Parameter(Mandatory=$true)]
        [string]$Junction,

        [Parameter(Mandatory=$true)]
        [string]$Right
    )

    Write-Host $Left -NoNewline -ForegroundColor Cyan

    for ($i = 0; $i -lt $Columns.Count; $i++) {
        Write-Host "".PadRight($Columns[$i].Width, "─") -NoNewline -ForegroundColor Cyan
        if ($i -lt ($Columns.Count - 1)) {
            Write-Host $Junction -NoNewline -ForegroundColor Cyan
        }
    }

    Write-Host $Right -ForegroundColor Cyan
}

# The box-drawn results table.
#
# Column widths live in one spec instead of being hand-repeated across four border
# rows, the header row and the data rows - that duplication is exactly how the old
# table drifted a character out of alignment. The table is capped to the console
# width: columns shrink toward their minimums first and are dropped only as a last
# resort, so an 80-column console does not wrap every single row.
function Show-ScanResultsTable {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [AllowEmptyCollection()]
        [PSObject[]]$Results
    )

    $columns = @(
        @{ Header = "IP Address";  Property = "IPAddress";    Width = 15; Min = 15; Color = "Green";  ByDeviceType = $false },
        @{ Header = "Hostname";    Property = "Hostname";     Width = 25; Min = 12; Color = "Cyan";   ByDeviceType = $false },
        @{ Header = "Device Type"; Property = "DeviceType";   Width = 15; Min = 12; Color = "White";  ByDeviceType = $true },
        @{ Header = "Response";    Property = "ResponseTime"; Width = 10; Min = 9;  Color = "Yellow"; ByDeviceType = $false },
        @{ Header = "MAC Address"; Property = "MAC";          Width = 19; Min = 17; Color = "Gray";   ByDeviceType = $false }
    )

    $available = (Get-ScanConsoleWidth) - 1

    # Shrink the roomiest columns first
    foreach ($shrinkHeader in @("Hostname", "MAC Address", "Device Type", "Response")) {
        $excess = (Get-TableTotalWidth -Columns $columns) - $available
        if ($excess -le 0) {
            break
        }

        foreach ($column in $columns) {
            if ($column.Header -eq $shrinkHeader) {
                $room = $column.Width - $column.Min
                if ($room -gt 0) {
                    $column.Width = $column.Width - [Math]::Min($excess, $room)
                }
            }
        }
    }

    # Still too wide - start dropping the least essential columns
    foreach ($dropHeader in @("MAC Address", "Response", "Device Type")) {
        if ((Get-TableTotalWidth -Columns $columns) -le $available) {
            break
        }
        $columns = @($columns | Where-Object { $_.Header -ne $dropHeader })
    }

    $tableWidth = Get-TableTotalWidth -Columns $columns

    Write-Host "`n" -NoNewline

    # Top border and title row span the full table width
    Write-Host "┌" -NoNewline -ForegroundColor Cyan
    Write-Host "".PadRight($tableWidth - 2, "─") -NoNewline -ForegroundColor Cyan
    Write-Host "┐" -ForegroundColor Cyan

    Write-Host "│" -NoNewline -ForegroundColor Cyan
    Write-Host " SCAN RESULTS ".PadRight($tableWidth - 2, " ") -NoNewline -ForegroundColor Yellow
    Write-Host "│" -ForegroundColor Cyan

    Write-TableBorder -Columns $columns -Left "├" -Junction "┬" -Right "┤"

    # Header row
    Write-Host "│" -NoNewline -ForegroundColor Cyan
    foreach ($column in $columns) {
        Write-Host (Format-CellText -Text $column.Header -Width $column.Width) -NoNewline -ForegroundColor White
        Write-Host "│" -NoNewline -ForegroundColor Cyan
    }
    Write-Host ""

    Write-TableBorder -Columns $columns -Left "├" -Junction "┼" -Right "┤"

    # Data rows
    foreach ($result in $Results) {
        Write-Host "│" -NoNewline -ForegroundColor Cyan

        foreach ($column in $columns) {
            $cellColor = $column.Color
            if ($column.ByDeviceType) {
                $cellColor = Get-DeviceTypeColor -DeviceType ([string]$result.DeviceType)
            }

            $cellText = Format-CellText -Text ([string]$result.($column.Property)) -Width $column.Width
            Write-Host $cellText -NoNewline -ForegroundColor $cellColor
            Write-Host "│" -NoNewline -ForegroundColor Cyan
        }

        Write-Host ""
    }

    Write-TableBorder -Columns $columns -Left "└" -Junction "┴" -Right "┘"
}

function Start-NetworkScan {
    <#
    .SYNOPSIS
        Scans a range of IPv4 addresses for live hosts
    .DESCRIPTION
        Sweeps every address between StartIP and EndIP using a throttled runspace pool.
        Each address is probed with ICMP first; when TcpFallback is enabled and the ping
        times out, a short TCP connect is attempted against 445, 135 and 80 so hosts that
        drop inbound ping (the Windows Firewall default on Public/Domain profiles) are
        still discovered. Hosts that answer nothing at all but appear in the neighbour
        table are reported too.

        MAC addresses are resolved with a single Get-NetNeighbor lookup after the sweep
        instead of one arp.exe process per host, and hostname resolution uses an
        asynchronous DNS call with a hard timeout so dead PTR lookups cannot dominate
        the scan.

        Both addresses are validated here rather than trusted from the caller: this
        function is the authoritative choke point, because a malformed address that
        merely parses would otherwise scan a completely different range and report
        success.
    .PARAMETER StartIP
        First address of the range to scan
    .PARAMETER EndIP
        Last address of the range to scan
    .PARAMETER TimeoutMilliseconds
        ICMP echo timeout per host (default 300)
    .PARAMETER MaxThreads
        Maximum number of concurrent runspaces (default 50)
    .PARAMETER Gateway
        Default gateway address, used to flag the router in the device-type heuristic
    .PARAMETER ResolveHostnames
        Set to $false to skip reverse DNS entirely (default $true)
    .PARAMETER TcpFallback
        Set to $false to disable the TCP connect fallback (default $true)
    .OUTPUTS
        An array of PSCustomObject with the properties IPAddress, Hostname, MAC, Status,
        ResponseTime, DeviceType and DiscoveryMethod. An empty array when nothing is
        found, or when the supplied range is rejected.
    .EXAMPLE
        Start-NetworkScan -StartIP "192.168.1.1" -EndIP "192.168.1.254" -Gateway "192.168.1.1"
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$StartIP,

        [Parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$EndIP,

        [int]$TimeoutMilliseconds = 300,

        [int]$MaxThreads = 50,

        [string]$Gateway = '',

        [bool]$ResolveHostnames = $true,

        [bool]$TcpFallback = $true
    )

    $emptyResults = @()

    # Validate before anything else. An address that merely parses is not good
    # enough - "010.0.0.1", "1.2", "192.168.1", "10" and "2130706433" all parse
    # and all silently become a different address.
    $addressProblems = @()
    if (-not (Test-IPv4AddressText -Text $StartIP)) {
        $addressProblems += "Start: '$StartIP'"
    }
    if (-not (Test-IPv4AddressText -Text $EndIP)) {
        $addressProblems += "End:   '$EndIP'"
    }

    if ($addressProblems.Count -gt 0) {
        $addressErrorContent = @(
            "Not a valid IPv4 address in a.b.c.d form:"
        )
        $addressErrorContent += $addressProblems
        $addressErrorContent += ""
        $addressErrorContent += "Nothing was scanned."

        Show-InfoBox -Title "INVALID ADDRESS" -Content $addressErrorContent -BorderColor Red -TitleColor Yellow
        return ,$emptyResults
    }

    $startIPText = $StartIP.Trim()
    $endIPText = $EndIP.Trim()

    # ConvertTo-IPv4Number returns $null rather than throwing on bad input
    $startIPNumber = ConvertTo-IPv4Number -IPAddress $startIPText
    $endIPNumber = ConvertTo-IPv4Number -IPAddress $endIPText

    if ($null -eq $startIPNumber -or $null -eq $endIPNumber) {
        $convertErrorContent = @(
            "The scan range could not be converted to numbers:",
            "Start: '$startIPText'",
            "End:   '$endIPText'",
            "",
            "Nothing was scanned."
        )

        Show-InfoBox -Title "INVALID ADDRESS" -Content $convertErrorContent -BorderColor Red -TitleColor Yellow
        return ,$emptyResults
    }

    if ($endIPNumber -lt $startIPNumber) {
        $rangeErrorContent = @(
            "The start address is higher than the end address.",
            "Start: $startIPText",
            "End:   $endIPText"
        )

        Show-InfoBox -Title "INVALID RANGE" -Content $rangeErrorContent -BorderColor Red -TitleColor Yellow
        return ,$emptyResults
    }

    # Guard the tunables so a bad value cannot wedge the pool
    if ($TimeoutMilliseconds -lt 50) { $TimeoutMilliseconds = 50 }
    if ($MaxThreads -lt 1) { $MaxThreads = 1 }
    if ($MaxThreads -gt 256) { $MaxThreads = 256 }

    $gatewayText = ""
    if (-not [string]::IsNullOrWhiteSpace($Gateway)) {
        $gatewayText = $Gateway.Trim()
    }

    # Probe settings for the fallback paths - kept tight so they cannot balloon the scan
    $tcpProbePorts = @(445, 135, 80)
    $tcpProbeTimeout = 150
    $dnsProbeTimeout = 500

    # Calculate total IPs to scan
    $totalIPs = [long]($endIPNumber - $startIPNumber + 1)

    $scanInfo = @(
        "Preparing to scan $totalIPs IP addresses",
        "Range: $startIPText to $endIPText",
        "Timeout: $TimeoutMilliseconds ms per host",
        "Thread count: $MaxThreads concurrent scans"
    )

    Show-InfoBox -Title "SCAN CONFIGURATION" -Content $scanInfo -BorderColor Magenta -TitleColor Yellow

    # Check if the range is reasonable (prevent huge ranges) - '-gt', not '>', which
    # is the file redirection operator and would silently create a file named 10000
    if (($endIPNumber - $startIPNumber) -gt 10000) {
        $warningContent = @(
            "Very large IP range detected ($totalIPs addresses).",
            "This may take a very long time to complete."
        )

        Show-InfoBox -Title "WARNING" -Content $warningContent -BorderColor Red -TitleColor Yellow

        $confirm = Read-Host "Continue with this range? (Y/N)"
        if ($confirm -ne "Y" -and $confirm -ne "y") {
            return ,$emptyResults
        }
    }

    # Track results
    $results = New-Object System.Collections.ArrayList
    $scanStartTime = Get-Date

    # Progress counters
    $totalScanned = [long]0
    $totalActive = [long]0

    # Create a hashtable to track device types for summary
    $deviceTypeCounts = @{}

    $startingContent = @(
        "Starting network scan at $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')",
        "Discovering active hosts on your network...",
        ""
    )

    Show-InfoBox -Title "STARTING SCAN" -Content $startingContent -BorderColor Yellow -TitleColor Green -Center

    # The progress row is budgeted to this width and never exceeds it, so one
    # carriage return always erases all of it - no wrapped, stranded half-bars
    $progressWidth = [Math]::Min((Get-ScanConsoleWidth) - 1, 78)

    # This scriptblock runs once per address inside the pool. It stays deliberately
    # small: no device classification, no ARP, no console output.
    $scanScriptBlock = {
        param (
            [string]$IPAddressText,
            [int]$Timeout,
            [bool]$ResolveNames,
            [bool]$UseTcpFallback,
            [int[]]$TcpPorts,
            [int]$TcpTimeout,
            [int]$DnsTimeout
        )

        $discoveryMethod = $null
        $responseTime = "N/A"

        # ICMP first - wrapped so a PingException on an unreachable network cannot
        # kill the runspace, and disposed on every path
        $ping = $null
        try {
            $ping = New-Object System.Net.NetworkInformation.Ping
            $reply = $ping.Send($IPAddressText, $Timeout)
            if ($null -ne $reply -and $reply.Status -eq 'Success') {
                $discoveryMethod = "ICMP"
                $responseTime = "$($reply.RoundtripTime) ms"
            }
        } catch {
            $discoveryMethod = $null
        } finally {
            if ($null -ne $ping) {
                try { $ping.Dispose() } catch { }
            }
        }

        # TCP connect fallback - Windows blocks inbound ping by default on the
        # Public and Domain firewall profiles, so ICMP alone under-reports badly
        if ($null -eq $discoveryMethod -and $UseTcpFallback) {
            foreach ($port in $TcpPorts) {
                $client = $null
                try {
                    $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
                    $client = New-Object System.Net.Sockets.TcpClient
                    $asyncConnect = $client.BeginConnect($IPAddressText, $port, $null, $null)

                    if ($asyncConnect.AsyncWaitHandle.WaitOne($TcpTimeout, $false)) {
                        $connected = $false
                        try {
                            $client.EndConnect($asyncConnect)
                            $connected = $client.Connected
                        } catch {
                            $connected = $false
                        }

                        if ($connected) {
                            $stopwatch.Stop()
                            $discoveryMethod = "TCP:$port"
                            $responseTime = "$([int]$stopwatch.ElapsedMilliseconds) ms"
                        }
                    }
                } catch {
                    # Refused, filtered or unroutable - just try the next port
                } finally {
                    if ($null -ne $client) {
                        try { $client.Close() } catch { }
                    }
                }

                if ($null -ne $discoveryMethod) {
                    break
                }
            }
        }

        if ($null -eq $discoveryMethod) {
            return $null
        }

        # Reverse DNS with a hard ceiling. GetHostEntry blocks for 1-5 seconds where no
        # PTR record exists, which otherwise dwarfs the ping timeout entirely.
        $resolvedName = "Unknown"
        if ($ResolveNames) {
            try {
                $asyncDns = [System.Net.Dns]::BeginGetHostEntry($IPAddressText, $null, $null)
                if ($asyncDns.AsyncWaitHandle.WaitOne($DnsTimeout, $false)) {
                    $entry = [System.Net.Dns]::EndGetHostEntry($asyncDns)
                    if ($null -ne $entry -and -not [string]::IsNullOrWhiteSpace($entry.HostName)) {
                        $resolvedName = $entry.HostName
                    }
                }
                # On timeout the lookup is simply abandoned - the thread pool reaps it
            } catch {
                $resolvedName = "Unknown"
            }
        }

        return [PSCustomObject]@{
            IPAddress = $IPAddressText
            Hostname = $resolvedName
            ResponseTime = $responseTime
            DiscoveryMethod = $discoveryMethod
        }
    }

    # Declared before the try so the finally block can always see them
    $runspacePool = $null
    $inFlight = New-Object System.Collections.ArrayList
    $progressShown = $false

    try {
        # Create a runspace pool
        $runspacePool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads)
        $runspacePool.Open()

        # Producer/consumer throttle: never hold more than this many live PowerShell
        # instances at once. The old code built one per address up front, which is
        # 65,534 instances on a /16 before a single ping was reaped.
        $maxInFlight = $MaxThreads * 2
        $nextIPNumber = $startIPNumber

        $lastUpdateTime = Get-Date
        $updateInterval = [TimeSpan]::FromSeconds(1)

        while ($nextIPNumber -le $endIPNumber -or $inFlight.Count -gt 0) {

            # Dispatch as many new probes as there are free slots
            while ($inFlight.Count -lt $maxInFlight -and $nextIPNumber -le $endIPNumber) {
                $currentIP = ConvertFrom-IPv4Number -Number $nextIPNumber

                $powershell = [powershell]::Create()
                $handle = $null
                try {
                    [void]$powershell.AddScript($scanScriptBlock)
                    [void]$powershell.AddParameter("IPAddressText", $currentIP)
                    [void]$powershell.AddParameter("Timeout", $TimeoutMilliseconds)
                    [void]$powershell.AddParameter("ResolveNames", $ResolveHostnames)
                    [void]$powershell.AddParameter("UseTcpFallback", $TcpFallback)
                    [void]$powershell.AddParameter("TcpPorts", $tcpProbePorts)
                    [void]$powershell.AddParameter("TcpTimeout", $tcpProbeTimeout)
                    [void]$powershell.AddParameter("DnsTimeout", $dnsProbeTimeout)
                    $powershell.RunspacePool = $runspacePool

                    # On its own line: if this throws, the instance is not yet in
                    # $inFlight and the finally block could never dispose it
                    $handle = $powershell.BeginInvoke()
                } catch {
                    try { $powershell.Dispose() } catch { }
                    throw
                }

                [void]$inFlight.Add([PSCustomObject]@{
                    PowerShell = $powershell
                    Handle = $handle
                    IPAddress = $currentIP
                })

                $nextIPNumber = $nextIPNumber + 1
            }

            # Harvest whatever has finished. Walking backwards lets us remove entries
            # in place, so the in-flight list is the only thing we ever enumerate -
            # no Where-Object sweep of every runspace on every tick.
            $completed = New-Object System.Collections.ArrayList
            for ($i = $inFlight.Count - 1; $i -ge 0; $i--) {
                if ($inFlight[$i].Handle.IsCompleted) {
                    [void]$completed.Add($inFlight[$i])
                    $inFlight.RemoveAt($i)
                }
            }

            # $completed came off the list newest-first; walk it in reverse so the
            # live feed reads in ascending address order like the user expects
            for ($j = $completed.Count - 1; $j -ge 0; $j--) {
                $job = $completed[$j]

                $record = $null
                try {
                    $output = $job.PowerShell.EndInvoke($job.Handle)
                    if ($null -ne $output -and $output.Count -gt 0) {
                        $record = $output[0]
                    }
                } catch {
                    if ($progressShown) {
                        Clear-ConsoleLine -LineWidth $progressWidth
                        $progressShown = $false
                    }
                    Write-Host ("[{0}/{1}] " -f $totalScanned, $totalIPs) -NoNewline -ForegroundColor Gray
                    Write-Host "Error processing IP $($job.IPAddress): $($_.Exception.Message)" -ForegroundColor Red
                }

                if ($null -ne $record) {
                    $hostname = [string]$record.Hostname
                    $deviceType = Get-BasicDeviceType -IPAddressText $job.IPAddress -Hostname $hostname -Gateway $gatewayText

                    $hostResult = [PSCustomObject]@{
                        IPAddress = $job.IPAddress
                        Hostname = $hostname
                        MAC = "Unknown"
                        Status = "Online"
                        ResponseTime = [string]$record.ResponseTime
                        DeviceType = $deviceType
                        DiscoveryMethod = [string]$record.DiscoveryMethod
                    }

                    [void]$results.Add($hostResult)
                    $totalActive++

                    # Update device type counts
                    if (-not $deviceTypeCounts.ContainsKey($deviceType)) {
                        $deviceTypeCounts[$deviceType] = 0
                    }
                    $deviceTypeCounts[$deviceType]++

                    # Wipe the progress row before printing so the two never interleave,
                    # then leave it blank - the normal one second cadence redraws it.
                    # Forcing a redraw here instead would smear a fresh bar between
                    # every pair of discovery lines.
                    if ($progressShown) {
                        Clear-ConsoleLine -LineWidth $progressWidth
                        $progressShown = $false
                    }

                    Write-DiscoveryLine -Scanned $totalScanned -Total $totalIPs -Result $hostResult
                }

                # Clean up
                $job.PowerShell.Dispose()
                $totalScanned++
            }

            # Update progress on the usual one second cadence
            $currentTime = Get-Date
            if (($currentTime - $lastUpdateTime) -gt $updateInterval) {
                Write-ScanProgressLine -Scanned $totalScanned -Total $totalIPs -ElapsedSeconds ($currentTime - $scanStartTime).TotalSeconds -LineWidth $progressWidth
                $progressShown = $true
                $lastUpdateTime = $currentTime
            }

            # Sleep briefly to reduce CPU usage, but only when nothing was ready
            if ($completed.Count -eq 0) {
                Start-Sleep -Milliseconds 20
            }
        }
    }
    finally {
        # Guarantee cleanup on every exit path, including Ctrl+C mid-scan
        foreach ($job in $inFlight) {
            try { $job.PowerShell.Stop() } catch { }
            try { [void]$job.PowerShell.EndInvoke($job.Handle) } catch { }
            try { $job.PowerShell.Dispose() } catch { }
        }
        $inFlight.Clear()

        if ($null -ne $runspacePool) {
            try { $runspacePool.Close() } catch { }
            try { $runspacePool.Dispose() } catch { }
        }
    }

    # Clear the progress line
    Clear-ConsoleLine -LineWidth $progressWidth
    Write-Host ""

    # One neighbour lookup for the whole scan. The sweep itself populates the table,
    # so this single snapshot covers both the MAC join and the ARP-only hosts.
    $macTable = Get-NeighborMacTable

    $knownIPs = @{}
    foreach ($result in $results) {
        if ($macTable.ContainsKey($result.IPAddress)) {
            $result.MAC = $macTable[$result.IPAddress]
        }
        $knownIPs[$result.IPAddress] = $true
    }

    # An in-range neighbour that answered nothing at all is still a live host -
    # the classic "replies to ARP, drops ICMP and TCP" case
    foreach ($neighborIP in $macTable.Keys) {
        if ($knownIPs.ContainsKey($neighborIP)) {
            continue
        }

        # $null means the neighbour is not a plain IPv4 address - skip, never throw
        $neighborNumber = ConvertTo-IPv4Number -IPAddress $neighborIP
        if ($null -eq $neighborNumber) {
            continue
        }

        # Only addresses inside the requested range
        if ($neighborNumber -lt $startIPNumber -or $neighborNumber -gt $endIPNumber) {
            continue
        }

        $deviceType = Get-BasicDeviceType -IPAddressText $neighborIP -Hostname "Unknown" -Gateway $gatewayText

        $arpResult = [PSCustomObject]@{
            IPAddress = $neighborIP
            Hostname = "Unknown"
            MAC = $macTable[$neighborIP]
            Status = "Online"
            ResponseTime = "N/A"
            DeviceType = $deviceType
            DiscoveryMethod = "ARP"
        }

        [void]$results.Add($arpResult)
        $knownIPs[$neighborIP] = $true
        $totalActive++

        if (-not $deviceTypeCounts.ContainsKey($deviceType)) {
            $deviceTypeCounts[$deviceType] = 0
        }
        $deviceTypeCounts[$deviceType]++

        Write-DiscoveryLine -Scanned $totalScanned -Total $totalIPs -Result $arpResult
    }

    $scanEndTime = Get-Date
    $scanDuration = $scanEndTime - $scanStartTime

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

    # Sort results by IP address
    $sortedResults = @($results | Sort-Object { ConvertTo-IPv4Number -IPAddress $_.IPAddress })

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
    if ($sortedResults.Count -gt 0) {
        Show-ScanResultsTable -Results $sortedResults
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

    # Emit the array itself, never unrolled - callers get @() when nothing was found
    return ,$sortedResults
}

function Wait-ForAnyKey {
    <#
    .SYNOPSIS
        Waits for a single key press, falling back to Read-Host where RawUI is unavailable
    .DESCRIPTION
        $Host.UI.RawUI.ReadKey() is not implemented by every PowerShell host. The ISE,
        remoting sessions and non-interactive hosts throw when it is called. This helper
        probes RawUI.KeyAvailable first (which throws in exactly the same hosts) and
        degrades to a plain Read-Host instead of blowing up the caller.
    .PARAMETER Message
        Prompt printed once, in both the ReadKey and the Read-Host paths, so
        callers must NOT print their own prompt as well
    .EXAMPLE
        Wait-ForAnyKey -Message "Press any key to return to the main menu"
    #>
    [CmdletBinding()]
    param (
        [string]$Message = "Press any key to continue"
    )

    $canReadKey = $false

    try {
        if ($null -ne $Host.UI -and $null -ne $Host.UI.RawUI) {
            # Touching KeyAvailable throws in hosts that do not implement raw input.
            $null = $Host.UI.RawUI.KeyAvailable
            $canReadKey = $true
        }
    } catch {
        $canReadKey = $false
    }

    if ($canReadKey) {
        try {
            # ReadKey prints nothing, so we print the prompt ourselves - exactly
            # once, matching the fallback path below.
            Write-Host $Message -ForegroundColor Cyan
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        } catch {
            # Fall through to the Read-Host path below.
            $canReadKey = $false
        }
    }

    # Read-Host prints the prompt itself (with a trailing ": ").
    $null = Read-Host $Message
}

function Test-IPv4Address {
    <#
    .SYNOPSIS
        Returns $true only for a real dotted-quad IPv4 address
    .DESCRIPTION
        [System.Net.IPAddress]::TryParse is address-family agnostic and accepts
        legacy shorthand: "10" parses to 0.0.0.10, "1.2.3" to 1.2.0.3, and IPv6
        literals like ::1 are accepted too. This helper additionally requires four
        dotted decimal octets, each 0-255, in the InterNetwork (IPv4) family, so
        the menu never stores a silently mangled address.
    .PARAMETER Candidate
        The trimmed user input to validate
    .EXAMPLE
        if (Test-IPv4Address $userInput) { ... }
    #>
    [CmdletBinding()]
    param (
        [string]$Candidate
    )

    if ([string]::IsNullOrWhiteSpace($Candidate)) { return $false }
    if ($Candidate -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return $false }

    foreach ($octet in $Candidate.Split('.')) {
        if ([int]$octet -gt 255) { return $false }
    }

    $parsed = $null
    if (-not [System.Net.IPAddress]::TryParse($Candidate, [ref]$parsed)) { return $false }
    if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { return $false }

    return $true
}

function Show-Menu {
    <#
    .SYNOPSIS
        Displays the interactive PowerSweep Lite menu and drives the scan workflow
    .DESCRIPTION
        Renders the current settings and actions, dispatches on the key the user
        typed, and loops until Q (or stdin EOF). The most recent scan is kept in
        memory for the session so R can redisplay it without rescanning, and is
        mirrored to $Global:PowerSweepLastScan for 'irm ... | iex' users. This is
        the Lite edition: there is deliberately no CSV/JSON export.
    .PARAMETER NetworkInfo
        Hashtable from Get-LocalNetworkInfo. Keys used: FirstIP, LastIP, Gateway
    .NOTES
        Menu keys: S start scan, C custom range, N reset range, T advanced settings,
        R redisplay last results, H help/about, Q quit.
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [ValidateNotNull()]
        [hashtable]$NetworkInfo
    )

    # Index syntax ($NetworkInfo['FirstIP']) yields $null for a missing key WITHOUT
    # tripping Set-StrictMode; dot syntax would throw. Cast coalesces $null to "".
    $netFirstIP = [string]$NetworkInfo['FirstIP']
    $netLastIP  = [string]$NetworkInfo['LastIP']
    $netGateway = [string]$NetworkInfo['Gateway']

    # Single source of truth for every scan parameter. Timeout and thread count are
    # always passed explicitly to Start-NetworkScan so its own defaults never apply.
    $scanOptions = @{
        StartIP          = $netFirstIP
        EndIP            = $netLastIP
        Timeout          = 300
        ThreadCount      = 50
        ResolveHostnames = $true
        TcpFallback      = $true
    }

    $lastScanResults = @()
    $lastScanTime    = $null
    $lastScanRange   = ""
    $firstDraw       = $true
    $menuActive      = $true

    while ($menuActive) {
        Clear-Host

        # Animate only the first time in - redrawing the animation on every keystroke
        # made the menu feel sluggish.
        if ($firstDraw) {
            Show-Banner -Animate
            $firstDraw = $false
        } else {
            Show-Banner
        }

        $resolveState = "Disabled"
        if ($scanOptions.ResolveHostnames) { $resolveState = "Enabled" }

        $tcpState = "Disabled"
        if ($scanOptions.TcpFallback) { $tcpState = "Enabled" }

        $lastScanState = "None yet this session"
        if ($null -ne $lastScanTime) {
            $lastScanState = "$($lastScanResults.Count) host(s) at $($lastScanTime.ToString('HH:mm:ss'))"
        }

        # A blank StartIP/EndIP (degenerate NetworkInfo, or the N reset restoring an
        # empty detected range) would trip Start-NetworkScan's Mandatory +
        # ValidateNotNullOrEmpty binding far from here. Gate the S action instead.
        $startBlank = [string]::IsNullOrWhiteSpace($scanOptions.StartIP)
        $endBlank   = [string]::IsNullOrWhiteSpace($scanOptions.EndIP)
        $rangeReady = -not ($startBlank -or $endBlank)

        $rangeDisplay = "$($scanOptions.StartIP) to $($scanOptions.EndIP)"
        if (-not $rangeReady) {
            $rangeDisplay = "unavailable - press C to set a custom range"
        }

        $settingsContent = @(
            "IP Range          : $rangeDisplay",
            "Gateway           : $netGateway",
            "Timeout           : $($scanOptions.Timeout) ms",
            "Thread Count      : $($scanOptions.ThreadCount)",
            "Resolve Hostnames : $resolveState",
            "TCP Fallback      : $tcpState",
            "Last Scan         : $lastScanState"
        )

        Show-InfoBox -Title "CURRENT SETTINGS" -Content $settingsContent -BorderColor Cyan -TitleColor Yellow

        $actionsContent = @(
            "S. Start Network Scan",
            "C. Change IP Range to Custom Values",
            "N. Reset IP Range to Network Range",
            "T. Configure Advanced Settings",
            "R. Redisplay Last Scan Results",
            "H. Help & About Information",
            "Q. Quit PowerSweep Lite"
        )

        Show-InfoBox -Title "ACTIONS" -Content $actionsContent -BorderColor Cyan -TitleColor Green

        # Single-line prompt. Read-Host emits its own newline when ENTER is pressed,
        # so a drawn box around it can never close on the right row.
        Write-Host ""
        Write-Host " Enter your choice " -NoNewline -ForegroundColor White -BackgroundColor DarkBlue
        Write-Host " > " -NoNewline -ForegroundColor Yellow
        $choice = Read-Host
        if ($null -eq $choice) {
            # Read-Host returns $null (not "") at stdin EOF - piped/redirected input
            # that has run out. Without this the loop would spin forever redrawing
            # at ~400 iterations/sec. Exit cleanly, as if the user pressed Q.
            $menuActive = $false
            continue
        }
        $choice = $choice.Trim()

        if ($choice.Length -eq 0) {
            continue
        }

        # Every pattern is anchored and every branch breaks. Without both, PowerShell
        # runs *every* matching branch - "1t" used to fire two actions at once.
        switch -Regex ($choice) {
            "^[Ss]$" {
                if (-not $rangeReady) {
                    Write-Host "No network range is available to scan. Press C to set a custom IP range first." -ForegroundColor Red
                    Start-Sleep -Seconds 2
                    break
                }

                # Loop the scan for as long as the user answers Y, so the "scan again?"
                # prompt actually does something.
                $runScan = $true

                while ($runScan) {
                    Clear-Host

                    # Splatted rather than backtick-continued: no trailing-whitespace
                    # hazard at assembly time. Timeout and thread count are always
                    # passed, so the scan function's own defaults never apply.
                    $scanParameters = @{
                        StartIP             = $scanOptions.StartIP
                        EndIP               = $scanOptions.EndIP
                        TimeoutMilliseconds = $scanOptions.Timeout
                        MaxThreads          = $scanOptions.ThreadCount
                        Gateway             = $netGateway
                        ResolveHostnames    = $scanOptions.ResolveHostnames
                        TcpFallback         = $scanOptions.TcpFallback
                    }

                    # Guard the scan: any exception it throws (bad input, a WMI/CIM
                    # hiccup, a runspace failure) must return to the menu, never
                    # unwind Show-Menu and take the GOODBYE box + key-wait with it -
                    # which on a double-clicked window means it vanishes on an error
                    # the user cannot read.
                    try {
                        $lastScanResults = @(Start-NetworkScan @scanParameters)

                        $lastScanTime  = Get-Date
                        $lastScanRange = "$($scanOptions.StartIP) to $($scanOptions.EndIP)"

                        # Keep the objects reachable after the menu exits (no export).
                        $Global:PowerSweepLastScan = $lastScanResults

                        $postScanContent = @(
                            "$($lastScanResults.Count) host(s) found. Results are kept in memory;",
                            "press R at the main menu to show them again without rescanning.",
                            "",
                            "Options:",
                            "  Y - Run the same scan again",
                            "  N - Return to main menu"
                        )

                        Show-InfoBox -Title "SCAN AGAIN?" -Content $postScanContent -BorderColor Yellow -TitleColor Green

                        $scanAgain = Read-Host "Your choice (Y/N)"
                        if ($null -eq $scanAgain) { $scanAgain = "" }

                        if ($scanAgain.Trim() -match "^[Yy]([Ee][Ss])?$") {
                            $runScan = $true
                        } else {
                            $runScan = $false
                        }
                    } catch {
                        $scanFailedContent = @(
                            "The scan did not complete:",
                            "",
                            "$($_.Exception.Message)",
                            "",
                            "Returning to the main menu."
                        )

                        Show-InfoBox -Title "SCAN FAILED" -Content $scanFailedContent -BorderColor Red -TitleColor Yellow
                        Start-Sleep -Seconds 2
                        $runScan = $false
                    }
                }

                break
            }
            "^[Cc]$" {
                Clear-Host

                $customContent = @(
                    "Enter the start and end IP addresses for your custom scan range.",
                    "Current range: $($scanOptions.StartIP) to $($scanOptions.EndIP)",
                    "Leave a field blank to keep its current value.",
                    "Addresses must be dotted-quad IPv4, e.g. 192.168.1.1",
                    ""
                )

                Show-InfoBox -Title "CUSTOM IP RANGE CONFIGURATION" -Content $customContent -BorderColor Magenta -TitleColor Yellow

                $newStart = Read-Host "Enter start IP [Current: $($scanOptions.StartIP)]"
                if ($null -eq $newStart) { $newStart = "" }
                $newStart = $newStart.Trim()

                if ($newStart.Length -gt 0) {
                    if (Test-IPv4Address $newStart) {
                        $scanOptions.StartIP = $newStart
                    } else {
                        Write-Host "Not a valid IPv4 address. Keeping current value ($($scanOptions.StartIP))" -ForegroundColor Red
                        Start-Sleep -Seconds 1
                    }
                }

                $newEnd = Read-Host "Enter end IP [Current: $($scanOptions.EndIP)]"
                if ($null -eq $newEnd) { $newEnd = "" }
                $newEnd = $newEnd.Trim()

                if ($newEnd.Length -gt 0) {
                    if (Test-IPv4Address $newEnd) {
                        $scanOptions.EndIP = $newEnd
                    } else {
                        Write-Host "Not a valid IPv4 address. Keeping current value ($($scanOptions.EndIP))" -ForegroundColor Red
                        Start-Sleep -Seconds 1
                    }
                }

                break
            }
            "^[Nn]$" {
                $scanOptions.StartIP = $netFirstIP
                $scanOptions.EndIP   = $netLastIP
                Write-Host "IP range reset to network range ($netFirstIP to $netLastIP)" -ForegroundColor Green
                Start-Sleep -Seconds 1
                break
            }
            "^[Tt]$" {
                Clear-Host

                $advancedContent = @(
                    "Configure advanced scan settings",
                    "",
                    "Timeout           : Higher values may find more hosts but scan slower",
                    "Threads           : Higher values scan faster but use more resources",
                    "Resolve Hostnames : Names every host via DNS - useful, but costs time",
                    "TCP Fallback      : Finds Windows hosts that silently drop ping",
                    ""
                )

                Show-InfoBox -Title "ADVANCED CONFIGURATION" -Content $advancedContent -BorderColor Blue -TitleColor Cyan

                $timeout = Read-Host "Enter timeout in milliseconds (100-5000) [Current: $($scanOptions.Timeout)]"
                if ($null -eq $timeout) { $timeout = "" }
                $timeout = $timeout.Trim()

                $parsedTimeout = 0
                if ([int]::TryParse($timeout, [ref]$parsedTimeout) -and $parsedTimeout -ge 100 -and $parsedTimeout -le 5000) {
                    $scanOptions.Timeout = $parsedTimeout
                } else {
                    Write-Host "Invalid input. Keeping current value ($($scanOptions.Timeout) ms)" -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }

                $threads = Read-Host "Enter thread count (1-100) [Current: $($scanOptions.ThreadCount)]"
                if ($null -eq $threads) { $threads = "" }
                $threads = $threads.Trim()

                $parsedThreads = 0
                if ([int]::TryParse($threads, [ref]$parsedThreads) -and $parsedThreads -ge 1 -and $parsedThreads -le 100) {
                    $scanOptions.ThreadCount = $parsedThreads
                } else {
                    Write-Host "Invalid input. Keeping current value ($($scanOptions.ThreadCount))" -ForegroundColor Red
                    Start-Sleep -Seconds 1
                }

                $currentResolve = "Disabled"
                if ($scanOptions.ResolveHostnames) { $currentResolve = "Enabled" }

                $resolveAnswer = Read-Host "Resolve hostnames? (Y/N) [Current: $currentResolve]"
                if ($null -eq $resolveAnswer) { $resolveAnswer = "" }

                switch -Regex ($resolveAnswer.Trim()) {
                    "^[Yy]([Ee][Ss])?$" { $scanOptions.ResolveHostnames = $true;  break }
                    "^[Nn][Oo]?$"       { $scanOptions.ResolveHostnames = $false; break }
                    default             { Write-Host "Keeping current value ($currentResolve)" -ForegroundColor DarkGray }
                }

                $currentTcp = "Disabled"
                if ($scanOptions.TcpFallback) { $currentTcp = "Enabled" }

                $tcpAnswer = Read-Host "Use TCP fallback? (Y/N) [Current: $currentTcp]"
                if ($null -eq $tcpAnswer) { $tcpAnswer = "" }

                switch -Regex ($tcpAnswer.Trim()) {
                    "^[Yy]([Ee][Ss])?$" { $scanOptions.TcpFallback = $true;  break }
                    "^[Nn][Oo]?$"       { $scanOptions.TcpFallback = $false; break }
                    default             { Write-Host "Keeping current value ($currentTcp)" -ForegroundColor DarkGray }
                }

                break
            }
            "^[Rr]$" {
                Clear-Host

                if ($null -eq $lastScanTime) {
                    $emptyContent = @(
                        "No scan has been run yet in this session.",
                        "",
                        "Press S at the main menu to run a scan first."
                    )

                    Show-InfoBox -Title "NO STORED RESULTS" -Content $emptyContent -BorderColor Yellow -TitleColor Red
                } elseif ($lastScanResults.Count -eq 0) {
                    $noHostContent = @(
                        "Range     : $lastScanRange",
                        "Completed : $($lastScanTime.ToString('yyyy-MM-dd HH:mm:ss'))",
                        "",
                        "That scan found no responding hosts.",
                        "Try a longer timeout, or enable TCP fallback under T."
                    )

                    Show-InfoBox -Title "LAST SCAN RESULTS" -Content $noHostContent -BorderColor Yellow -TitleColor Red
                } else {
                    $replayContent = @(
                        "Range     : $lastScanRange",
                        "Completed : $($lastScanTime.ToString('yyyy-MM-dd HH:mm:ss'))",
                        "Hosts     : $($lastScanResults.Count)"
                    )

                    Show-InfoBox -Title "LAST SCAN RESULTS" -Content $replayContent -BorderColor Green -TitleColor Yellow

                    # Render through Out-String rather than straight to the host:
                    # Format-Table produces nothing at all when the host cannot
                    # report a console width (redirected output, some terminals).
                    $tableWidth = 200
                    try {
                        if ($null -ne $Host.UI -and $null -ne $Host.UI.RawUI -and $Host.UI.RawUI.BufferSize.Width -gt 40) {
                            $tableWidth = $Host.UI.RawUI.BufferSize.Width - 1
                        }
                    } catch {
                        $tableWidth = 200
                    }

                    # Column order mirrors the live table drawn by Start-NetworkScan.
                    # Status is omitted: every returned host is an active one.
                    $resultsTable = $lastScanResults |
                        Format-Table -Property IPAddress, Hostname, DeviceType, ResponseTime, MAC, DiscoveryMethod -AutoSize |
                        Out-String -Width $tableWidth

                    Write-Host $resultsTable
                }

                Write-Host ""
                # Wait-ForAnyKey prints the prompt itself in both host paths, so we
                # do not pre-print it (that used to double up in fallback hosts).
                Wait-ForAnyKey -Message "Press any key to return to the main menu"
                break
            }
            "^[Hh]$" {
                Clear-Host

                $aboutContent = @(
                    "PowerSweep Lite v1.2",
                    "A simple PowerShell network discovery tool",
                    "",
                    "Author: Ulises Paiz",
                    "License: MIT License",
                    "",
                    "This tool scans your network to discover active hosts",
                    "and provides basic information about them.",
                    "",
                    "USAGE:",
                    "- S starts a scan with the settings shown on the main menu",
                    "- C sets a custom IP range, N restores the detected range",
                    "- T tunes timeout, threads, hostname resolution and TCP fallback",
                    "- R redisplays the last results without rescanning",
                    "- Q returns to your shell",
                    "",
                    "NOTES:",
                    "- Hostname resolution is accurate but adds time to every host",
                    "- TCP fallback finds Windows hosts that block ICMP echo",
                    "- MAC addresses need an elevated session to be reliable",
                    "- Lite has no CSV/JSON export by design; results stay on screen",
                    '  and in $Global:PowerSweepLastScan for the current session'
                )

                Show-InfoBox -Title "ABOUT POWERSWEEP LITE" -Content $aboutContent -BorderColor Cyan -TitleColor Magenta -Center

                Wait-ForAnyKey -Message "Press any key to return to the main menu"
                break
            }
            "^[Qq]$" {
                $menuActive = $false
                break
            }
            default {
                Write-Host "Invalid choice '$choice'. Valid keys are S, C, N, T, R, H and Q." -ForegroundColor Red
                Start-Sleep -Seconds 1
            }
        }
    }
}

# ---------------------------------------------------------------------------
# Main script execution
# ---------------------------------------------------------------------------

# --- Console preparation ---------------------------------------------------
# Everything here is best-effort. Hosts without a real console (redirected
# output, ISE, non-interactive runspaces) are detected up front and skipped
# rather than relying on an exception being thrown and swallowed.

$hasRealConsole = $false

try {
    if ($Host.Name -eq "ConsoleHost" -and [Environment]::UserInteractive) {
        if ($null -ne $Host.UI -and $null -ne $Host.UI.RawUI) {
            # These throw in hosts that only pretend to have a console.
            $null = $Host.UI.RawUI.BufferSize
            $null = $Host.UI.RawUI.WindowSize
            $hasRealConsole = $true
        }
    }
} catch {
    $hasRealConsole = $false
}

if ($hasRealConsole) {
    try {
        if ([Console]::IsOutputRedirected) { $hasRealConsole = $false }
    } catch {
        # [Console]::IsOutputRedirected is unavailable on some runtimes; ignore.
    }
}

if ($hasRealConsole) {
    try {
        $Host.UI.RawUI.WindowTitle = "PowerSweep Lite v1.2"
    } catch {
        # Some terminals refuse title changes. Not worth reporting.
    }

    try {
        $rawUI = $Host.UI.RawUI

        $desiredWidth  = 100
        $desiredHeight = 30

        # Never ask for a window bigger than the screen can physically show.
        $maxWindow = $rawUI.MaxPhysicalWindowSize
        if ($null -ne $maxWindow) {
            if ($maxWindow.Width  -gt 0 -and $desiredWidth  -gt $maxWindow.Width)  { $desiredWidth  = $maxWindow.Width }
            if ($maxWindow.Height -gt 0 -and $desiredHeight -gt $maxWindow.Height) { $desiredHeight = $maxWindow.Height }
        }

        $currentWindow = $rawUI.WindowSize
        $currentBuffer = $rawUI.BufferSize

        if ($currentWindow.Width -lt $desiredWidth -or $currentWindow.Height -lt $desiredHeight) {
            # 1. Grow the buffer FIRST - a window may never exceed its buffer.
            #    Only ever grow it; shrinking the buffer below the window throws
            #    and would also discard scrollback.
            $targetBufferWidth  = [Math]::Max($currentBuffer.Width,  $desiredWidth)
            $targetBufferHeight = [Math]::Max($currentBuffer.Height, $desiredHeight)

            if ($targetBufferWidth -ne $currentBuffer.Width -or $targetBufferHeight -ne $currentBuffer.Height) {
                $rawUI.BufferSize = New-Object System.Management.Automation.Host.Size($targetBufferWidth, $targetBufferHeight)
            }

            # 2. Now grow the window, clamped to the buffer we just guaranteed.
            $newBuffer = $rawUI.BufferSize
            $targetWindowWidth  = [Math]::Min([Math]::Max($currentWindow.Width,  $desiredWidth),  $newBuffer.Width)
            $targetWindowHeight = [Math]::Min([Math]::Max($currentWindow.Height, $desiredHeight), $newBuffer.Height)

            if ($targetWindowWidth -ne $currentWindow.Width -or $targetWindowHeight -ne $currentWindow.Height) {
                $rawUI.WindowSize = New-Object System.Management.Automation.Host.Size($targetWindowWidth, $targetWindowHeight)
            }
        }
    } catch {
        Write-Host "Window size could not be adjusted automatically. For the best experience, please maximize your terminal window." -ForegroundColor Yellow
    }
}

Clear-Host
Show-Banner

# --- Privilege check -------------------------------------------------------
# This is the ONE admin check in the whole script. There is deliberately no
# '#requires -RunAsAdministrator': that directive is ignored entirely when the
# script is piped through Invoke-Expression (the documented install path), and
# when it IS honoured it hard-fails before this friendly prompt can run.

# WindowsIdentity/WindowsPrincipal can throw under ConstrainedLanguage / WDAC /
# AppLocker (real locked-down enterprise deployments). Treat any failure as
# "not admin" and fall through to the same friendly warning.
$isAdmin = $false
try {
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} catch {
    $isAdmin = $false
}

if (-not $isAdmin) {
    $adminWarning = @(
        "PowerSweep Lite is not running with administrator privileges.",
        "",
        "MAC address detection relies on the ARP cache and may be incomplete.",
        "Host discovery itself will still work normally.",
        "",
        "Restart your shell as administrator for full functionality."
    )

    Show-InfoBox -Title "WARNING" -Content $adminWarning -BorderColor Red -TitleColor Yellow

    $continue = Read-Host "Continue anyway? (Y/N)"
    if ($null -eq $continue) { $continue = "" }

    if ($continue.Trim() -notmatch "^[Yy]([Ee][Ss])?$") {
        Write-Host ""
        Write-Host "Cancelled. Relaunch PowerShell as administrator for full functionality." -ForegroundColor Yellow
        # 'return' unwinds the script only. 'exit' would kill the caller's shell
        # when this script is dot-sourced or run via 'irm ... | iex'.
        return
    }
}

# --- Network discovery -----------------------------------------------------
# Get-LocalNetworkInfo prints its own error box and returns $null when no
# usable adapter exists. Stop cleanly instead of handing $null to Show-Menu.

$Global:NetworkInfo = Get-LocalNetworkInfo

# Test the TYPE, not just $null: Show-Menu's parameter is Mandatory [hashtable],
# so an unexpected array or PSCustomObject from Get-LocalNetworkInfo would pass a
# null check and then throw a binding error at the Show-Menu call - unwinding the
# script past the farewell and vanishing the window.
if ($Global:NetworkInfo -isnot [hashtable]) {
    $noNetworkContent = @(
        "PowerSweep Lite could not determine a network range to scan.",
        "",
        "Things to check:",
        "  - Is an Ethernet or Wi-Fi adapter connected and 'Up'?",
        "  - Does the adapter have an IPv4 address and a default gateway?",
        "  - VPN and virtual adapters are skipped on purpose.",
        "",
        "You can also run Get-NetIPConfiguration to inspect your adapters."
    )

    Show-InfoBox -Title "CANNOT CONTINUE" -Content $noNetworkContent -BorderColor Red -TitleColor Yellow

    Write-Host ""
    Write-Host "Exiting without scanning." -ForegroundColor Yellow
    return
}

# --- Interactive menu ------------------------------------------------------
# try/finally guarantees the farewell box and the key-wait run even if Show-Menu
# throws - so a double-clicked or 'irm | iex' window never closes instantly on a
# red error the user cannot read. An error is surfaced in a box first.
try {
    Show-Menu -NetworkInfo $Global:NetworkInfo
} catch {
    $menuErrorContent = @(
        "PowerSweep Lite hit an unexpected error and had to stop:",
        "",
        "$($_.Exception.Message)",
        "",
        "Please report this if it keeps happening."
    )

    Show-InfoBox -Title "UNEXPECTED ERROR" -Content $menuErrorContent -BorderColor Red -TitleColor Yellow
} finally {
    # --- Farewell ----------------------------------------------------------
    $farewellContent = @(
        "",
        "Thank you for using PowerSweep Lite!",
        ""
    )

    Show-InfoBox -Title "GOODBYE" -Content $farewellContent -BorderColor Cyan -TitleColor Magenta -Center

    Wait-ForAnyKey -Message "Press any key to exit"
}

