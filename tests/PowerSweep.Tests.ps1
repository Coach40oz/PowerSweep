BeforeAll {
    # Dot-source the main script to load functions, but skip execution
    # We extract just the function definitions by parsing the script
    $scriptPath = Join-Path $PSScriptRoot '..' 'powersweep.ps1'
    $scriptContent = Get-Content -Path $scriptPath -Raw

    # Extract function definitions using AST parsing
    $tokens = $null
    $errors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($scriptContent, [ref]$tokens, [ref]$errors)

    # Find all function definitions and evaluate them in current scope
    $functionDefs = $ast.FindAll({ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $false)
    foreach ($func in $functionDefs) {
        try {
            Invoke-Expression $func.Extent.Text
        } catch {
            # Some functions may fail to load due to dependencies; skip those
        }
    }
}

Describe "Get-DeviceType" {
    Context "Gateway detection" {
        It "identifies the gateway IP as Router/Gateway" {
            $result = Get-DeviceType -ip "192.168.1.1" -openPorts @() -hostname "" -gw "192.168.1.1"
            $result | Should -Be "Router/Gateway"
        }
    }

    Context "Port-based detection" {
        It "identifies Windows by port signature" {
            $result = Get-DeviceType -ip "192.168.1.10" -openPorts @(135, 139, 445) -hostname "" -gw "192.168.1.1"
            $result | Should -Match "Windows"
        }

        It "identifies web server by ports 80 and 443 with 8080" {
            $result = Get-DeviceType -ip "192.168.1.20" -openPorts @(80, 443, 8080) -hostname "" -gw "192.168.1.1"
            $result | Should -Match "Web"
        }

        It "identifies database server by SQL port" {
            $result = Get-DeviceType -ip "192.168.1.30" -openPorts @(1433, 445) -hostname "" -gw "192.168.1.1"
            $result | Should -Match "Database|Windows"
        }

        It "identifies print server by port 9100" {
            $result = Get-DeviceType -ip "192.168.1.40" -openPorts @(515, 631, 9100) -hostname "" -gw "192.168.1.1"
            $result | Should -Match "Print"
        }

        It "returns Unknown for no open ports and no hostname" {
            $result = Get-DeviceType -ip "192.168.1.50" -openPorts @() -hostname "" -gw "192.168.1.1"
            $result | Should -Be "Unknown"
        }
    }

    Context "Hostname-based detection" {
        It "identifies a router by hostname" {
            $result = Get-DeviceType -ip "192.168.1.2" -openPorts @() -hostname "ubnt-router-01" -gw "192.168.1.1"
            $result | Should -Match "Network"
        }

        It "identifies a printer by hostname" {
            $result = Get-DeviceType -ip "192.168.1.3" -openPorts @() -hostname "HP-Printer-Office" -gw "192.168.1.1"
            $result | Should -Match "Printer"
        }

        It "identifies a camera by hostname" {
            $result = Get-DeviceType -ip "192.168.1.4" -openPorts @() -hostname "hikvision-cam-01" -gw "192.168.1.1"
            $result | Should -Match "Camera"
        }

        It "identifies a server by hostname" {
            $result = Get-DeviceType -ip "192.168.1.5" -openPorts @() -hostname "win-server-dc01" -gw "192.168.1.1"
            $result | Should -Match "Server|Windows"
        }

        It "identifies IoT device by hostname" {
            $result = Get-DeviceType -ip "192.168.1.6" -openPorts @() -hostname "nest-thermostat" -gw "192.168.1.1"
            $result | Should -Match "IoT"
        }

        It "identifies mobile device by hostname" {
            $result = Get-DeviceType -ip "192.168.1.7" -openPorts @() -hostname "Johns-iPhone" -gw "192.168.1.1"
            $result | Should -Match "Mobile"
        }

        It "identifies media device by hostname" {
            $result = Get-DeviceType -ip "192.168.1.8" -openPorts @() -hostname "roku-livingroom" -gw "192.168.1.1"
            $result | Should -Match "Media"
        }
    }

    Context "Combined port and hostname detection" {
        It "combines OS and role when both are detected" {
            $result = Get-DeviceType -ip "192.168.1.10" -openPorts @(135, 139, 445, 1433) -hostname "sql-server-01" -gw "192.168.1.1"
            $result | Should -Match "Server|Windows"
        }
    }
}

Describe "Scan-Vulnerabilities" {
    Context "Vulnerability detection" {
        It "detects Telnet as high severity" {
            $testResults = @(
                [PSCustomObject]@{
                    IPAddress  = "192.168.1.10"
                    Hostname   = "test-host"
                    DeviceType = "Unknown"
                    OpenPorts  = "23 (Telnet)"
                    Shares     = ""
                }
            )

            $vulns = Scan-Vulnerabilities -Results $testResults
            $vulns.Count | Should -BeGreaterThan 0
            $vulns[0].Vulnerabilities | Where-Object { $_.Severity -eq "High" -and $_.Type -eq "Insecure Protocol" } | Should -Not -BeNullOrEmpty
        }

        It "detects FTP as medium severity" {
            $testResults = @(
                [PSCustomObject]@{
                    IPAddress  = "192.168.1.10"
                    Hostname   = "test-host"
                    DeviceType = "Unknown"
                    OpenPorts  = "21 (FTP Control)"
                    Shares     = ""
                }
            )

            $vulns = Scan-Vulnerabilities -Results $testResults
            $vulns.Count | Should -BeGreaterThan 0
            $vulns[0].Vulnerabilities | Where-Object { $_.Severity -eq "Medium" -and $_.Description -match "FTP" } | Should -Not -BeNullOrEmpty
        }

        It "detects exposed RDP" {
            $testResults = @(
                [PSCustomObject]@{
                    IPAddress  = "192.168.1.10"
                    Hostname   = "test-host"
                    DeviceType = "Windows"
                    OpenPorts  = "3389 (RDP)"
                    Shares     = ""
                }
            )

            $vulns = Scan-Vulnerabilities -Results $testResults
            $vulns[0].Vulnerabilities | Where-Object { $_.Type -eq "Remote Access" } | Should -Not -BeNullOrEmpty
        }

        It "detects exposed databases" {
            $testResults = @(
                [PSCustomObject]@{
                    IPAddress  = "192.168.1.10"
                    Hostname   = "db-server"
                    DeviceType = "Server"
                    OpenPorts  = "3306 (MySQL)"
                    Shares     = ""
                }
            )

            $vulns = Scan-Vulnerabilities -Results $testResults
            $vulns[0].Vulnerabilities | Where-Object { $_.Type -eq "Database Exposure" } | Should -Not -BeNullOrEmpty
        }

        It "detects open network shares" {
            $testResults = @(
                [PSCustomObject]@{
                    IPAddress  = "192.168.1.10"
                    Hostname   = "file-server"
                    DeviceType = "FileServer"
                    OpenPorts  = "445 (SMB)"
                    Shares     = "Public, Documents"
                }
            )

            $vulns = Scan-Vulnerabilities -Results $testResults
            $vulns[0].Vulnerabilities | Where-Object { $_.Type -eq "Excessive Exposure" } | Should -Not -BeNullOrEmpty
        }

        It "returns empty for a clean host" {
            $testResults = @(
                [PSCustomObject]@{
                    IPAddress  = "192.168.1.10"
                    Hostname   = "clean-host"
                    DeviceType = "Unknown"
                    OpenPorts  = "443 (HTTPS)"
                    Shares     = ""
                }
            )

            $vulns = Scan-Vulnerabilities -Results $testResults
            $vulns.Count | Should -Be 0
        }

        It "detects multiple high-risk ports" {
            $testResults = @(
                [PSCustomObject]@{
                    IPAddress  = "192.168.1.10"
                    Hostname   = "risky-host"
                    DeviceType = "Unknown"
                    OpenPorts  = "21 (FTP Control), 23 (Telnet), 3389 (RDP), 5900 (VNC)"
                    Shares     = ""
                }
            )

            $vulns = Scan-Vulnerabilities -Results $testResults
            $multiExposure = $vulns[0].Vulnerabilities | Where-Object { $_.Type -eq "Multiple Exposures" }
            $multiExposure | Should -Not -BeNullOrEmpty
        }
    }
}

Describe "Export-JsonReport" {
    Context "JSON generation" {
        It "creates a valid JSON file" {
            $testResults = @(
                [PSCustomObject]@{
                    IPAddress    = "192.168.1.1"
                    Hostname     = "router"
                    MAC          = "AA:BB:CC:DD:EE:FF"
                    Status       = "Online"
                    ResponseTime = "1 ms"
                    DeviceType   = "Router/Gateway"
                    OpenPorts    = "80 (HTTP), 443 (HTTPS)"
                    Shares       = ""
                }
            )

            $tempFile = Join-Path $TestDrive "test_report.json"
            Export-JsonReport -Results $testResults -ExportPath $tempFile

            Test-Path $tempFile | Should -BeTrue
            $content = Get-Content $tempFile -Raw | ConvertFrom-Json
            $content.metadata.tool | Should -Be "PowerSweep"
            $content.hosts.Count | Should -Be 1
            $content.hosts[0].ipAddress | Should -Be "192.168.1.1"
        }

        It "includes vulnerability data" {
            $testResults = @(
                [PSCustomObject]@{
                    IPAddress    = "192.168.1.10"
                    Hostname     = "test"
                    MAC          = "Unknown"
                    Status       = "Online"
                    ResponseTime = "5 ms"
                    DeviceType   = "Unknown"
                    OpenPorts    = "23 (Telnet)"
                    Shares       = ""
                }
            )
            $testVulns = @(
                [PSCustomObject]@{
                    IPAddress       = "192.168.1.10"
                    Hostname        = "test"
                    DeviceType      = "Unknown"
                    Vulnerabilities = @(
                        [PSCustomObject]@{
                            Severity       = "High"
                            Type           = "Insecure Protocol"
                            Description    = "Telnet detected"
                            Recommendation = "Use SSH"
                            References     = "CIS"
                        }
                    )
                }
            )

            $tempFile = Join-Path $TestDrive "test_vuln_report.json"
            Export-JsonReport -Results $testResults -Vulnerabilities $testVulns -ExportPath $tempFile

            $content = Get-Content $tempFile -Raw | ConvertFrom-Json
            $content.vulnerabilities.Count | Should -Be 1
            $content.vulnerabilities[0].vulnerabilities[0].severity | Should -Be "High"
        }
    }
}

Describe "Script Parameter Validation" {
    It "has a param block with expected parameters" {
        $scriptPath = Join-Path $PSScriptRoot '..' 'powersweep.ps1'
        $scriptContent = Get-Content -Path $scriptPath -Raw
        $scriptContent | Should -Match 'param\s*\('
        $scriptContent | Should -Match '\[string\]\$Target'
        $scriptContent | Should -Match '\[string\]\$OutputCsv'
        $scriptContent | Should -Match '\[string\]\$OutputHtml'
        $scriptContent | Should -Match '\[string\]\$OutputJson'
        $scriptContent | Should -Match '\[switch\]\$NonInteractive'
    }
}
