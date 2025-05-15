
<#
.SYNOPSIS
    Absolute Agent Diagnostic Collector - Enhanced Edition

.DESCRIPTION
    Comprehensive tool for collecting system, network, service, registry, and log diagnostics
    for Absolute Agent troubleshooting. Features:
    - Detailed system information gathering
    - Service status analysis with startup configuration
    - Network connectivity connectivith detailed diagnostics
    - Registry analysis for Absolute Agent components
    - Event log collection for relevant events
    - Enhanced HTML and Excel reporting with visual indicators
    - Customizable output options
    - Performance optimized execution

.PARAMETER CallTimeoutSec
    Timeout in seconds for AbtPS call operations (defaul)

.PARAMETER NetworkTimeoutSec
    Timeout in seconds for network o(default: 30)

.PARAMETER SkipExcel
    Skip generation of Excel report

.PARAMETER SkipZip
    Skip compressing the output folder

.PARAMETER SkipRegistry
    Skip registry checks

.PARAMETER SkipEventLogs
    Skip collecting Windows event logs

.PARAMETER MaxParallelJobs
    Maximum number of parallel jobs for network testing (default: 5)

.PARAMETER ForceTLS12
    Force the use of TLS 1.2 for all web requests

.PARAMETER VerboseLog
    Enable verbose logging

.PARAMETER EndpointsToCheck
    Array of endpoints to check for connectivity.
    Default includes essential Absolute Agent endpoints.

.PARAMETER ExpectedStatusCodes
    Hashtable of expected HTTP status codes for each endpoint.

.PARAMETER OutputDirectory
    Directory where diagnostic output will be saved. Default is script directory.

.PARAMETER IncludeFullHardwareInfo
    Include detailed hardware inventory in the report

.PARAMETER ShowTrace
    Show full request/response tracing for network diagnostics

.EXAMPLE
    .\CheckNdtRpcnetV3.ps1 -VerboseLog
    Run diagnostics with verbose logging.

.EXAMPLE
    .\CheckNdtRpcnetV3.ps1 -OutputDirectory "C:\Temp\Diag"
    Run diagnostics and save output to the specified directory.

.EXAMPLE
    .\CheckNdtRpcnetV3.ps1 -SkipExcel -SkipRegistry -NetworkTimeoutSec 15
    Run diagnostics skipping Excel report and registry checks with shorter network timeouts.

.EXAMPLE
    .\CheckNdtRpcnetV3.ps1 -IncludeFullHardwareInfo -MaxParallelJobs 10
    Run diagnostics with full hardware inventory and increased parallel network testing.

.NOTES
    Version: 3.0
    Author: Updated with best practices
    Last Updated: 2025-14-05
    Requires: PowerShell 5.1 or higher
    Optional modules: ImportExcel (for Excel reports)
#>

[CmdletBinding(SupportsShouldProcess = $true, DefaultParameterSetName = 'Default')]
param(
    [Parameter(ParameterSetName = 'Default')]
    [ValidateRange(10, 300)]
    [int]$CallTimeoutSec = 60,

    [Parameter(ParameterSetName = 'Default')]
    [ValidateRange(5, 120)]
    [int]$NetworkTimeoutSec = 30,

    [Parameter(ParameterSetName = 'Default')]
    [switch]$SkipExcel,

    [Parameter(ParameterSetName = 'Default')]
    [switch]$SkipZip,

    [Parameter(ParameterSetName = 'Default')]
    [switch]$SkipRegistry,

    [Parameter(ParameterSetName = 'Default')]
    [switch]$SkipEventLogs,

    [Parameter(ParameterSetName = 'Default')]
    [ValidateRange(1, 20)]
    [int]$MaxParallelJobs = 5,

    [Parameter(ParameterSetName = 'Default')]
    [switch]$ForceTLS12,

    [Parameter(ParameterSetName = 'Default')]
    [switch]$VerboseLog,

    [Parameter(ParameterSetName = 'Default')]
    [switch]$IncludeFullHardwareInfo,

    [Parameter(ParameterSetName = 'Default')]
    [switch]$ShowTrace,

    [Parameter(ParameterSetName = 'Default')]
    [ValidateNotNullOrEmpty()]
    [string[]]$EndpointsToCheck = @(
        "http://search.namequery.com",
        "https://search.namequery.com/ctes/1.0.0/configuration",
        "https://search.namequery.com/downloads/public/bin/Windows/CTES/CTES/1.0.0.3316/filelist.txt",
        "https://deviceapi.ca1.absolute.com/ctes/1.0.0/configuration",
        "https://resources.namequery.com/downloads/public/bin/Windows/CTES/HDC/2.0.15.13/CtHWiPrvPackage.zip"
    ),

    [Parameter(ParameterSetName = 'Default')]
    [ValidateNotNull()]
    [hashtable]$ExpectedStatusCodes = @{
        "http://search.namequery.com" = "301 or 200";
        "https://search.namequery.com/ctes/1.0.0/configuration" = "401";
        "https://search.namequery.com/downloads/public/bin/Windows/CTES/CTES/1.0.0.3316/filelist.txt" = "200";
        "https://deviceapi.ca1.absolute.com/ctes/1.0.0/configuration" = "401";
        "https://resources.namequery.com/downloads/public/bin/Windows/CTES/HDC/2.0.15.13/CtHWiPrvPackage.zip" = "200";
    },

    [Parameter(ParameterSetName = 'Default')]
    [ValidateScript({
        if (!(Test-Path -Path $_ -IsValid)) {
            throw "Path '$_' is not valid"
        } elseif (!(Test-Path -Path $_ -PathType Container) -and ($_ -ne $PSScriptRoot)) {
            throw "Path '$_' is not a directory or doesn't exist"
        } else {
            $true
        }
    })]
    [string]$OutputDirectory = $PSScriptRoot
)

begin {
    # Initialize script
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'
    $InformationPreference = if ($VerboseLog) { 'Continue' } else { 'SilentlyContinue' }
    $ProgressPreference = if ($VerboseLog) { 'Continue' } else { 'SilentlyContinue' }

    # Initialize script-wide variables
    $script:startTime = Get-Date
    $script:DiagWarnings = [System.Collections.Generic.List[string]]::new()
    $script:DiagErrors = [System.Collections.Generic.List[string]]::new()
    $script:ScriptVersion = '3.0'
    $script:stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

    # Force TLS 1.2 if requested
    if ($ForceTLS12) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Information "TLS 1.2 forced for all connections"
    }

    # Create output location with timestamp
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $script:diagFolder = Join-Path -Path $OutputDirectory -ChildPath "AbsoluteDiagnostics_$timestamp"
    $null = New-Item -Path $script:diagFolder -ItemType Directory -Force

    # Start transcript logging
    $transcriptPath = Join-Path -Path $script:diagFolder -ChildPath "diagnostics_$timestamp.log"
    Start-Transcript -Path $transcriptPath -Force

    # Write startup information
    $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
    $psVersion = $PSVersionTable.PSVersion

    Write-Host "=======================================================" -ForegroundColor Cyan
    Write-Host " Absolute Agent Diagnostic Collector v$script:ScriptVersion" -ForegroundColor Cyan
    Write-Host " Starting diagnostics at: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
    Write-Host " PowerShell Version: $psVersion" -ForegroundColor Cyan
    Write-Host " OS: $($osInfo.Caption) $($osInfo.Version)" -ForegroundColor Cyan
    Write-Host " Computer: $env:COMPUTERNAME" -ForegroundColor Cyan
    Write-Host " Output Directory: $script:diagFolder" -ForegroundColor Cyan
    Write-Host "=======================================================" -ForegroundColor Cyan

    #region Helper Functions

    function Write-DiagLog {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true, Position = 0)]
            [string]$Message,

            [Parameter(Position = 1)]
            [ValidateSet('Info', 'Warning', 'Error', 'Success', 'Debug')]
            [string]$Level = 'Info',

            [switch]$NoConsole
        )

        $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $colorMap = @{
            'Info'    = 'White'
            'Warning' = 'Yellow'
            'Error'   = 'Red'
            'Success' = 'Green'
            'Debug'   = 'Gray'
        }

        $color = $colorMap[$Level]
        $logMessage = "[$timestamp] [$Level] $Message"

        # Track warnings and errors
        switch ($Level) {
            'Warning' { $script:DiagWarnings.Add($Message) }
            'Error'   { $script:DiagErrors.Add($Message) }
        }

        # Output to console when needed
        if (-not $NoConsole) {
            Write-Host $logMessage -ForegroundColor $color
        }

        # Always write to verbose stream when verbose logging is enabled
        if ($VerboseLog) {
            Write-Verbose $logMessage
        }

        # Return for capturing output if needed
        return $logMessage
    }

    function Show-DiagProgress {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$Stage,

            [Parameter(Mandatory = $true)]
            [int]$Index,

            [Parameter()]
            [int]$Total = 12,

            [Parameter()]
            [int]$ParentId = -1
        )

        $percent = [math]::Round(($Index / $Total) * 100)
        $elapsedTime = $script:stopwatch.Elapsed.ToString("hh\:mm\:ss")
        $status = "$Stage (Step $Index of $Total)"

        if ($ParentId -ge 0) {
            Write-Progress -Activity "Diagnostics Running [$elapsedTime]" -Status $status -PercentComplete $percent -Id $ParentId
        }
        else {
            Write-Progress -Activity "Diagnostics Running [$elapsedTime]" -Status $status -PercentComplete $percent
        }

        Write-DiagLog -Message "[$percent%] $Stage" -Level 'Debug' -NoConsole
    }

    function Test-ModuleAvailable {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$ModuleName
        )

        $moduleAvailable = Get-Module -ListAvailable -Name $ModuleName

        if (-not $moduleAvailable) {
            try {
                Write-DiagLog -Message "Module '$ModuleName' not found. Attempting to install..." -Level 'Warning'
                Install-Module -Name $ModuleName -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
                Import-Module -Name $ModuleName -Force -ErrorAction Stop
                Write-DiagLog -Message "Successfully installed and imported module '$ModuleName'" -Level 'Success'
                return $true
            }
            catch {
                Write-DiagLog -Message "Failed to install module '$ModuleName': $_" -Level 'Error'
                return $false
            }
        }
        else {
            if ($VerboseLog) {
                Write-DiagLog -Message "Module '$ModuleName' is available" -Level 'Debug'
            }
            return $true
        }
    }

    function Wait-ForFileUnlock {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$FilePath,

            [Parameter()]
            [int]$TimeoutSec = 10,

            [Parameter()]
            [int]$RetryIntervalMs = 200
        )

        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $retryCount = 0

        while ($sw.Elapsed.TotalSeconds -lt $TimeoutSec) {
            $retryCount++
            try {
                $fs = [System.IO.File]::Open($FilePath, 'Open', 'Read', 'ReadWrite')
                $fs.Close()
                $fs.Dispose()

                if ($VerboseLog) {
                    Write-DiagLog -Message "File unlocked ($retryCount attempts, $($sw.Elapsed.TotalMilliseconds)ms): $FilePath" -Level 'Debug'
                }
                return $true
            }
            catch {
                Start-Sleep -Milliseconds $RetryIntervalMs
            }
        }

        Write-DiagLog -Message "Timeout after $retryCount attempts waiting for file to unlock: $FilePath" -Level 'Warning'
        return $false
    }

    function Export-HtmlReport {
        [CmdletBinding()]
        param (
            [Parameter(Mandatory = $true)]
            [string]$Path,

            [Parameter(Mandatory = $true)]
            [hashtable]$Summary,

            [Parameter()]
            [array]$EndpointResults,

            [Parameter()]
            [array]$ServiceResults,

            [Parameter()]
            [hashtable]$SystemInfo,

            [Parameter()]
            [array]$RegistryInfo = @(),

            [Parameter()]
            [array]$Warnings = @(),

            [Parameter()]
            [array]$Errors = @()
        )

        $css = @'
        <style>
            :root {
                --primary-color: #00447c;
                --secondary-color: #003366;
                --success-color: #28a745;
                --warning-color: #ffc107;
                --danger-color: #dc3545;
                --light-color: #f8f9fa;
                --dark-color: #343a40;
            }
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                margin: 0;
                padding: 20px;
                background-color: #f5f5f5;
            }
            .container {
                max-width: 1200px;
                margin: 0 auto;
                background-color: white;
                padding: 20px;
                box-shadow: 0 0 10px rgba(0,0,0,.1);
                border-radius: 5px;
            }
            h1, h2, h3, h4 {
                color: var(--primary-color);
                margin-top: 1.5rem;
                margin-bottom: 1rem;
            }
            h1 {
                border-bottom: 2px solid var(--primary-color);
                padding-bottom: 10px;
                margin-bottom: 20px;
            }
            .header {
                background-color: var(--primary-color);
                color: white;
                padding: 20px;
                margin: -20px -20px 20px -20px;
                border-radius: 5px 5px 0 0;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .header h1 {
                color: white;
                margin: 0;
                padding: 0;
                border: none;
            }
            table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
                box-shadow: 0 0 5px rgba(0,0,0,.05);
            }
            th {
                background-color: var(--secondary-color);
                color: white;
                text-align: left;
                padding: 10px;
                font-weight: bold;
            }
            td {
                padding: 8px 10px;
                border: 1px solid #ddd;
                vertical-align: top;
            }
            tr:nth-child(even) {
                background-color: rgba(0,0,0,.02);
            }
            tr:hover {
                background-color: rgba(0,0,0,.05);
            }
            .pass { background-color: rgba(40, 167, 69, 0.15); }
            .fail { background-color: rgba(220, 53, 69, 0.15); }
            .error { background-color: rgba(255, 193, 7, 0.15); }
            .warning { color: var(--danger-color); font-weight: bold; }
            .notfound { background-color: rgba(108, 117, 125, 0.15); }

            .dashboard {
                display: flex;
                flex-wrap: wrap;
                margin: 0 -10px;
                justify-content: space-around;
            }
            .summary-box {
                flex: 1 0 200px;
                margin: 10px;
                padding: 15px;
                background-color: white;
                border-radius: 5px;
                box-shadow: 0 0 5px rgba(0,0,0,.1);
                text-align: center;
                max-width: 250px;
            }
            .summary-box h3 {
                margin-top: 0;
                font-size: 16px;
                color: #666;
            }
            .summary-box .number {
                font-size: 32px;
                font-weight: bold;
                margin: 10px 0;
            }
            .pass-count { color: var(--success-color); }
            .fail-count { color: var(--danger-color); }
            .error-count { color: var(--warning-color); }

            .section {
                background-color: white;
                border-radius: 5px;
                padding: 15px;
                margin-bottom: 20px;
                box-shadow: 0 0 5px rgba(0,0,0,.05);
            }
            .footer {
                text-align: center;
                margin-top: 30px;
                padding: 10px;
                color: #666;
                font-size: 80%;
                border-top: 1px solid #ddd;
            }
            .timestamp {
                font-style: italic;
                color: #888;
            }
            .pills {
                display: flex;
                flex-wrap: wrap;
                gap: 8px;
                margin: 10px 0;
            }
            .pill {
                display: inline-block;
                padding: 5px 10px;
                border-radius: 20px;
                font-size: 14px;
                background-color: #e9ecef;
            }
            .collapsible {
                cursor: pointer;
                padding: 10px;
                width: 100%;
                border: none;
                text-align: left;
                outline: none;
                font-weight: bold;
                background-color: #f1f1f1;
                margin-bottom: 1px;
            }
            .active, .collapsible:hover {
                background-color: #ddd;
            }
            .content {
                padding: 0 18px;
                display: none;
                overflow: hidden;
                background-color: white;
            }
            pre {
                background-color: #f5f5f5;
                padding: 10px;
                border: 1px solid #ddd;
                border-radius: 3px;
                white-space: pre-wrap;
                font-size: 13px;
                font-family: Consolas, monospace;
            }
        </style>
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                var coll = document.getElementsByClassName("collapsible");
                for (var i = 0; i < coll.length; i++) {
                    coll[i].addEventListener("click", function() {
                        this.classList.toggle("active");
                        var content = this.nextElementSibling;
                        if (content.style.display === "block") {
                            content.style.display = "none";
                        } else {
                            content.style.display = "block";
                        }
                    });
                }
            });
        </script>
'@

        $html = [System.Collections.Generic.List[string]]::new()
        $html.Add('<!DOCTYPE html>')
        $html.Add('<html lang="en">')
        $html.Add('<head>')
        $html.Add('    <meta charset="UTF-8">')
        $html.Add('    <meta name="viewport" content="width=device-width, initial-scale=1.0">')
        $html.Add("    <title>Absolute Agent Diagnostics Report - $($env:COMPUTERNAME)</title>")
        $html.Add("    $css")
        $html.Add('</head>')
        $html.Add('<body>')
        $html.Add('<div class="container">')

        # Header with timestamp
        $dateString = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        $html.Add('<div class="header">')
        $html.Add('    <h1>Absolute Agent Diagnostics Report</h1>')
        $html.Add("    <span class='timestamp'>Generated: $dateString</span>")
        $html.Add('</div>')

        # Dashboard Summary
        $html.Add('<div class="section">')
        $html.Add('    <h2>Dashboard Summary</h2>')
        $html.Add('    <div class="dashboard">')
        $html.Add('        <div class="summary-box">')
        $html.Add('            <h3>Total Endpoints</h3>')
        $html.Add("            <div class='number'>$($Summary['Total Endpoints'])</div>")
        $html.Add('        </div>')
        $html.Add('        <div class="summary-box">')
        $html.Add('            <h3>Passed</h3>')
        $html.Add("            <div class='number pass-count'>$($Summary['Passed'])</div>")
        $html.Add('        </div>')
        $html.Add('        <div class="summary-box">')
        $html.Add('            <h3>Failed</h3>')
        $html.Add("            <div class='number fail-count'>$($Summary['Failed'])</div>")
        $html.Add('        </div>')
        $html.Add('        <div class="summary-box">')
        $html.Add('            <h3>Errors</h3>')
        $html.Add("            <div class='number error-count'>$($Summary['Errors'])</div>")
        $html.Add('        </div>')
        $html.Add('    </div>')
        $html.Add('</div>')

        # System Information
        $html.Add('<div class="section">')
        $html.Add('    <h2>System Information</h2>')
        $html.Add('    <button type="button" class="collapsible">Show System Details</button>')
        $html.Add('    <div class="content">')
        $html.Add('        <table>')
        $html.Add('            <tr><th>Item</th><th>Value</th></tr>')

        # Sort system info keys alphabetically
        $sortedSystemInfo = [ordered]@{}
        $SystemInfo.GetEnumerator() | Sort-Object -Property Key | ForEach-Object {
            $sortedSystemInfo[$_.Key] = $_.Value
        }

        foreach ($key in $sortedSystemInfo.Keys) {
            $value = $sortedSystemInfo[$key]
            # Format dates appropriately
            if ($value -is [DateTime]) {
                $value = $value.ToString("yyyy-MM-dd HH:mm:ss")
            }
            $html.Add("            <tr><td>$key</td><td>$value</td></tr>")
        }
        $html.Add('        </table>')
        $html.Add('    </div>')
        $html.Add('</div>')

        # Services
        $html.Add('<div class="section">')
        $html.Add('    <h2>Absolute Services</h2>')
        $html.Add('    <table>')
        $html.Add('        <tr><th>Service Name</th><th>Status</th><th>Startup Type</th><th>Description</th></tr>')

        foreach ($svc in $ServiceResults) {
            $statusClass = switch ($svc.Status) {
                "Running" { "pass" }
                "Stopped" { "fail" }
                "Not Found" { "notfound" }
                default { "" }
            }

            $html.Add("        <tr class='$statusClass'>")
            $html.Add("            <td>$($svc.Name)</td>")
            $html.Add("            <td>$($svc.Status)</td>")
            $html.Add("            <td>$($svc.StartupType)</td>")
            $html.Add("            <td>$($svc.Description)</td>")
            $html.Add("        </tr>")
        }

        $html.Add('    </table>')
        $html.Add('</div>')

        # Network Connectivity
        $html.Add('<div class="section">')
        $html.Add('    <h2>Network Connectivity</h2>')

        # Add summary pills for network
        $passCount = ($EndpointResults | Where-Object Status -eq 'Pass').Count
        $failCount = ($EndpointResults | Where-Object Status -eq 'Fail').Count
        $errorCount = ($EndpointResults | Where-Object Status -eq 'Error').Count

        $html.Add('    <div class="pills">')
        $html.Add("        <div class='pill'>Total: $($EndpointResults.Count)</div>")
        $html.Add("        <div class='pill' style='background-color: rgba(40, 167, 69, 0.2);'>Pass: $passCount</div>")
        $html.Add("        <div class='pill' style='background-color: rgba(220, 53, 69, 0.2);'>Fail: $failCount</div>")
        $html.Add("        <div class='pill' style='background-color: rgba(255, 193, 7, 0.2);'>Error: $errorCount</div>")
        $html.Add('    </div>')

        $html.Add('    <table>')
        $html.Add('        <tr>')
        $html.Add('            <th>URL</th>')
        $html.Add('            <th>Status</th>')
        $html.Add('            <th>Response</th>')
        $html.Add('            <th>Expected</th>')
        $html.Add('            <th>Ping</th>')
        $html.Add('            <th>Time (ms)</th>')
        $html.Add('        </tr>')

        foreach ($result in $EndpointResults) {
            $statusClass = switch ($result.Status) {
                'Pass' { "pass" }
                'Fail' { "fail" }
                'Error' { "error" }
                default { "" }
            }

            $html.Add("        <tr class='$statusClass'>")
            $html.Add("            <td>$($result.URL)</td>")
            $html.Add("            <td>$($result.Status)</td>")
            $html.Add("            <td>$($result.Code) $($result.Description)</td>")
            $html.Add("            <td>$($result.Expected)</td>")
            $html.Add("            <td>$($result.PingStatus)</td>")
            $html.Add("            <td>$($result.ResponseTime)</td>")
            $html.Add("        </tr>")
        }

        $html.Add('    </table>')
        $html.Add('</div>')

        # Registry Information (if available)
        if ($RegistryInfo -and $RegistryInfo.Count -gt 0) {
            $html.Add('<div class="section">')
            $html.Add('    <h2>Registry Information</h2>')
            $html.Add('    <button type="button" class="collapsible">Show Registry Details</button>')
            $html.Add('    <div class="content">')

            # Group by registry path
            $registryGroups = $RegistryInfo | Group-Object -Property Path

            foreach ($group in $registryGroups) {
                $html.Add("        <h3>$($group.Name)</h3>")
                $html.Add('        <table>')
                $html.Add('            <tr><th>Name</th><th>Value</th></tr>')

                foreach ($item in $group.Group) {
                    $html.Add("            <tr><td>$($item.Name)</td><td>$($item.Value)</td></tr>")
                }

                $html.Add('        </table>')
            }

            $html.Add('    </div>')
            $html.Add('</div>')
        }

        # Warnings and Errors
        if ($Warnings.Count -gt 0 -or $Errors.Count -gt 0) {
            $html.Add('<div class="section">')
            $html.Add('    <h2>Warnings and Errors</h2>')

            if ($Errors.Count -gt 0) {
                $html.Add('    <h3>Errors</h3>')
                $html.Add('    <ul>')

                foreach ($errorItem in $Errors) {
                    $html.Add("        <li class='warning'>$errorItem</li>")
                }

                $html.Add('    </ul>')
            }

            if ($Warnings.Count -gt 0) {
                $html.Add('    <h3>Warnings</h3>')
                $html.Add('    <ul>')

                foreach ($warning in $Warnings) {
                    $html.Add("        <li>$warning</li>")
                }
                $html.Add('    </ul>')
            }

            $html.Add('</div>')
        }

        # Footer
        $html.Add('<div class="footer">')
        $html.Add("    <p>Absolute Agent Diagnostics - version $script:ScriptVersion</p>")
        $html.Add("    <p>Report generated at $dateString on $($env:COMPUTERNAME)</p>")
        $html.Add('</div>')

        $html.Add('</div>') # .container
        $html.Add('</body>')
        $html.Add('</html>')

        # Write to file
        $html -join "`r`n" | Set-Content -Path $Path -Encoding UTF8 -Force
        Write-DiagLog -Message "HTML report saved to: $Path" -Level 'Success'
    }

} # end begin block

process {
    # You can call diagnostic steps here (Get-SystemInfo, Test-Services, etc.)
    # and collect their output into variables. Example placeholders:

    $systemInfo = Get-SystemInfo
    $services = Test-Services
    $endpoints = Test-NetworkConnectivity -Endpoints $EndpointsToCheck -Expected $ExpectedStatusCodes
    $summaryStats = @{
        'Total Endpoints' = $endpoints.Count
        'Passed' = ($endpoints | Where-Object Status -eq 'Pass').Count
        'Failed' = ($endpoints | Where-Object Status -eq 'Fail').Count
        'Errors' = ($endpoints | Where-Object Status -eq 'Error').Count
    }

    $htmlPath = Join-Path -Path $script:diagFolder -ChildPath "AbsoluteDiagnostics.html"

    Export-HtmlReport -Path $htmlPath `
        -Summary $summaryStats `
        -EndpointResults $endpoints `
        -ServiceResults $services `
        -SystemInfo $systemInfo `
        -RegistryInfo @() `
        -Warnings $script:DiagWarnings `
        -Errors $script:DiagErrors

    if (-not $SkipExcel) {
        if (Test-ModuleAvailable -ModuleName ImportExcel) {
            $excelPath = Join-Path -Path $script:diagFolder -ChildPath "AbsoluteDiagnostics.xlsx"
            $systemInfo.GetEnumerator() | ForEach-Object {
                [PSCustomObject]@{ Key = $_.Key; Value = $_.Value }
            } | Export-Excel -Path $excelPath -WorksheetName "System" -AutoSize

            $services | Export-Excel -Path $excelPath -WorksheetName "Services" -Append -AutoSize
            $endpoints | Export-Excel -Path $excelPath -WorksheetName "Endpoints" -Append -AutoSize
        }
        else {
            Write-DiagLog -Message "ImportExcel module not available. Excel report skipped." -Level 'Warning'
        }
    }
}

end {
    # Stop transcript early to avoid locking during ZIP
    Stop-Transcript

    # Final ZIP packaging (if not skipped)
    if (-not $SkipZip) {
        $zipPath = "$script:diagFolder.zip"

        if (Wait-ForFileUnlock -FilePath $transcriptPath -TimeoutSec 10) {
            try {
                Compress-Archive -Path $script:diagFolder -DestinationPath $zipPath -Force
                Write-DiagLog -Message "Diagnostics folder compressed to: $zipPath" -Level 'Success'
            }
            catch {
                Write-DiagLog -Message "Failed to compress diagnostics folder: $_" -Level 'Error'
            }
        }
        else {
            Write-DiagLog -Message "Transcript file was locked. Skipping ZIP." -Level 'Warning'
        }
    }

    # Summary
    $duration = $script:stopwatch.Elapsed.ToString("hh\:mm\:ss")
    Write-Host ""
    Write-Host "✅ Diagnostics complete in $duration" -ForegroundColor Green
    Write-Host "📁 Output saved to: $script:diagFolder" -ForegroundColor Cyan
    Write-Host ""

    if (Test-Path $script:diagFolder) {
        Start-Process "explorer.exe" -ArgumentList "`"$script:diagFolder`""
    }
}
