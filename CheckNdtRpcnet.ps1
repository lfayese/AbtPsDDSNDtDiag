<#
.SYNOPSIS
Comprehensive diagnostic collector for Absolute agent and related services.

.DESCRIPTION
Performs a thorough diagnostic collection and analysis of the Absolute agent environment:
- System information and configuration
- Network endpoint connectivity tests with detailed status
- CTES logs collection and analysis
- Absolute service status (rpcnet, rpcnetp, rpcnetc)
- AbtPS and DDSNdt diagnostic tool execution
- Registry settings export
- Generates both HTML and optional Excel reports
- Creates a consolidated ZIP archive of all findings

.EXAMPLE
# Run basic diagnostics with default HTML report
.\CheckNdtRpcnet.ps1

.EXAMPLE
# Generate both HTML and Excel reports with verbose logging
.\CheckNdtRpcnet.ps1 -IncludeExcel -VerboseLog

.EXAMPLE
# Specify custom output directory and skip ZIP creation
.\CheckNdtRpcnet.ps1 -OutputDirectory "C:\Temp\Diagnostics" -SkipZip

.NOTES
Version: 2.0
Author: Absolute Software
Last Updated: 2025-05-19
#>

[CmdletBinding()]
param(
    [int]$CallTimeoutSec = 60,
    [switch]$IncludeExcel,
    [switch]$SkipZip,
    [switch]$VerboseLog,
    [int]$NetworkTimeout = 10,
    [string[]]$EndpointsToCheck = @(
        "http://search.namequery.com",
        "https://search.namequery.com/ctes/1.0.0/configuration",
        "https://search.namequery.com/downloads/public/bin/Windows/CTES/CTES/1.0.0.3316/filelist.txt",
        "https://deviceapi.ca1.absolute.com/ctes/1.0.0/configuration",
        "https://resources.namequery.com/downloads/public/bin/Windows/CTES/HDC/2.0.15.13/CtHWiPrvPackage.zip"
    ),
    [hashtable]$ExpectedStatusCodes = @{
        "http://search.namequery.com" = "301 or 200";
        "https://search.namequery.com/ctes/1.0.0/configuration" = "401";
        "https://search.namequery.com/downloads/public/bin/Windows/CTES/CTES/1.0.0.3316/filelist.txt" = "200";
        "https://deviceapi.ca1.absolute.com/ctes/1.0.0/configuration" = "401";
        "https://resources.namequery.com/downloads/public/bin/Windows/CTES/HDC/2.0.15.13/CtHWiPrvPackage.zip" = "404 or 200"
    },
    [string]$OutputDirectory = $PSScriptRoot
)

$env:PSModulePath = "$PSScriptRoot\Modules;$env:PSModulePath"

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Only set verbose if explicitly requested
if ($VerboseLog) { $VerbosePreference = 'Continue' }

# Create global variables for progress reporting
$script:ProgressId = 0
$script:ProgressActivity = "Absolute Diagnostics"
$script:TotalSteps = 8
$script:CurrentStep = 0
$script:DiagFolder = $null

if (-not (Test-Path $OutputDirectory)) {
    try {
        New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
    } catch {
        throw "Failed to create output directory: $OutputDirectory"
    }
}

Start-Transcript -Path (Join-Path $OutputDirectory "diagnostics_transcript_$(Get-Date -Format 'yyyyMMdd_HHmmss').log")

# Helper Functions
function Write-ProgressHelper {
    [CmdletBinding()]
    param(
        [string]$Activity,
        [string]$Status,
        [int]$PercentComplete = -1,
        [switch]$Completed
    )

    if ($Completed) {
        $script:CurrentStep++
        $percent = [math]::Min(($script:CurrentStep / $script:TotalSteps) * 100, 100)
        Write-Progress -Id $script:ProgressId -Activity $script:ProgressActivity -Status "Completed: $Activity" -PercentComplete $percent
    }
    else {
        if ($PercentComplete -ge 0) {
            $totalPercent = [math]::Min((($script:CurrentStep / $script:TotalSteps) * 100) + (($PercentComplete / 100) * (100 / $script:TotalSteps)), 100)
            Write-Progress -Id $script:ProgressId -Activity $script:ProgressActivity -Status $Status -PercentComplete $totalPercent
        }
        else {
            $percent = [math]::Min(($script:CurrentStep / $script:TotalSteps) * 100, 100)
            Write-Progress -Id $script:ProgressId -Activity $script:ProgressActivity -Status $Activity -PercentComplete $percent
        }
    }
}

function Set-ExecutionPolicySafe {
    try {
        if ((Get-ExecutionPolicy -Scope Process) -ne 'Bypass') {
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        }
    } catch {
        Write-Warning "Unable to set execution policy: $_"
    }
}

function Test-RequiredModule {
    Write-ProgressHelper -Activity "Checking required modules" -Status "Looking for ImportExcel module"

    $localModulePath = Join-Path $PSScriptRoot "Modules\ImportExcel"
    if (-not (Test-Path $localModulePath)) {
        Write-Warning "ImportExcel module not found in $localModulePath. Excel export will be skipped."
        Write-ProgressHelper -Activity "Checking required modules" -Completed
        return $false
    }

    try {
        Import-Module $localModulePath -Force
        Write-Verbose "Successfully imported local ImportExcel module"
        Write-ProgressHelper -Activity "Checking required modules" -Completed
        return $true
    } catch {
        Write-Warning "Failed to import ImportExcel module: $_"
        Write-ProgressHelper -Activity "Checking required modules" -Completed
        return $false
    }
}

function New-DiagnosticsFolder {
    Write-ProgressHelper -Activity "Creating diagnostics folder" -Status "Setting up folder structure"

    try {
        # Create single folder with no underscores
        $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
        $DiagFolder = Join-Path $OutputDirectory "AbsoluteDiagnostics$timestamp"

        # Create the folder
        New-Item -ItemType Directory -Path $DiagFolder -Force | Out-Null

        Write-Verbose "Created diagnostics folder: $DiagFolder"

        # Set global variable for easy access throughout the script
        $script:DiagFolder = $DiagFolder

        Write-ProgressHelper -Activity "Creating diagnostics folder" -Completed
        return $DiagFolder
    }
    catch {
        Write-Warning "Failed to create diagnostics folder: $_"
        throw
    }
}

function Get-SystemInfo {
    Write-ProgressHelper -Activity "Collecting system information" -Status "Gathering system details"

    try {
        $computerInfo = Get-ComputerInfo

        # Convert computer info to a formatted list, excluding empty values
        $formattedInfo = $computerInfo | 
            Get-Member -MemberType Properties |
            Where-Object { 
                $value = $computerInfo.($_.Name)
                $null -ne $value -and $value -ne '' -and $value -notmatch '^\s+$'
            } |
            Select-Object @{
                Name='Property';
                Expression={$_.Name}
            }, @{
                Name='Value';
                Expression={$computerInfo.($_.Name)}
            }

        Write-ProgressHelper -Activity "Collecting system information" -Completed
        return $formattedInfo
    }
    catch {
        Write-Warning "Failed to collect system information: $_"
        throw
    }
}

function Test-Services {
    Write-ProgressHelper -Activity "Checking Absolute services" -Status "Querying service status"

    try {
        $services = @('rpcnet', 'rpcnetp', 'rpcnetc')
        $status = foreach ($svc in $services) {
            try {
                $s = Get-Service -Name $svc -ErrorAction Stop
                # Get additional service properties
                $svcWMI = Get-CimInstance Win32_Service -Filter "Name='$($s.Name)'" -ErrorAction SilentlyContinue

                [PSCustomObject]@{
                    Name = $s.Name
                    DisplayName = $s.DisplayName
                    Status = $s.Status
                    StartType = if ($svcWMI) { $svcWMI.StartMode } else { "Unknown" }
                    Account = if ($svcWMI) { $svcWMI.StartName } else { "Unknown" }
                }
            } catch {
                [PSCustomObject]@{
                    Name = $svc
                    DisplayName = ''
                    Status = 'Not Found'
                    StartType = 'N/A'
                    Account = 'N/A'
                }
            }
        }

        Write-ProgressHelper -Activity "Checking Absolute services" -Completed
        return $status
    }
    catch {
        Write-Warning "Failed to check services: $_"
        return @()
    }
}

function Invoke-AbtPSDiagnostics {
    param (
        [string]$AbtPSPath,
        [int]$TimeoutSec,
        [string]$LogPath
    )

    Write-ProgressHelper -Activity "Running AbtPS diagnostics" -Status "Checking AbtPS.exe"

    try {
        if (!(Test-Path $AbtPSPath)) {
            throw "AbtPS.exe not found at $AbtPSPath"
        }

        $log = [System.Collections.Generic.List[string]]::new()
        $log.Add("AbtPS Diagnostics - $(Get-Date)")
        $log.Add("===================================")

        function RunCmd($CommandArgs) {
            $log.Add("> AbtPS $CommandArgs")
            try {
                & $AbtPSPath $CommandArgs 2>&1 | ForEach-Object { $log.Add($_) }
            }
            catch {
                $log.Add("Error: $_")
            }
        }

        Write-ProgressHelper -Status "Getting AbtPS status" -PercentComplete 10
        RunCmd "-Status"

        Write-ProgressHelper -Status "Getting AbtPS version" -PercentComplete 20
        RunCmd "-Version"

        Write-ProgressHelper -Status "Getting ESN" -PercentComplete 30
        RunCmd "-ESN"

        Write-ProgressHelper -Status "Starting call test" -PercentComplete 40
        RunCmd "-StartCall"

        $start = Get-Date
        $totalTime = [TimeSpan]::FromSeconds($TimeoutSec)

        while ((Get-Date) - $start -lt $totalTime) {
            $elapsed = ((Get-Date) - $start).TotalSeconds
            $percent = [math]::Min(($elapsed / $totalTime.TotalSeconds * 60) + 40, 90)

            Write-ProgressHelper -Status "Checking call status ($([int]$elapsed)s / ${TimeoutSec}s)" -PercentComplete $percent

            RunCmd "-IsCalling"
            if ($log[-1] -match "not calling") { break }
            Start-Sleep -Seconds 5
        }

        Write-ProgressHelper -Status "Getting final ESN" -PercentComplete 95
        RunCmd "-ESN"

        $log | Out-File -FilePath $LogPath -Encoding UTF8
        Write-ProgressHelper -Activity "Running AbtPS diagnostics" -Completed

        return $log
    }
    catch {
        Write-Warning "Failed to run AbtPS diagnostics: $_"
        return @("ERROR: Failed to run AbtPS diagnostics: $($_.Exception.Message)")
    }
}

function Test-NetworkConnectivity {
    param (
        [string]$Endpoint,
        [int]$Timeout = 5
    )

    try {
        # Extract hostname from URL
        $uri = [System.Uri]$Endpoint
        $hostname = $uri.Host

        # Run ping test
        $pingResult = Test-Connection -ComputerName $hostname -Count 2 -Quiet

        # Run traceroute (limited to 15 hops for performance)
        $traceOutput = @()
        try {
            $traceRoute = Test-NetConnection -ComputerName $hostname -TraceRoute -Hops 15 -WarningAction SilentlyContinue
            $traceOutput = $traceRoute.TraceRoute
        }
        catch {
            $traceOutput = @("Traceroute failed: $($_.Exception.Message)")
        }

        return @{
            Host = $hostname
            PingSuccessful = $pingResult
            TraceRoute = $traceOutput
        }
    }
    catch {
        return @{
            Host = "Unknown"
            PingSuccessful = $false
            TraceRoute = @("Error: $($_.Exception.Message)")
        }
    }
}

function Test-NetworkEndpoints {
    param (
        [string[]]$Endpoints,
        [hashtable]$Expected,
        [int]$Timeout = 10
    )

    Write-ProgressHelper -Activity "Testing network connectivity" -Status "Checking endpoints"

    try {
        $results = @()

        for ($i = 0; $i -lt $Endpoints.Count; $i++) {
            $endpoint = $Endpoints[$i]
            $percentComplete = [math]::Min(($i / $Endpoints.Count) * 100, 100)

            Write-ProgressHelper -Status "Testing $endpoint" -PercentComplete $percentComplete

            # Get connectivity info
            $connectivity = Test-NetworkConnectivity -Endpoint $endpoint -Timeout $Timeout

            try {
                $startTime = Get-Date
                $response = Invoke-WebRequest -Uri $endpoint -TimeoutSec $Timeout -UseBasicParsing -ErrorAction Stop
                $responseTime = ((Get-Date) - $startTime).TotalMilliseconds

                $statusDesc = [int]$response.StatusCode
                $expectedStatus = if ($Expected.ContainsKey($endpoint)) { $Expected[$endpoint] } else { "200" }

                # Check if actual status matches expected (handles "301 or 200" style expectations)
                $statusMatch = $expectedStatus -split ' or ' | ForEach-Object { $_ -eq $statusDesc.ToString() } | Where-Object { $_ -eq $true } | Select-Object -First 1

                $results += [PSCustomObject]@{
                    URL = $endpoint
                    Status = if ($statusMatch) { "Pass" } else { "Fail" }
                    Code = $statusDesc
                    Description = $response.StatusDescription
                    Expected = $expectedStatus
                    ResponseTime = [math]::Round($responseTime)
                    PingStatus = if ($connectivity.PingSuccessful) { "Success" } else { "Failed" }
                    TraceRoute = if ($connectivity.TraceRoute) { $connectivity.TraceRoute -join " -> " } else { "N/A" }
                }
            }
            catch [System.Net.WebException] {
                $webEx = $_.Exception

                if ($null -ne $webEx.Response) {
                    $statusCode = [int]$webEx.Response.StatusCode
                    $statusDesc = $webEx.Response.StatusDescription

                    $expectedStatus = if ($Expected.ContainsKey($endpoint)) { $Expected[$endpoint] } else { "200" }
                    $statusMatch = $expectedStatus -split ' or ' | ForEach-Object { $_ -eq $statusCode.ToString() } | Where-Object { $_ -eq $true } | Select-Object -First 1

                    $results += [PSCustomObject]@{
                        URL = $endpoint
                        Status = if ($statusMatch) { "Pass" } else { "Fail" }
                        Code = $statusCode
                        Description = $statusDesc
                        Expected = $expectedStatus
                        ResponseTime = 0
                        PingStatus = if ($connectivity.PingSuccessful) { "Success" } else { "Failed" }
                        TraceRoute = if ($connectivity.TraceRoute) { $connectivity.TraceRoute -join " -> " } else { "N/A" }
                    }
                }
                else {
                    $results += [PSCustomObject]@{
                        URL = $endpoint
                        Status = "Error"
                        Code = 0
                        Description = $webEx.Message
                        Expected = if ($Expected.ContainsKey($endpoint)) { $Expected[$endpoint] } else { "200" }
                        ResponseTime = 0
                        PingStatus = if ($connectivity.PingSuccessful) { "Success" } else { "Failed" }
                        TraceRoute = if ($connectivity.TraceRoute) { $connectivity.TraceRoute -join " -> " } else { "N/A" }
                    }
                }
            }
            catch {
                $results += [PSCustomObject]@{
                    URL = $endpoint
                    Status = "Error"
                    Code = 0
                    Description = $_.Exception.Message
                    Expected = if ($Expected.ContainsKey($endpoint)) { $Expected[$endpoint] } else { "200" }
                    ResponseTime = 0
                    PingStatus = if ($connectivity.PingSuccessful) { "Success" } else { "Failed" }
                    TraceRoute = if ($connectivity.TraceRoute) { $connectivity.TraceRoute -join " -> " } else { "N/A" }
                }
            }
        }

        Write-ProgressHelper -Activity "Testing network connectivity" -Completed
        return $results
    }
    catch {
        Write-Warning "Failed to test network endpoints: $_"
        return @()
    }
}

function Invoke-NetworkDiagnostics {
    param (
        [string]$DDSNdtPath,
        [string]$LogDir
    )

    Write-ProgressHelper -Activity "Running network diagnostics" -Status "Checking DDSNdt.exe"

    try {
        if (!(Test-Path $DDSNdtPath)) {
            throw "DDSNdt.exe not found at $DDSNdtPath"
        }

        $log = [System.Collections.Generic.List[string]]::new()
        $log.Add("Network Diagnostics - $(Get-Date)")
        $log.Add("=======================================")

        # Run tool and capture output
        Write-ProgressHelper -Status "Executing network diagnostics" -PercentComplete 20
        try {
            $output = & $DDSNdtPath 2>&1 | Out-String
            $log.Add($output)
        }
        catch {
            $log.Add("Error executing DDSNdt.exe: $_")
        }

        $logPath = Join-Path $LogDir "DDSNdt.log"
        $log | Out-File -FilePath $logPath -Encoding UTF8
        Write-ProgressHelper -Activity "Running network diagnostics" -Completed

        return $log
    }
    catch {
        Write-Warning "Failed to run network diagnostics: $_"
        return @("ERROR: Failed to run network diagnostics: $($_.Exception.Message)")
    }
}

function Export-HtmlReport {
    param (
        [string]$HtmlPath,
        [array]$SystemInfo,
        [array]$ExtendedInfo,
        [array]$AbtPSLog,
        [array]$NetResults,
        [array]$DDSLog,
        [array]$ServiceStatus,
        [array]$CtesLogs
    )

    Write-ProgressHelper -Activity "Creating HTML report" -Status "Preparing data"

    try {
        $html = [System.Collections.Generic.List[string]]::new()
        $html.Add('<!DOCTYPE html>')
        $html.Add('<html lang="en">')
        $html.Add('<head>')
        $html.Add('    <meta charset="UTF-8">')
        $html.Add('    <title>Absolute Agent Diagnostics</title>')
        $html.Add('    <style>')
        $html.Add('        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; color: #333; }')
        $html.Add('        .container { max-width: 1200px; margin: 0 auto; background: #fff; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }')
        $html.Add('        h1, h2, h3 { color: #00447c; }')
        $html.Add('        table { width: 100%; border-collapse: collapse; margin-bottom: 20px; }')
        $html.Add('        th { background-color: #00447c; color: #fff; text-align: left; padding: 8px; }')
        $html.Add('        td { padding: 8px; border: 1px solid #ddd; }')
        $html.Add('        tr:nth-child(even) { background-color: #f2f2f2; }')
        $html.Add('        .pass { background-color: #dff0d8; }')
        $html.Add('        .fail { background-color: #f2dede; }')
        $html.Add('        .warning { background-color: #fcf8e3; }')
        $html.Add('        .notfound { background-color: #eee; }')
        $html.Add('        .timestamp { color: #666; font-style: italic; margin-bottom: 20px; }')
        $html.Add('        .footer { margin-top: 30px; text-align: center; font-size: 12px; color: #666; }')
        $html.Add('        .collapsible { cursor: pointer; padding: 10px; border: none; text-align: left; outline: none; width: 100%; }')
        $html.Add('        .active, .collapsible:hover { background-color: #f8f9fa; }')
        $html.Add('        .content { padding: 0 18px; display: none; overflow: hidden; background-color: #f8f9fa; }')
        $html.Add('        .log-content { font-family: monospace; white-space: pre-wrap; max-height: 400px; overflow-y: auto; }')
        $html.Add('    </style>')
        $html.Add('    <script>')
        $html.Add('        function toggleCollapsible(element) {')
        $html.Add('            element.classList.toggle("active");')
        $html.Add('            var content = element.nextElementSibling;')
        $html.Add('            if (content.style.display === "block") {')
        $html.Add('                content.style.display = "none";')
        $html.Add('            } else {')
        $html.Add('                content.style.display = "block";')
        $html.Add('            }')
        $html.Add('        }')
        $html.Add('    </script>')
        $html.Add('</head>')
        $html.Add('<body>')
        $html.Add('    <div class="container">')
        $html.Add("        <h1>Absolute Agent Diagnostics</h1>")
        $html.Add("        <div class='timestamp'>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</div>")

        # System Information
        $html.Add('        <h2>System Information</h2>')
        $html.Add('        <table>')
        $html.Add('            <tr><th>Property</th><th>Value</th></tr>')
        foreach ($item in $SystemInfo) {
            $html.Add("            <tr><td>$($item.Property)</td><td>$($item.Value)</td></tr>")
        }
        $html.Add('        </table>')

        if ($ExtendedInfo -and $ExtendedInfo.Count -gt 0) {
            $html.Add('        <h3>Extended System Information</h3>')
            $html.Add('        <button class="collapsible" onclick="toggleCollapsible(this)">Show Extended Info</button>')
            $html.Add('        <div class="content">')
            $html.Add('            <table>')
            $html.Add('                <tr><th>Property</th><th>Value</th></tr>')
            foreach ($item in $ExtendedInfo) {
                $html.Add("                <tr><td>$($item.Property)</td><td>$($item.Value)</td></tr>")
            }
            $html.Add('            </table>')
            $html.Add('        </div>')
        }

        # Network Connectivity
        $html.Add('        <h2>Network Connectivity Tests</h2>')
        $html.Add('        <table>')
        $html.Add('            <tr><th>URL</th><th>Status</th><th>Code</th><th>Description</th><th>Expected</th><th>Response Time (ms)</th><th>Ping Status</th></tr>')
        foreach ($item in $NetResults) {
            $statusClass = switch ($item.Status) {
                'Pass' { 'pass' }
                'Fail' { 'fail' }
                'Error' { 'warning' }
                default { '' }
            }
            $html.Add("            <tr class='$statusClass'>")
            $html.Add("                <td>$($item.URL)</td>")
            $html.Add("                <td>$($item.Status)</td>")
            $html.Add("                <td>$($item.Code)</td>")
            $html.Add("                <td>$($item.Description)</td>")
            $html.Add("                <td>$($item.Expected)</td>")
            $html.Add("                <td>$($item.ResponseTime)</td>")
            $html.Add("                <td>$($item.PingStatus)</td>")
            $html.Add("            </tr>")
        }
        $html.Add('        </table>')

        # Services
        $html.Add('        <h2>Absolute Services</h2>')
        $html.Add('        <table>')
        $html.Add('            <tr><th>Name</th><th>Display Name</th><th>Status</th><th>Startup Type</th><th>Account</th></tr>')
        foreach ($item in $ServiceStatus) {
            $statusClass = switch ($item.Status) {
                'Running' { 'pass' }
                'Stopped' { 'fail' }
                'Not Found' { 'notfound' }
                default { '' }
            }
            $html.Add("            <tr class='$statusClass'>")
            $html.Add("                <td>$($item.Name)</td>")
            $html.Add("                <td>$($item.DisplayName)</td>")
            $html.Add("                <td>$($item.Status)</td>")
            $html.Add("                <td>$($item.StartType)</td>")
            $html.Add("                <td>$($item.Account)</td>")
            $html.Add("            </tr>")
        }
        $html.Add('        </table>')

        # CTES Logs
        if ($CtesLogs -and $CtesLogs.Count -gt 0) {
            $html.Add('        <h2>CTES Logs</h2>')
            foreach ($log in $CtesLogs) {
                $html.Add("        <button class='collapsible' onclick='toggleCollapsible(this)'>$($log.Name) - Last Modified: $($log.LastWriteTime)</button>")
                $html.Add('        <div class="content">')
                $html.Add('            <div class="log-content">')
                $html.Add([System.Web.HttpUtility]::HtmlEncode($log.Content))
                $html.Add('            </div>')
                $html.Add('        </div>')
            }
        }

        # Diagnostic Logs
        if ($AbtPSLog -and $AbtPSLog.Count -gt 0) {
            $html.Add('        <h2>AbtPS Diagnostics</h2>')
            $html.Add("        <button class='collapsible' onclick='toggleCollapsible(this)'>Show AbtPS Diagnostic Log</button>")
            $html.Add('        <div class="content">')
            $html.Add('            <div class="log-content">')
            foreach ($line in $AbtPSLog) {
                $html.Add([System.Web.HttpUtility]::HtmlEncode($line))
            }
            $html.Add('            </div>')
            $html.Add('        </div>')
        }

        if ($DDSLog -and $DDSLog.Count -gt 0) {
            $html.Add('        <h2>Network Diagnostics</h2>')
            $html.Add("        <button class='collapsible' onclick='toggleCollapsible(this)'>Show Network Diagnostic Log</button>")
            $html.Add('        <div class="content">')
            $html.Add('            <div class="log-content">')
            foreach ($line in $DDSLog) {
                $html.Add([System.Web.HttpUtility]::HtmlEncode($line))
            }
            $html.Add('            </div>')
            $html.Add('        </div>')
        }

        $html.Add('        <div class="footer">Absolute Agent Diagnostics | ' + $env:COMPUTERNAME + '</div>')
        $html.Add('    </div>')
        $html.Add('</body>')
        $html.Add('</html>')

        $html -join "`r`n" | Out-File -FilePath $HtmlPath -Encoding UTF8 -Force
        Write-Verbose "HTML report created successfully at $HtmlPath"
        Write-ProgressHelper -Activity "Creating HTML report" -Completed
        return $true
    }
    catch {
        Write-Warning "Failed to create HTML report: $_"
        return $false
    }
}

function Copy-AdditionalLogs {
    param (
        [string]$OutputFolder
    )

    Write-ProgressHelper -Activity "Collecting additional logs" -Status "Searching for Absolute logs"

    try {
        $logLocations = @(
            "C:\ProgramData\CTES\logs"
        )

        $foundLogs = $false

        foreach ($location in $logLocations) {
            if (Test-Path $location) {
                $foundLogs = $true
                # Create a labeled folder for CTES logs within the diagnostics folder
                $destFolder = Join-Path $OutputFolder "CTES_Logs"

                if (!(Test-Path $destFolder)) {
                    New-Item -ItemType Directory -Path $destFolder -Force | Out-Null
                }

                Copy-Item -Path "$location\*" -Destination $destFolder -Recurse -Force -ErrorAction SilentlyContinue
                Write-Verbose "Copied logs from $location to $destFolder"
            }
        }

        # Also collect registry settings
        $regFile = Join-Path $OutputFolder "AbsoluteRegistry.txt"
        try {
            $regPaths = @(
                "HKLM:\SOFTWARE\Absolute",
                "HKLM:\SOFTWARE\Absolute Software",
                "HKLM:\SOFTWARE\Wow6432Node\Absolute",
                "HKLM:\SOFTWARE\Wow6432Node\Absolute Software"
            )

            $regOutput = foreach ($path in $regPaths) {
                if (Test-Path $path) {
                    "# Registry Path: $path"
                    Get-ItemProperty -Path $path | Format-Table -AutoSize | Out-String
                    Get-ChildItem $path -Recurse -ErrorAction SilentlyContinue |
                        ForEach-Object {
                            "## $($_.Name)"
                            Get-ItemProperty -Path $_.PSPath | Format-Table -AutoSize | Out-String
                        }
                }
            }

            $regOutput | Out-File -FilePath $regFile -Encoding UTF8
            $foundLogs = $true
        }
        catch {
            Write-Warning "Failed to export registry settings: $_"
        }

        Write-ProgressHelper -Activity "Collecting additional logs" -Completed
        return $foundLogs
    }
    catch {
        Write-Warning "Failed to collect additional logs: $_"
        Write-ProgressHelper -Activity "Collecting additional logs" -Completed
        return $false
    }
}

function Export-DiagnosticsReport {
    param (
        [string]$ExcelPath,
        [array]$SystemInfo,
        [array]$ExtendedInfo,
        [array]$AbtPSLog,
        [array]$NetResults,
        [array]$DDSLog,
        [array]$ServiceStatus,
        [array]$CtesLogs
    )

    Write-ProgressHelper -Activity "Creating Excel report" -Status "Preparing data"

    try {
        # Use ImportExcel module
        if (-not (Get-Module -Name ImportExcel)) {
            Import-Module "$PSScriptRoot\Modules\ImportExcel" -ErrorAction Stop
        }

        Write-ProgressHelper -Status "Creating Excel workbook" -PercentComplete 20

        # Create Excel package
        $excel = New-Object OfficeOpenXml.ExcelPackage

        # System Info worksheet
        Write-ProgressHelper -Status "Adding system information" -PercentComplete 30
        $sysWs = $excel.Workbook.Worksheets.Add("System Info")
        $row = 1

        $sysWs.Cells["A$row"].Value = "System Information"
        $sysWs.Cells["A$row:C$row"].Merge = $true
        $sysWs.Cells["A$row:C$row"].Style.Font.Bold = $true
        $sysWs.Cells["A$row:C$row"].Style.Font.Size = 14
        $row++

        $sysWs.Cells["A$row"].Value = "Property"
        $sysWs.Cells["B$row"].Value = "Value"
        $sysWs.Cells["A$row:B$row"].Style.Font.Bold = $true
        $row++

        foreach ($item in $SystemInfo) {
            $sysWs.Cells["A$row"].Value = $item.Property
            $sysWs.Cells["B$row"].Value = if ($null -eq $item.Value) { "N/A" } else { $item.Value.ToString() }
            $row++
        }

        $sysWs.Cells["A$row"].Value = "Extended System Information"
        $sysWs.Cells["A$row:C$row"].Merge = $true
        $sysWs.Cells["A$row:C$row"].Style.Font.Bold = $true
        $sysWs.Cells["A$row:C$row"].Style.Font.Size = 14
        $row++

        $sysWs.Cells["A$row"].Value = "Property"
        $sysWs.Cells["B$row"].Value = "Value"
        $sysWs.Cells["A$row:B$row"].Style.Font.Bold = $true
        $row++

        foreach ($item in $ExtendedInfo) {
            $sysWs.Cells["A$row"].Value = $item.Property
            $sysWs.Cells["B$row"].Value = if ($null -eq $item.Value) { "N/A" } else { $item.Value.ToString() }
            $row++
        }

        $sysWs.Cells.AutoFitColumns()

        # Network Results worksheet
        Write-ProgressHelper -Status "Adding network information" -PercentComplete 50
        $netWs = $excel.Workbook.Worksheets.Add("Network")
        $row = 1

        $netWs.Cells["A$row"].Value = "Network Connectivity Tests"
        $netWs.Cells["A$row:G$row"].Merge = $true
        $netWs.Cells["A$row:G$row"].Style.Font.Bold = $true
        $netWs.Cells["A$row:G$row"].Style.Font.Size = 14
        $row++

        $netWs.Cells["A$row"].Value = "URL"
        $netWs.Cells["B$row"].Value = "Status"
        $netWs.Cells["C$row"].Value = "Status Code"
        $netWs.Cells["D$row"].Value = "Description"
        $netWs.Cells["E$row"].Value = "Expected"
        $netWs.Cells["F$row"].Value = "Response Time (ms)"
        $netWs.Cells["G$row"].Value = "Ping Status"
        $netWs.Cells["A$row:G$row"].Style.Font.Bold = $true
        $row++

        foreach ($item in $NetResults) {
            $netWs.Cells["A$row"].Value = $item.URL
            $netWs.Cells["B$row"].Value = $item.Status
            $netWs.Cells["C$row"].Value = $item.Code
            $netWs.Cells["D$row"].Value = $item.Description
            $netWs.Cells["E$row"].Value = $item.Expected
            $netWs.Cells["F$row"].Value = $item.ResponseTime
            $netWs.Cells["G$row"].Value = $item.PingStatus

            # Colorize status
            switch ($item.Status) {
                "Pass" { $color = [System.Drawing.Color]::LightGreen }
                "Fail" { $color = [System.Drawing.Color]::LightCoral }
                "Error" { $color = [System.Drawing.Color]::LightYellow }
                default { $color = $null }
            }

            if ($color) {
                $netWs.Cells["B$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                $netWs.Cells["B$row"].Style.Fill.BackgroundColor.SetColor($color)
            }

            $row++
        }

        $netWs.Cells.AutoFitColumns()

        # Services worksheet
        Write-ProgressHelper -Status "Adding service information" -PercentComplete 70
        $svcWs = $excel.Workbook.Worksheets.Add("Services")
        $row = 1

        $svcWs.Cells["A$row"].Value = "Absolute Services"
        $svcWs.Cells["A$row:E$row"].Merge = $true
        $svcWs.Cells["A$row:E$row"].Style.Font.Bold = $true
        $svcWs.Cells["A$row:E$row"].Style.Font.Size = 14
        $row++

        $svcWs.Cells["A$row"].Value = "Name"
        $svcWs.Cells["B$row"].Value = "Display Name"
        $svcWs.Cells["C$row"].Value = "Status"
        $svcWs.Cells["D$row"].Value = "Startup Type"
        $svcWs.Cells["E$row"].Value = "Account"
        $svcWs.Cells["A$row:E$row"].Style.Font.Bold = $true
        $row++

        foreach ($item in $ServiceStatus) {
            $svcWs.Cells["A$row"].Value = $item.Name
            $svcWs.Cells["B$row"].Value = $item.DisplayName
            $svcWs.Cells["C$row"].Value = $item.Status
            $svcWs.Cells["D$row"].Value = $item.StartType
            $svcWs.Cells["E$row"].Value = $item.Account

            # Colorize status
            switch ($item.Status) {
                "Running" { $color = [System.Drawing.Color]::LightGreen }
                "Stopped" { $color = [System.Drawing.Color]::LightCoral }
                "Not Found" { $color = [System.Drawing.Color]::LightGray }
                default { $color = $null }
            }

            if ($color) {
                $svcWs.Cells["C$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                $svcWs.Cells["C$row"].Style.Fill.BackgroundColor.SetColor($color)
            }

            $row++
        }

        $svcWs.Cells.AutoFitColumns()

        # CTES Logs worksheet
        if ($CtesLogs -and $CtesLogs.Count -gt 0) {
            Write-ProgressHelper -Status "Adding CTES logs" -PercentComplete 80
            $ctesWs = $excel.Workbook.Worksheets.Add("CTES Logs")
            $row = 1

            $ctesWs.Cells["A$row"].Value = "CTES Logs"
            $ctesWs.Cells["A$row:D$row"].Merge = $true
            $ctesWs.Cells["A$row:D$row"].Style.Font.Bold = $true
            $ctesWs.Cells["A$row:D$row"].Style.Font.Size = 14
            $row++

            $ctesWs.Cells["A$row"].Value = "Log File"
            $ctesWs.Cells["B$row"].Value = "Last Modified"
            $ctesWs.Cells["C$row"].Value = "Path"
            $ctesWs.Cells["D$row"].Value = "Content Summary"
            $ctesWs.Cells["A$row:D$row"].Style.Font.Bold = $true
            $row++

            foreach ($log in $CtesLogs) {
                $ctesWs.Cells["A$row"].Value = $log.Name
                $ctesWs.Cells["B$row"].Value = $log.LastWriteTime
                $ctesWs.Cells["C$row"].Value = $log.Path
                # Get first few lines of content as summary
                $summary = $log.Content -split "`n" | Select-Object -First 5 | Out-String
                $ctesWs.Cells["D$row"].Value = if ($summary) { $summary.Trim() } else { "N/A" }
                $row++
            }

            $ctesWs.Cells.AutoFitColumns()
        }

        # Diagnostics Logs worksheets
        Write-ProgressHelper -Status "Adding diagnostics logs" -PercentComplete 90

        # AbtPS Logs
        if ($AbtPSLog -and $AbtPSLog.Count -gt 0) {
            $abtWs = $excel.Workbook.Worksheets.Add("AbtPS Logs")
            $row = 1

            $abtWs.Cells["A$row"].Value = "AbtPS Diagnostic Log"
            $abtWs.Cells["A$row"].Style.Font.Bold = $true
            $abtWs.Cells["A$row"].Style.Font.Size = 14
            $row++

            foreach ($line in $AbtPSLog) {
                $abtWs.Cells["A$row"].Value = $line
                $row++
            }

            $abtWs.Cells.AutoFitColumns()
        }

        # DDSNdt Logs
        if ($DDSLog -and $DDSLog.Count -gt 0) {
            $ddsWs = $excel.Workbook.Worksheets.Add("DDSNdt Logs")
            $row = 1

            $ddsWs.Cells["A$row"].Value = "DDSNdt Network Diagnostic Log"
            $ddsWs.Cells["A$row"].Style.Font.Bold = $true
            $ddsWs.Cells["A$row"].Style.Font.Size = 14
            $row++

            foreach ($line in $DDSLog) {
                $ddsWs.Cells["A$row"].Value = $line
                $row++
            }

            $ddsWs.Cells.AutoFitColumns()
        }

        # Save the Excel report
        $excel.SaveAs($ExcelPath)
        Write-Verbose "Excel report saved to: $ExcelPath"

        Write-ProgressHelper -Activity "Creating Excel report" -Completed
        return $true
    }
    catch {
        Write-Warning "Failed to create Excel report: $_"
        return $false
    }
    finally {
        if ($excel) {
            $excel.Dispose()
        }
    }
}

function Get-CtesLogs {
    param (
        [string]$LogPath = "C:\ProgramData\CTES\logs"
    )

    try {
        if (-not (Test-Path $LogPath)) {
            Write-Verbose "CTES logs path not found: $LogPath"
            return @()
        }

        $logs = Get-ChildItem -Path $LogPath -File -Recurse -ErrorAction SilentlyContinue |
            ForEach-Object {
                [PSCustomObject]@{
                    Name = $_.Name
                    Path = $_.FullName
                    Content = Get-Content -Path $_.FullName -Raw -ErrorAction SilentlyContinue
                    LastWriteTime = $_.LastWriteTime
                }
            }

        return $logs
    }
    catch {
        Write-Warning "Failed to collect CTES logs: $_"
        return @()
    }
}

# Main script execution block
try {
    # Initialize diagnostics folder
    $diagFolder = New-DiagnosticsFolder

    # Check for required modules if Excel output is requested
    $hasExcelModule = $false
    if ($IncludeExcel) {
        $hasExcelModule = Test-RequiredModule
        if (-not $hasExcelModule) {
            Write-Warning "Excel output requested but ImportExcel module not available. Excel report will be skipped."
        }
    }

    # Collect system information
    $sysInfoResults = Get-SystemInfo

    # Check Absolute services
    $serviceResults = Test-Services

    # Test network connectivity
    $networkResults = Test-NetworkEndpoints -Endpoints $EndpointsToCheck -Expected $ExpectedStatusCodes -Timeout $NetworkTimeout

    # Run AbtPS diagnostics if available
    $abtPSResults = @()
    $abtPSPath = Join-Path $PSScriptRoot "AbtPS.exe"
    if (Test-Path $abtPSPath) {
        $abtPSResults = Invoke-AbtPSDiagnostics -AbtPSPath $abtPSPath -TimeoutSec $CallTimeoutSec -LogPath (Join-Path $diagFolder "AbtPS.log")
    } else {
        Write-Warning "AbtPS.exe not found in script directory. Skipping AbtPS diagnostics."
    }

    # Run network diagnostics if available
    $ddsResults = @()
    $ddsPath = Join-Path $PSScriptRoot "DDSNdt.exe"
    if (Test-Path $ddsPath) {
        $ddsResults = Invoke-NetworkDiagnostics -DDSNdtPath $ddsPath -LogDir $diagFolder
    } else {
        Write-Warning "DDSNdt.exe not found in script directory. Skipping network diagnostics."
    }

    # Collect CTES logs
    $ctesLogs = Get-CtesLogs -LogPath "C:\ProgramData\CTES\logs"
    if ($ctesLogs.Count -gt 0) {
        $ctesLogPath = Join-Path $diagFolder "CTES_Logs"
        if (!(Test-Path $ctesLogPath)) {
            New-Item -ItemType Directory -Path $ctesLogPath -Force | Out-Null
        }
        foreach ($log in $ctesLogs) {
            $destPath = Join-Path $ctesLogPath $log.Name
            Copy-Item -Path $log.Path -Destination $destPath -Force
        }
        Write-Verbose "CTES logs copied to: $ctesLogPath"
    } else {
        Write-Verbose "No CTES logs found at the specified path."
    }

    # Create HTML report (default)
    $htmlPath = Join-Path $diagFolder "DiagnosticsReport.html"
    $htmlResult = Export-HtmlReport -HtmlPath $htmlPath `
        -SystemInfo $sysInfoResults `
        -ExtendedInfo $ExtendedInfo `
        -AbtPSLog $abtPSResults `
        -NetResults $networkResults `
        -DDSLog $ddsResults `
        -ServiceStatus $serviceResults `
        -CtesLogs $ctesLogs

    if ($htmlResult) {
        Write-Verbose "HTML report created at: $htmlPath"
    }

    # Create Excel report if requested and module available
    if ($IncludeExcel -and $hasExcelModule) {
        $excelPath = Join-Path $diagFolder "DiagnosticsReport.xlsx"
        $excelResult = Export-DiagnosticsReport -ExcelPath $excelPath `
            -SystemInfo $sysInfoResults `
            -ExtendedInfo $ExtendedInfo `
            -AbtPSLog $abtPSResults `
            -NetResults $networkResults `
            -DDSLog $ddsResults `
            -ServiceStatus $serviceResults `
            -CtesLogs $ctesLogs

        if ($excelResult) {
            Write-Verbose "Excel report created at: $excelPath"
        }
    }

    # Create ZIP archive if requested
    if (-not $SkipZip) {
        $zipPath = "$diagFolder.zip"
        Write-Verbose "Creating ZIP archive at: $zipPath"
        Compress-Archive -Path $diagFolder -DestinationPath $zipPath -Force
        Write-Verbose "ZIP archive created successfully"
    }

    Write-Host "`nDiagnostics completed successfully. Reports can be found in: $diagFolder"
    Write-Host "HTML report: $htmlPath"
    if ($IncludeExcel -and $hasExcelModule -and $excelResult) {
        Write-Host "Excel report: $excelPath"
    }
    if (-not $SkipZip) {
        Write-Host "ZIP archive: $zipPath"
    }
}
catch {
    Write-Error "An error occurred while running diagnostics: $_"
    throw
}
finally {
    Stop-Transcript
    Write-Progress -Id $script:ProgressId -Activity $script:ProgressActivity -Completed
}
