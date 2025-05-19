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
    [int]$MaxParallelTasks = 5,
    [string[]]$EndpointsToCheck = @(
    "http://search.namequery.com",
    "https://search.namequery.com/ctes/1.0.0/configuration", 
    "https://search.namequery.com/downloads/public/bin/Windows/CTES/CTES/1.0.0.3316/filelist.txt",
    "https://deviceapi.ca1.absolute.com/ctes/1.0.0/configuration",
    "https://resources.namequery.com/downloads/public/bin/Windows/CTES/HDC/2.0.15.13/CtHWiPrvPackage.zip"
),
[hashtable]$ExpectedStatusCodes = @{
    "http://search.namequery.com" = "200";  # Updated to match curl behavior
    "https://search.namequery.com/ctes/1.0.0/configuration" = "401";
    "https://search.namequery.com/downloads/public/bin/Windows/CTES/CTES/1.0.0.3316/filelist.txt" = "200";
    "https://deviceapi.ca1.absolute.com/ctes/1.0.0/configuration" = "401";
    "https://resources.namequery.com/downloads/public/bin/Windows/CTES/HDC/2.0.15.13/CtHWiPrvPackage.zip" = "404 or 200"
},
    [string]$OutputDirectory = $PSScriptRoot
)

# Enable TLS 1.2 and 1.3 for all HTTPS requests
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13

# Load HtmlEncode support
Add-Type -AssemblyName System.Web

# Define execution policy helper before use
function Set-ProcessExecutionPolicy {
    try {
        if ((Get-ExecutionPolicy -Scope Process) -ne 'Bypass') {
            Write-Verbose "Setting execution policy to Bypass for current process (was: $(Get-ExecutionPolicy -Scope Process))"
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        }
    } catch {
        Write-Warning "Unable to set execution policy: $_"
    }
}

# Set the execution policy
Set-ProcessExecutionPolicy

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
function Set-ExecutionPolicySafe {
    try {
        if ((Get-ExecutionPolicy -Scope Process) -ne 'Bypass') {
            Write-Verbose "Setting execution policy to Bypass for current process (was: $(Get-ExecutionPolicy -Scope Process))"
            Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force
        }
    } catch {
        Write-Warning "Unable to set execution policy: $_"
    }
}

function Write-ProgressHelper {
    [CmdletBinding()]
    param(
        [string]$Activity,
        [string]$Status = "",
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
            $statusMsg = if ([string]::IsNullOrWhiteSpace($Status)) { "Processing..." } else { $Status }
            Write-Progress -Id $script:ProgressId -Activity $script:ProgressActivity -Status $statusMsg -PercentComplete $totalPercent
        }
        else {
            $percent = [math]::Min(($script:CurrentStep / $script:TotalSteps) * 100, 100)
            $statusMsg = if ([string]::IsNullOrWhiteSpace($Status) -and ![string]::IsNullOrWhiteSpace($Activity)) { $Activity } else { "Processing..." }
            Write-Progress -Id $script:ProgressId -Activity $script:ProgressActivity -Status $statusMsg -PercentComplete $percent
        }
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
        $allProperties = $computerInfo | Get-Member -MemberType Properties
        
        # Core system properties
        $coreProperties = @(
            'CsName','CsDomain','CsUserName','OsName','OsVersion',
            'OsBuildNumber','OsArchitecture','CsProcessors','CsNumberOfProcessors',
            'CsPhysicallyInstalledMemory','CsTotalPhysicalMemory'
        )

        # Core information
        $coreInfo = $allProperties | 
            Where-Object { 
                $value = $computerInfo.($_.Name)
                $_.Name -in $coreProperties -and
                $null -ne $value -and $value -ne '' -and $value -notmatch '^\s+$'
            } |
            Select-Object @{
                Name='Property';
                Expression={$_.Name}
            }, @{
                Name='Value';
                Expression={
                    $value = $computerInfo.($_.Name)
                    if ($_.Name -match 'Memory|PhysicalMemory') {
                        $bytes = [math]::Round($value / 1GB, 2)
                        "$bytes GB"
                    } else {
                        $value
                    }
                }
            }

        # Extended information
        $extendedInfo = $allProperties | 
            Where-Object { 
                $value = $computerInfo.($_.Name)
                $_.Name -notin $coreProperties -and
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
        return @{
            Core = $coreInfo
            Extended = $extendedInfo
        }
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

        # Run ping test with timeout parameter
        $pingParams = @{
            ComputerName = $hostname
            Count = 2
            BufferSize = 32
            Quiet = $true
        }
        
        # Add timeout parameter if available in current PowerShell version
        if ((Get-Command Test-Connection).Parameters.ContainsKey('TimeoutSeconds')) {
            $pingParams['TimeoutSeconds'] = $Timeout
        }
        
        $pingResult = Test-Connection @pingParams

        # Run traceroute (limited to 15 hops for performance)
        $traceOutput = @()
        $fullTrace = @()
        try {
            $traceRoute = Test-NetConnection -ComputerName $hostname -TraceRoute -Hops 15 -WarningAction SilentlyContinue
            if ($traceRoute.TraceRoute) {
                $traceOutput = $traceRoute.TraceRoute
                $fullTrace = $traceRoute.TraceRoute
            }
        }
        catch {
            $traceOutput = @("Traceroute failed: $($_.Exception.Message)")
        }

        # Get certificate info for HTTPS URLs
        $certInfo = "N/A"
        if ($uri.Scheme -eq "https") {
            try {
                $req = [System.Net.HttpWebRequest]::Create($Endpoint)
                $req.Timeout = $Timeout * 1000
                $req.ServerCertificateValidationCallback = {$true}  # Ignore certificate errors
                
                try {
                    $response = $req.GetResponse()
                    $cert = $req.ServicePoint.Certificate
                    
                    if ($cert) {
                        $certDetails = @(
                            "Issuer: $($cert.Issuer)",
                            "Subject: $($cert.Subject)",
                            "Valid from: $($cert.GetEffectiveDateString())",
                            "Valid to: $($cert.GetExpirationDateString())",
                            "Serial: $($cert.GetSerialNumberString())"
                        ) -join " | "
                        $certInfo = $certDetails
                    }
                    
                    if ($response) { $response.Dispose() }
                }
                catch {
                    $certInfo = "Error getting certificate: $($_.Exception.Message)"
                }
            }
            catch {
                $certInfo = "Error accessing certificate: $($_.Exception.Message)"
            }
        }

        return @{
            Host = $hostname
            PingSuccessful = $pingResult
            TraceRoute = $traceOutput
            FullTraceRoute = $fullTrace
            CertificateInfo = $certInfo
        }
    }
    catch {
        return @{
            Host = "Unknown"
            PingSuccessful = $false
            TraceRoute = @("Error: $($_.Exception.Message)")
            FullTraceRoute = @()
            CertificateInfo = "N/A"
        }
    }
}

function Test-NetworkEndpoints {
    param (
        [string[]]$Endpoints,
        [hashtable]$Expected,
        [int]$Timeout = 10,
        [int]$MaxParallel = 5
    )

    Write-ProgressHelper -Activity "Testing network connectivity" -Status "Checking endpoints"

    try {
        # Create a thread-safe collection for results
        $results = [System.Collections.Concurrent.ConcurrentBag[PSObject]]::new()
        
        # Cache for system proxy to avoid repeatedly getting it
        $systemProxy = [System.Net.WebRequest]::GetSystemWebProxy()
        $defaultCredentials = [System.Net.CredentialCache]::DefaultNetworkCredentials
        
        # Create script block for testing a single endpoint
        $testEndpointScript = {
            param (
                [string]$Endpoint,
                [hashtable]$Expected,
                [int]$Timeout,
                [System.Net.IWebProxy]$SystemProxy,
                [System.Net.NetworkCredential]$ProxyCredentials
            )
            
            try {
                # Get ping and traceroute results first
                $pingCheck = Test-NetworkConnectivity -Endpoint $Endpoint -Timeout $Timeout

                # Create stopwatch for timing
                $sw = [System.Diagnostics.Stopwatch]::StartNew()

                try {
                    # Create and configure the request
                    $request = [System.Net.WebRequest]::Create($Endpoint)
                    $request.Method = "GET"
                    $request.Timeout = $Timeout * 1000
                    $request.AllowAutoRedirect = $false # Match curl behavior for redirects
                    $request.UserAgent = "AbsoluteDiagnostics/2.0"
                    $request.Proxy = $SystemProxy
                    $request.Proxy.Credentials = $ProxyCredentials

                    # Get the response
                    $response = $request.GetResponse()
                    $sw.Stop()
                    $statusCode = [int]$response.StatusCode
                    $statusDesc = $response.StatusDescription
                    $responseTime = $sw.ElapsedMilliseconds
                }
                catch [System.Net.WebException] {
                    $sw.Stop()
                    $responseTime = $sw.ElapsedMilliseconds
                    if ($_.Exception.Response) {
                        $statusCode = [int]$_.Exception.Response.StatusCode
                        $statusDesc = $_.Exception.Response.StatusDescription
                    }
                    else {
                        $statusCode = 0
                        $statusDesc = $_.Exception.Message
                    }
                }
                finally {
                    if ($response) { $response.Dispose() }
                }

                $expectedStatus = if ($Expected.ContainsKey($Endpoint)) { $Expected[$Endpoint] } else { "200" }
                $statusMatch = $expectedStatus -split ' or ' | Where-Object { $_ -eq $statusCode.ToString() } | Select-Object -First 1

                return [PSCustomObject]@{
                    URL = $Endpoint
                    Status = if ($statusMatch) { "Pass" } else { "Fail" }
                    Code = $statusCode
                    Description = if ([string]::IsNullOrEmpty($statusDesc)) { "No response" } else { $statusDesc }
                    Expected = $expectedStatus
                    ResponseTime = $responseTime
                    PingStatus = if ($pingCheck.PingSuccessful) { "Success" } else { "Failed" }
                    TraceRoute = if ($pingCheck.TraceRoute) { $pingCheck.TraceRoute -join " -> " } else { "N/A" }
                    FullTraceRoute = $pingCheck.FullTraceRoute
                    CertificateInfo = $pingCheck.CertificateInfo
                }
            }
            catch {
                return [PSCustomObject]@{
                    URL = $Endpoint
                    Status = "Error"
                    Code = 0
                    Description = if ([string]::IsNullOrEmpty($_.Exception.Message)) { "Unknown error" } else { $_.Exception.Message }
                    Expected = if ($Expected.ContainsKey($Endpoint)) { $Expected[$Endpoint] } else { "200" }
                    ResponseTime = 0
                    PingStatus = "Failed"
                    TraceRoute = "N/A"
                    FullTraceRoute = @()
                    CertificateInfo = "N/A"
                }
            }
        }
        
        # Check if running in PowerShell Core (supports parallel processing)
        $canRunParallel = $PSVersionTable.PSVersion.Major -ge 7
        
        if ($canRunParallel) {
            try {
                # Use ForEach-Object -Parallel in PowerShell 7+
                $parallelResults = $Endpoints | ForEach-Object -ThrottleLimit $MaxParallel -Parallel {
                    # Display progress in the parallel thread
                    Write-Host "Testing $_ ..." -ForegroundColor Cyan
                    
                    # Call the script block with parameters
                    & $using:testEndpointScript -Endpoint $_ -Expected $using:Expected -Timeout $using:Timeout -SystemProxy $using:systemProxy -ProxyCredentials $using:defaultCredentials
                }
                
                # Add all results to the concurrent bag
                foreach ($result in $parallelResults) {
                    $results.Add($result)
                }
            }
            catch {
                Write-Warning "Error in parallel processing: $_. Falling back to sequential processing."
                # Fall back to sequential processing
                $canRunParallel = $false
            }
        }
        
        # If parallel processing isn't available or failed, use sequential approach
        if (-not $canRunParallel) {
            $total = $Endpoints.Count
            $current = 0
            
            foreach ($endpoint in $Endpoints) {
                $current++
                $progressPercent = [math]::Round(($current / $total) * 100)
                Write-ProgressHelper -Activity "Testing network connectivity" -Status "Testing $endpoint ($current of $total)" -PercentComplete $progressPercent
                
                $result = & $testEndpointScript -Endpoint $endpoint -Expected $Expected -Timeout $Timeout -SystemProxy $systemProxy -ProxyCredentials $defaultCredentials
                $results.Add($result)
            }
        }

        Write-ProgressHelper -Activity "Testing network connectivity" -Status "Completed endpoint testing" -Completed
        return $results.ToArray() | Sort-Object URL
    }
    catch {
        Write-Warning "Failed to test network endpoints: $_"
        # Return empty array instead of throwing to allow script to continue
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
            $output = & $DDSNdtPath /server=resources.namequery.com 2>&1 | Out-String
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
                    # get child items once
                    Get-ChildItem -Path $path -Recurse -ErrorAction SilentlyContinue | ForEach-Object {
                        "## $($_.PSChildName)"
                        Get-ItemProperty -Path $_.PSPath -ErrorAction SilentlyContinue | Format-Table -AutoSize | Out-String
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

        # Create Excel package with better error handling
        try {
            $excel = New-Object OfficeOpenXml.ExcelPackage
        }
        catch {
            Write-Warning "Failed to initialize Excel package: $_"
            throw "Unable to create Excel report. Ensure ImportExcel module is properly installed."
        }

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

        # Network Results worksheet with enhanced traceroute details
        Write-ProgressHelper -Status "Adding network information" -PercentComplete 50
        $netWs = $excel.Workbook.Worksheets.Add("Network")
        $row = 1

        $netWs.Cells["A$row"].Value = "Network Connectivity Tests"
        $netWs.Cells["A$row:H$row"].Merge = $true
        $netWs.Cells["A$row:H$row"].Style.Font.Bold = $true
        $netWs.Cells["A$row:H$row"].Style.Font.Size = 14
        $row++

        $netWs.Cells["A$row"].Value = "URL"
        $netWs.Cells["B$row"].Value = "Status"
        $netWs.Cells["C$row"].Value = "Status Code"
        $netWs.Cells["D$row"].Value = "Description"
        $netWs.Cells["E$row"].Value = "Expected"
        $netWs.Cells["F$row"].Value = "Response Time (ms)"
        $netWs.Cells["G$row"].Value = "Ping Status"
        $netWs.Cells["H$row"].Value = "Certificate Info"
        $netWs.Cells["A$row:H$row"].Style.Font.Bold = $true
        $row++

        foreach ($item in $NetResults) {
            $netWs.Cells["A$row"].Value = $item.URL
            $netWs.Cells["B$row"].Value = $item.Status
            $netWs.Cells["C$row"].Value = $item.Code
            $netWs.Cells["D$row"].Value = $item.Description
            $netWs.Cells["E$row"].Value = $item.Expected
            $netWs.Cells["F$row"].Value = $item.ResponseTime
            $netWs.Cells["G$row"].Value = $item.PingStatus
            $netWs.Cells["H$row"].Value = $item.CertificateInfo

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

        # Detailed traceroute information in a separate sheet
        if ($NetResults | Where-Object { $_.TraceRoute }) {
            $traceWs = $excel.Workbook.Worksheets.Add("TraceRoute")
            $row = 1

            $traceWs.Cells["A$row"].Value = "Detailed Traceroute Information"
            $traceWs.Cells["A$row:C$row"].Merge = $true
            $traceWs.Cells["A$row:C$row"].Style.Font.Bold = $true
            $traceWs.Cells["A$row:C$row"].Style.Font.Size = 14
            $row++

            $traceWs.Cells["A$row"].Value = "Endpoint"
            $traceWs.Cells["B$row"].Value = "Hop"
            $traceWs.Cells["C$row"].Value = "IP Address"
            $traceWs.Cells["A$row:C$row"].Style.Font.Bold = $true
            $row++

            foreach ($item in $NetResults) {
                if ($item.FullTraceRoute) {
                    $hopNumber = 1
                    foreach ($hop in $item.FullTraceRoute) {
                        $traceWs.Cells["A$row"].Value = $item.URL
                        $traceWs.Cells["B$row"].Value = $hopNumber
                        $traceWs.Cells["C$row"].Value = $hop
                        $hopNumber++
                        $row++
                    }
                    # Add a blank row between different endpoints
                    $row++
                }
            }
            
            $traceWs.Cells.AutoFitColumns()
        }

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
                # Get first few lines of content as summary (safely handling large files)
                try {
                    $summary = $log.Content -split "`n" | Select-Object -First 5 | Out-String
                    $ctesWs.Cells["D$row"].Value = if ($summary) { $summary.Trim() } else { "N/A" }
                }
                catch {
                    $ctesWs.Cells["D$row"].Value = "Error reading log content: $($_.Exception.Message)"
                }
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
            Write-ProgressHelper -Status "Adding DDSNdt logs" -PercentComplete 85
            try {
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
            } catch {
                Write-Warning "Failed to add DDSNdt logs: $_"
            }
        }

        # Add summary page as the first worksheet
        $summaryWs = $excel.Workbook.Worksheets.Add("Summary")
        $excel.Workbook.Worksheets.MoveToStart("Summary")
        
        $row = 1
        $summaryWs.Cells["A$row"].Value = "Absolute Agent Diagnostics Summary"
        $summaryWs.Cells["A$row:C$row"].Merge = $true
        $summaryWs.Cells["A$row:C$row"].Style.Font.Bold = $true
        $summaryWs.Cells["A$row:C$row"].Style.Font.Size = 16
        $row++

        $summaryWs.Cells["A$row"].Value = "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        $summaryWs.Cells["A$row:C$row"].Merge = $true
        $row += 2

        $summaryWs.Cells["A$row"].Value = "System Info"
        $summaryWs.Cells["A$row"].Style.Font.Bold = $true
        $row++
        $summaryWs.Cells["A$row"].Value = "Computer Name"
        $computerName = ($SystemInfo | Where-Object { $_.Property -eq 'CsName' }).Value
        $summaryWs.Cells["B$row"].Value = $computerName
        $row++
        $summaryWs.Cells["A$row"].Value = "Operating System"
        $osInfo = ($SystemInfo | Where-Object { $_.Property -eq 'OsName' }).Value
        $summaryWs.Cells["B$row"].Value = $osInfo
        $row += 2

        $summaryWs.Cells["A$row"].Value = "Network Tests"
        $summaryWs.Cells["A$row"].Style.Font.Bold = $true
        $row++
        $passCount = ($NetResults | Where-Object { $_.Status -eq 'Pass' }).Count
        $failCount = ($NetResults | Where-Object { $_.Status -eq 'Fail' }).Count
        $errorCount = ($NetResults | Where-Object { $_.Status -eq 'Error' }).Count
        $totalTests = $NetResults.Count
        
        $summaryWs.Cells["A$row"].Value = "Tests Passed"
        $summaryWs.Cells["B$row"].Value = "$passCount of $totalTests"
        if ($passCount -eq $totalTests) {
            $summaryWs.Cells["B$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $summaryWs.Cells["B$row"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGreen)
        }
        elseif ($passCount -eq 0) {
            $summaryWs.Cells["B$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $summaryWs.Cells["B$row"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightCoral)
        }
        elseif ($passCount -lt ($totalTests / 2)) {
            $summaryWs.Cells["B$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $summaryWs.Cells["B$row"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightYellow)
        }
        $row++
        
        # Add the failed tests count information
        $summaryWs.Cells["A$row"].Value = "Tests Failed"
        $summaryWs.Cells["B$row"].Value = "$failCount of $totalTests"
        if ($failCount -gt 0) {
            $summaryWs.Cells["B$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $summaryWs.Cells["B$row"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightCoral)
        }
        $row++
        
        # Add the error count information
        $summaryWs.Cells["A$row"].Value = "Tests with Errors"
        $summaryWs.Cells["B$row"].Value = "$errorCount of $totalTests"
        if ($errorCount -gt 0) {
            $summaryWs.Cells["B$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $summaryWs.Cells["B$row"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightYellow)
        }
        $row += 1

        $summaryWs.Cells["A$row"].Value = "Services"
        $summaryWs.Cells["A$row"].Style.Font.Bold = $true
        $row++
        $runningServices = ($ServiceStatus | Where-Object { $_.Status -eq 'Running' }).Count
        $stoppedServices = ($ServiceStatus | Where-Object { $_.Status -eq 'Stopped' }).Count
        $notFoundServices = ($ServiceStatus | Where-Object { $_.Status -eq 'Not Found' }).Count
        $totalServices = $ServiceStatus.Count

        $summaryWs.Cells["A$row"].Value = "Running Services"
        $summaryWs.Cells["B$row"].Value = "$runningServices of $totalServices"
        if ($runningServices -eq $totalServices) {
            $summaryWs.Cells["B$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $summaryWs.Cells["B$row"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGreen)
        }
        elseif ($runningServices -eq 0) {
            $summaryWs.Cells["B$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $summaryWs.Cells["B$row"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightCoral)
        }
        $row++
        
        $summaryWs.Cells["A$row"].Value = "Stopped Services"
        $summaryWs.Cells["B$row"].Value = "$stoppedServices of $totalServices"
        if ($stoppedServices -gt 0) {
            $summaryWs.Cells["B$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $summaryWs.Cells["B$row"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightYellow)
        }
        $row++
        
        $summaryWs.Cells["A$row"].Value = "Not Found Services"
        $summaryWs.Cells["B$row"].Value = "$notFoundServices of $totalServices"
        if ($notFoundServices -gt 0) {
            $summaryWs.Cells["B$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
            $summaryWs.Cells["B$row"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightCoral)
        }
        $row++
        
        $summaryWs.Cells.AutoFitColumns()

        # Save the Excel report with better error handling
        try {
            $excel.SaveAs($ExcelPath)
            Write-Verbose "Excel report saved to: $ExcelPath"
        }
        catch {
            Write-Warning "Failed to save Excel report to $ExcelPath $($_)"
            # Try an alternative path in temp directory as fallback
            $fallbackPath = Join-Path ([System.IO.Path]::GetTempPath()) ("AbsoluteDiagnosticsReport_" + (Get-Date -Format 'yyyyMMddHHmmss') + ".xlsx")
            try {
                $excel.SaveAs($fallbackPath)
                Write-Warning "Excel report saved to fallback location: $fallbackPath"
                return $true
            }
            catch {
                Write-Warning "Failed to save Excel report to fallback location: $_"
                return $false
            }
        }

        Write-ProgressHelper -Activity "Creating Excel report" -Completed
        return $true
    }
    catch {
        Write-Warning "Failed to create Excel report: $_"
        return $false
    }
    finally {
        # Ensure Excel package is properly disposed
        if ($excel) {
            try {
                $excel.Dispose()
            }
            catch {
                Write-Warning "Error disposing Excel package: $_"
            }
        }
    }
}

function Get-CtesLogs {
    param (
        [string]$LogPath = "C:\ProgramData\CTES\logs",
        [int]$MaxLogSizeMB = 10, # Skip reading full content of files larger than this size
        [int]$MaxPreviewLines = 200 # For large files, only show first and last lines
    )

    try {
        if (-not (Test-Path $LogPath)) {
            Write-Verbose "CTES logs path not found: $LogPath"
            return @()
        }

        # Get all log files
        $logFiles = Get-ChildItem -Path $LogPath -File -Recurse -ErrorAction SilentlyContinue
        
        # Process files in batches to improve performance
        $batchSize = 10
        $totalFiles = $logFiles.Count
        $processedCount = 0
        $logs = @()
        
        for ($i = 0; $i -lt $totalFiles; $i += $batchSize) {
            $batch = $logFiles[$i..([Math]::Min($i + $batchSize - 1, $totalFiles - 1))]
            
            $batchResults = foreach ($file in $batch) {
                $processedCount++
                if ($processedCount % 5 -eq 0) {
                    Write-Verbose "Processing log file $processedCount of ${totalFiles}: $($file.Name)"
                }
                
                $fileSizeMB = $file.Length / 1MB
                $content = $null
                
                # For large files, only get preview
                if ($fileSizeMB -gt $MaxLogSizeMB) {
                    try {
                        # Get first and last lines only
                        $firstLines = Get-Content -Path $file.FullName -TotalCount ($MaxPreviewLines / 2) -ErrorAction SilentlyContinue
                        $lastLines = Get-Content -Path $file.FullName -Tail ($MaxPreviewLines / 2) -ErrorAction SilentlyContinue
                        
                        if ($firstLines -or $lastLines) {
                            $preview = @()
                            if ($firstLines) { $preview += $firstLines }
                            $preview += "..."
                            $preview += "[File truncated, total size: $([Math]::Round($fileSizeMB, 2)) MB]"
                            $preview += "..."
                            if ($lastLines) { $preview += $lastLines }
                            $content = $preview -join "`r`n"
                        }
                        else {
                            $content = "[Unable to read file content, file may be locked or too large ($([Math]::Round($fileSizeMB, 2)) MB)]"
                        }
                    }
                    catch {
                        $content = "[Error reading large file: $($_.Exception.Message)]"
                    }
                }
                else {
                    # For smaller files, get full content
                    try {
                        $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
                        if ($null -eq $content) { $content = "[Empty file]" }
                    }
                    catch {
                        $content = "[Error reading file: $($_.Exception.Message)]"
                    }
                }
                
                [PSCustomObject]@{
                    Name = $file.Name
                    Path = $file.FullName
                    Content = $content
                    LastWriteTime = $file.LastWriteTime
                    SizeMB = [Math]::Round($fileSizeMB, 2)
                }
            }
            
            $logs += $batchResults
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
    $sysInfo = Get-SystemInfo
    $sysInfoResults = $sysInfo.Core
    $extendedInfo = $sysInfo.Extended

    # Check Absolute services
    $serviceResults = Test-Services

    # Test network connectivity
    $networkResults = Test-NetworkEndpoints -Endpoints $EndpointsToCheck -Expected $ExpectedStatusCodes -Timeout $NetworkTimeout -MaxParallel $MaxParallelTasks

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
        -ExtendedInfo $extendedInfo `
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
            -ExtendedInfo $extendedInfo `
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
