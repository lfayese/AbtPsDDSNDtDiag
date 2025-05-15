<#
.SYNOPSIS
Absolute Agent Diagnostic Collector

.DESCRIPTION
Runs Absolute agent diagnostics: system info, endpoints, CTES logs, AbtPS/DDSNdt, ZIP/Excel output.

.EXAMPLE
.\CheckNdtRpcnet.ps1 -VerboseLog
.\CheckNdtRpcnet.ps1 -OutputDirectory "C:\Temp\Diag" -SkipZip
.\CheckNdtRpcnet.ps1 -SkipExcel

.NOTES
Enhanced with additional diagnostics, error handling, and performance optimizations.
#>

[CmdletBinding()]
param(
    [int]$CallTimeoutSec = 60,
    [switch]$SkipExcel,
    [switch]$SkipZip,
    [switch]$SkipHtml,
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
        "https://resources.namequery.com/downloads/public/bin/Windows/CTES/HDC/2.0.15.13/CtHWiPrvPackage.zip" = "200"
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
    Write-ProgressHelper -Activity "Collecting system information" -Status "Gathering basic system details"

    try {
        $bios = Get-CimInstance Win32_BIOS
        $sys = Get-CimInstance Win32_ComputerSystem
        $os = Get-CimInstance Win32_OperatingSystem

        $core = [PSCustomObject]@{
            BIOSSerial = $bios.SerialNumber
            ComputerName = $sys.Name
            Manufacturer = $sys.Manufacturer
            Model = $sys.Model
            OS = "$($os.Caption) $($os.Version)"
        }

        # Convert core info to key-value pairs for consistent reporting
        $coreFormatted = $core | Get-Member -MemberType Properties |
            Select-Object @{Name='Property';Expression={$_.Name}},
                          @{Name='Value';Expression={$core.($_.Name)}}

        Write-ProgressHelper -Status "Gathering extended system information" -PercentComplete 50

        try {
            $extended = Get-ComputerInfo

            # Convert extended info to key-value pairs
            $extendedFormatted = $extended | Get-Member -MemberType Properties |
                Where-Object { $_.Name -ne 'PSComputerName' } |
                Select-Object @{Name='Property';Expression={$_.Name}},
                              @{Name='Value';Expression={$extended.($_.Name)}}
        }
        catch {
            Write-Warning "Unable to retrieve extended system info: $_"
            $extendedFormatted = @()
            $extended = @()
        }

        Write-ProgressHelper -Activity "Collecting system information" -Completed
        return @{
            Core = $core
            CoreFormatted = $coreFormatted
            Extended = $extended
            ExtendedFormatted = $extendedFormatted
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

                if ($webEx.Response -ne $null) {
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

function Copy-AdditionalLogs {
    param (
        [string]$OutputFolder
    )

    Write-ProgressHelper -Activity "Collecting additional logs" -Status "Searching for Absolute logs"

    try {
        $logLocations = @(
            "C:\ProgramData\CTES\Logs"
        )

        $foundLogs = $false

        foreach ($location in $logLocations) {
            if (Test-Path $location) {
                $foundLogs = $true
                $destFolder = Join-Path $OutputFolder (Split-Path $location -Leaf)

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
        [array]$ServiceStatus
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
            $sysWs.Cells["B$row"].Value = $item.Value
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
            $sysWs.Cells["B$row"].Value = $item.Value
            $row++
        }

        $sysWs.Cells.AutoFitColumns()

        # Network Results worksheet
        Write-ProgressHelper -Status "Adding network information" -PercentComplete 50
        $netWs = $excel.Workbook.Worksheets.Add("Network")
        $row = 1

        $netWs.Cells["A$row"].Value = "Network Connectivity Tests"
        $netWs.Cells["A$row:F$row"].Merge = $true
        $netWs.Cells["A$row:F$row"].Style.Font.Bold = $true
        $netWs.Cells["A$row:F$row"].Style.Font.Size = 14
        $row++

        $netWs.Cells["A$row"].Value = "URL"
        $netWs.Cells["B$row"].Value = "Status"
        $netWs.Cells["C$row"].Value = "Status Code"
        $netWs.Cells["D$row"].Value = "Description"
        $netWs.Cells["E$row"].Value = "Expected"
        $netWs.Cells["F$row"].Value = "Response Time (ms)"
        $netWs.Cells["A$row:F$row"].Style.Font.Bold = $true
        $row++

        foreach ($item in $NetResults) {
            $netWs.Cells["A$row"].Value = $item.URL
            $netWs.Cells["B$row"].Value = $item.Status
            $netWs.Cells["C$row"].Value = $item.Code
            $netWs.Cells["D$row"].Value = $item.Description
            $netWs.Cells["E$row"].Value = $item.Expected
            $netWs.Cells["F$row"].Value = $item.ResponseTime

            # Colorize status
            if ($item.Status -eq "Pass") {
                $netWs.Cells["B$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                $netWs.Cells["B$row"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGreen)
            } elseif ($item.Status -eq "Fail") {
                $netWs.Cells["B$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                $netWs.Cells["B$row"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightCoral)
            } elseif ($item.Status -eq "Error") {
                $netWs.Cells["B$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                $netWs.Cells["B$row"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightYellow)
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
            if ($item.Status -eq "Running") {
                $svcWs.Cells["C$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                $svcWs.Cells["C$row"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGreen)
            } elseif ($item.Status -eq "Stopped") {
                $svcWs.Cells["C$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                $svcWs.Cells["C$row"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightCoral)
            } elseif ($item.Status -eq "Not Found") {
                $svcWs.Cells["C$row"].Style.Fill.PatternType = [OfficeOpenXml.Style.ExcelFillStyle]::Solid
                $svcWs.Cells["C$row"].Style.Fill.BackgroundColor.SetColor([System.Drawing.Color]::LightGray)
            }

            $row++
        }

        $svcWs.Cells.AutoFitColumns()

        # Diagnostics Logs worksheet
        Write-ProgressHelper -Status "Adding diagnostics logs" -PercentComplete 90

        # AbtPS Logs
        $abtWs = $excel.Workbook.Worksheets.Add("AbtPS Logs")
        $row = 1

        $abtWs.Cells["A$row"].Value
