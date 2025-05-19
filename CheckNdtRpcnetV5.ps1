<#
.SYNOPSIS
Absolute Agent Diagnostic Collector

.DESCRIPTION
Runs Absolute agent diagnostics: system info, endpoints, CTES logs, AbtPS/DDSNdt, HTML/Excel output.

.EXAMPLE
.\CheckNdtRpcnet.ps1
.\CheckNdtRpcnet.ps1 -GenerateExcel
#>

[CmdletBinding()]
param(
    [int]$CallTimeoutSec = 60,
    [switch]$GenerateExcel,
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
        "https://resources.namequery.com/downloads/public/bin/Windows/CTES/HDC/2.0.15.13/CtHWiPrvPackage.zip" = "200 or 404"
    },
    [string]$OutputDirectory = $PSScriptRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($VerboseLog) { $VerbosePreference = 'Continue' }

function New-DiagnosticsFolder {
    $timestamp = Get-Date -Format 'yyyyMMddHHmmss'
    $folder = Join-Path $OutputDirectory "AbsoluteDiagnostics$timestamp"
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    return $folder
}

function Get-SystemInfo {
    Write-Host "🔍 Collecting System Info..."
    $info = Get-ComputerInfo
    $filtered = $info.PSObject.Properties | Where-Object {
        $null -ne $_.Value -and $_.Value.ToString().Trim() -ne ''
    }
    return $filtered | ForEach-Object {
        [PSCustomObject]@{
            Property = $_.Name
            Value    = $_.Value
        }
    }
}

function Invoke-AbtPSDiagnostics {
    param (
        [string]$AbtPath,
        [int]$TimeoutSec
    )
    $log = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path $AbtPath)) {
        $log.Add("❌ AbtPS.exe not found.")
        return $log
    }
    $cmds = @("-Status", "-Version", "-ESN", "-StartCall", "-IsCalling")
    $start = Get-Date
    foreach ($cmd in $cmds) {
        $log.Add("> $cmd")
        try {
            & $AbtPath $cmd 2>&1 | ForEach-Object { $log.Add($_) }
        } catch {
            $log.Add("Error running $cmd : $($_.Exception.Message)")
        }
        if ($cmd -eq "-IsCalling") {
            while ((Get-Date) - $start -lt ([TimeSpan]::FromSeconds($TimeoutSec))) {
                Start-Sleep -Seconds 5
                $result = & $AbtPath -IsCalling
                $log.Add($result)
                if ($result -match "not calling") { break }
            }
        }
    }
    return $log
}
function Invoke-DDSNdtDiagnostics {
    param([string]$DDSPath)
    $log = New-Object System.Collections.Generic.List[string]
    if (-not (Test-Path $DDSPath)) {
        $log.Add("❌ DDSNdt.exe not found.")
        return $log
    }
    try {
        $output = & $DDSPath 2>&1
        $log.AddRange($output)
    } catch {
        $log.Add("Error running DDSNdt: $($_.Exception.Message)")
    }
    return $log
}

function Copy-CTESLogs {
    param([string]$TargetPath)
    $source = "C:\ProgramData\CTES\logs"
    if (Test-Path $source) {
        Copy-Item "$source\*" -Destination $TargetPath -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "📁 CTES logs copied to: $TargetPath"
    } else {
        Write-Host "⚠️ CTES log source not found."
    }
}

function Test-PortConnection {
    param($Hostname, [int[]]$Ports = @(80,443,11364))
    $results = @()
    foreach ($port in $Ports) {
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $tcp.Connect($Hostname, $port)
            $tcp.Close()
            $results += "${Hostname} port ${port}: Open"
        } catch {
            $results += "${Hostname} port ${port}: Closed"
        }
    }
    return $results
}

function Test-IPRange {
    param([string[]]$IPs)
    $validIPv4 = [IPAddress]::Parse("199.91.188.0")
    $maskIPv4 = [IPAddress]::Parse("255.255.252.0")
    $results = @()
    foreach ($ipStr in $IPs) {
        try {
            $ip = [IPAddress]::Parse($ipStr)
            if ($ip.AddressFamily -eq 'InterNetwork') {
                $ipBytes = $ip.GetAddressBytes()
                $netBytes = $validIPv4.GetAddressBytes()
                $maskBytes = $maskIPv4.GetAddressBytes()
                $match = $true
                for ($i = 0; $i -lt 4; $i++) {
                    if (($ipBytes[$i] -band $maskBytes[$i]) -ne ($netBytes[$i] -band $maskBytes[$i])) {
                        $match = $false; break
                    }
                }
                $results += "$ipStr is " + ($(if ($match) { "✅ in range" } else { "❌ out of range" }))
            } elseif ($ip.AddressFamily -eq 'InterNetworkV6') {
                $results += "$ipStr is IPv6 (manual check required)"
            }
        } catch {
            $results += "$ipStr - invalid IP"
        }
    }
    return $results
}

function Resolve-EndpointInfo {
    param([string]$Url)
    $uri = [uri]$Url
    $hostname = $uri.Host
    $ips = @()
    try {
        $ips = [System.Net.Dns]::GetHostAddresses($hostname) | Select-Object -ExpandProperty IPAddressToString
    } catch {
        $ips = @("Failed DNS lookup")
    }

    $portResults = Test-PortConnection -Hostname $hostname
    $ipResults = Test-IPRange -IPs $ips

    return [PSCustomObject]@{
        Hostname      = $hostname
        IPs           = $ips -join ', '
        IPRangeCheck  = $ipResults -join '; '
        PortsScanned  = $portResults -join '; '
        DNS_OK        = ($ips -notcontains "Failed DNS lookup")
    }
}

function Test-HttpStatus {
    param([string]$Url, [string]$Expected)
    try {
        $resp = Invoke-WebRequest -Uri $Url -UseBasicParsing -Method Head -TimeoutSec 10
        $actualCode = $resp.StatusCode
        $status = $actualCode.ToString()
    } catch {
        if ($_.Exception.Response) {
            $actualCode = $_.Exception.Response.StatusCode
            $status = $actualCode.ToString()
        } else {
            $status = "N/A"
        }
    }

    $match = ($Expected -split " or ") -contains $status
    return [PSCustomObject]@{
        URL      = $Url
        Expected = $Expected
        Actual   = $status
        Status   = if ($match) { "Pass" } else { "Fail" }
    }
}
function Export-Html {
    param (
        [string]$Path,
        [array]$SystemInfo,
        [array]$HttpChecks,
        [array]$AbtLog,
        [array]$DDSLog,
        [array]$CTESLog,
        [array]$EndpointInfo
    )

    $html = @()
    $html += "<html><head><style>
        body{font-family:Arial;padding:20px;background:#f5f5f5;}
        h2{color:#00447c;} table{border-collapse:collapse;width:100%;margin-bottom:20px;}
        th,td{border:1px solid #ccc;padding:8px;} th{background:#00447c;color:white;}
        .ok{background:#dff0d8;} .fail{background:#f2dede;} .warn{background:#fcf8e3;}
        details{margin-bottom:10px}
    </style></head><body>"
    $html += "<h1>Absolute Diagnostics Report</h1><p><i>Generated: $(Get-Date)</i></p>"

    $html += "<h2>System Info</h2><table><tr><th>Property</th><th>Value</th></tr>"
    foreach ($row in $SystemInfo) {
        $html += "<tr><td>$($row.Property)</td><td>$($row.Value)</td></tr>"
    }
    $html += "</table>"

    $html += "<h2>Endpoint Status</h2><table><tr><th>URL</th><th>Expected</th><th>Actual</th><th>Status</th></tr>"
    foreach ($r in $HttpChecks) {
        $cls = if ($r.Status -eq "Pass") { "ok" } else { "fail" }
        $html += "<tr class='$cls'><td>$($r.URL)</td><td>$($r.Expected)</td><td>$($r.Actual)</td><td>$($r.Status)</td></tr>"
    }
    $html += "</table>"

    $html += "<h2>Endpoint Connectivity</h2><table><tr><th>Host</th><th>IP(s)</th><th>IP Range Check</th><th>Port Scan</th><th>DNS</th></tr>"
    foreach ($r in $EndpointInfo) {
        $dns = if ($r.DNS_OK) { "OK" } else { "FAIL" }
        $cls = if ($r.DNS_OK) { "ok" } else { "warn" }
        $html += "<tr class='$cls'><td>$($r.Hostname)</td><td>$($r.IPs)</td><td>$($r.IPRangeCheck)</td><td>$($r.PortsScanned)</td><td>$dns</td></tr>"
    }
    $html += "</table>"

    $html += "<h2>Diagnostics Logs</h2>"
    $html += "<details><summary><b>AbtPS Diagnostics</b></summary><pre>$($AbtLog -join "`n")</pre></details>"
    $html += "<details><summary><b>DDSNdt Diagnostics</b></summary><pre>$($DDSLog -join "`n")</pre></details>"
    $html += "<details><summary><b>CTES Logs</b></summary><pre>$($CTESLog -join "`n")</pre></details>"

    $html += "<hr><p><i>Report generated by CheckNdtRpcnet.ps1</i></p>"
    $html += "</body></html>"

    $html | Set-Content -Path $Path -Encoding UTF8
    Write-Host "📄 HTML report created: $Path"
}

function Export-ExcelReport {
    param(
        [string]$Path,
        [array]$SystemInfo,
        [array]$HttpChecks,
        [array]$EndpointInfo,
        [array]$AbtPSLog,
        [array]$DDSLog,
        [array]$CTESLog
    )

    try {
        if (-not (Get-Module -Name ImportExcel -ListAvailable)) {
            Import-Module "$PSScriptRoot\Modules\ImportExcel" -Force
        }

        $SystemInfo | Export-Excel -Path $Path -WorksheetName "SystemInfo" -AutoSize

        $HttpChecks | Export-Excel -Path $Path -WorksheetName "HTTP_Status" -AutoSize -Append

        $EndpointInfo | Export-Excel -Path $Path -WorksheetName "EndpointConnectivity" -AutoSize -Append

        $AbtPSLog | ForEach-Object { [PSCustomObject]@{ Line = $_ } } |
            Export-Excel -Path $Path -WorksheetName "AbtPS_Log" -AutoSize -Append

        $DDSLog | ForEach-Object { [PSCustomObject]@{ Line = $_ } } |
            Export-Excel -Path $Path -WorksheetName "DDSNdt_Log" -AutoSize -Append

        $CTESLog | ForEach-Object { [PSCustomObject]@{ Line = $_ } } |
            Export-Excel -Path $Path -WorksheetName "CTES_Logs" -AutoSize -Append

        Write-Host "📊 Excel report created: $Path"
    } catch {
        Write-Warning "Excel export failed: $($_.Exception.Message)"
    }
}

function Compress-Diagnostics {
    param([string]$FolderPath)

    try {
        $zipPath = "$FolderPath.zip"
        Compress-Archive -Path $FolderPath -DestinationPath $zipPath -Force
        Write-Host "🗜️ Diagnostics zipped to: $zipPath"
    } catch {
        Write-Warning "Failed to compress diagnostics folder: $_"
    }
}

# ---------- MAIN EXECUTION FLOW ----------

Write-Host "🚀 Starting Absolute Diagnostics..." -ForegroundColor Cyan

# Tool Paths
$abtPath = Join-Path $PSScriptRoot "AbtPS.exe"
$ddsPath = Join-Path $PSScriptRoot "DDSNdt.exe"
if (-not (Test-Path $abtPath)) { throw "AbtPS.exe is missing in script folder." }
if (-not (Test-Path $ddsPath)) { throw "DDSNdt.exe is missing in script folder." }

# Collect data
$sysInfoRaw = Get-SystemInfo
$abtLog = Invoke-AbtPSDiagnostics -AbtPath $abtPath -TimeoutSec $CallTimeoutSec
$ddsLog = Invoke-DDSNdtDiagnostics -DDSPath $ddsPath

# Collect CTES logs
$copiedCTESLog = @()
$ctesLogPath = "C:\ProgramData\CTES\logs"
if (Test-Path $ctesLogPath) {
    $dest = Join-Path $DiagFolder "CTES_Logs"
    Copy-Item -Path "$ctesLogPath\*" -Destination $dest -Recurse -Force -ErrorAction SilentlyContinue
    $copiedCTESLog = Get-ChildItem -Path $dest -Recurse | ForEach-Object { "[$($_.Name)]`n$(Get-Content $_.FullName -Raw)" }
}

# Test endpoints
$endpointInfo = $EndpointsToCheck | ForEach-Object { Resolve-EndpointInfo $_ }
$httpChecks   = $EndpointsToCheck | ForEach-Object { Test-HttpStatus -Url $_ -Expected $ExpectedStatusCodes[$_] }

# HTML export (default)
if (-not $SkipHtml) {
    $htmlPath = Join-Path $DiagFolder "DiagnosticsReport.html"
    Export-Html -Path $htmlPath -SystemInfo $sysInfoRaw -HttpChecks $httpChecks -AbtLog $abtLog -DDSLog $ddsLog -CTESLog $copiedCTESLog -EndpointInfo $endpointInfo
}

# Excel export (optional)
if ($GenerateExcel) {
    $excelPath = Join-Path $DiagFolder "DiagnosticsReport.xlsx"
    Export-ExcelReport -Path $excelPath -SystemInfo $sysInfoRaw -HttpChecks $httpChecks -EndpointInfo $endpointInfo -AbtPSLog $abtLog -DDSLog $ddsLog -CTESLog $copiedCTESLog
}

# ZIP export (optional)
if (-not $SkipZip) {
    Compress-Diagnostics -FolderPath $DiagFolder
}

Stop-Transcript
Write-Host "`n✅ Diagnostics complete. Output: $DiagFolder" -ForegroundColor Green
Start-Process "explorer.exe" -ArgumentList "`"$DiagFolder`""