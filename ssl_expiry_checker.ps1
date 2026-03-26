#Requires -Version 5.1
<#
.SYNOPSIS
    Checks SSL certificate expiry for FQDNs listed in a TXT or CSV file.
    Port can be specified per entry directly in the input file.
.DESCRIPTION
    Reads FQDN:PORT pairs from a plain text file or CSV file, connects to each
    host on the specified port over TLS, retrieves the certificate expiry date,
    and outputs a single list sorted by days remaining (soonest expiring first).
    The report file is automatically named ssl_expiry_report_YYYYMMDD.txt
    and saved in the same folder as the input file, unless -OutputFolder is set.
    No third-party modules or Excel required.
.PARAMETER InputFile
    Path to the input file.
    TXT format  - one entry per line, port is optional:
        portal01.zone-a.company.com:443
        portal02.zone-a.company.com:5480
        portal03.zone-a.company.com:9200
        portal04.zone-a.company.com        <- uses -DefaultPort if no port given
    CSV format  - a column for FQDN and an optional column for port:
        fqdn,port
        portal01.zone-a.company.com,443
        portal02.zone-a.company.com,5480
    Lines starting with # and blank lines are always skipped.
.PARAMETER OutputFolder
    Folder where the dated report file will be saved.
    Default: same folder as the input file.
.PARAMETER DefaultPort
    Port to use when no port is specified on a line. Default: 443
.PARAMETER CsvColumn
    Column header for FQDNs in a CSV file. Default: fqdn
.PARAMETER CsvPortColumn
    Column header for ports in a CSV file. Default: port
.PARAMETER CsvDelimiter
    Delimiter used in the CSV file. Default: , (comma)
.PARAMETER TimeoutSeconds
    TCP connection timeout per host/port combination. Default: 10
.PARAMETER Threads
    Number of parallel runspaces. Default: 30
.PARAMETER WarnCriticalDays
    Days threshold below which a cert is flagged CRITICAL. Default: 245
.PARAMETER WarnWarningDays
    Days threshold below which a cert is flagged WARNING. Default: 365
.EXAMPLE
    .\Check-SSLExpiry.ps1 -InputFile "D:\SSL_Expiry_Checker\fqdns.txt" -WarnCriticalDays 245 -WarnWarningDays 365
    # Saves report as: D:\SSL_Expiry_Checker\ssl_expiry_report_20260306.txt
.EXAMPLE
    .\Check-SSLExpiry.ps1 -InputFile "D:\SSL_Expiry_Checker\fqdns.txt" -OutputFolder "D:\SSL_Expiry_Checker\Reports"
    # Saves report as: D:\SSL_Expiry_Checker\Reports\ssl_expiry_report_20260306.txt
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$InputFile,

    [string]  $OutputFolder     = "",
    [int]     $DefaultPort      = 443,
    [string]  $CsvColumn        = "fqdn",
    [string]  $CsvPortColumn    = "port",
    [string]  $CsvDelimiter     = ",",
    [int]     $TimeoutSeconds   = 10,
    [int]     $Threads          = 30,
    [int]     $WarnCriticalDays = 245,
    [int]     $WarnWarningDays  = 365
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Build dated output path ──────────────────────────────────────────────────
$dateStamp         = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$reportName        = "ssl_expiry_report_$dateStamp.txt"
$htmlReportName    = "ssl_expiry_report_$dateStamp.html"
$generatedDisplay  = $dateStamp

if ($OutputFolder -ne "") {
    if (-not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder | Out-Null
    }
    $resolvedOutputFolder = (Resolve-Path $OutputFolder).Path
    $OutputFile     = Join-Path $resolvedOutputFolder $reportName
    $HtmlOutputFile = Join-Path $resolvedOutputFolder $htmlReportName
} else {
    $inputFolder    = Split-Path (Resolve-Path $InputFile).Path -Parent
    $OutputFile     = Join-Path $inputFolder $reportName
    $HtmlOutputFile = Join-Path $inputFolder $htmlReportName
}

# ── Read FQDN:PORT pairs from TXT or CSV ─────────────────────────────────────
function Read-FQDNs {
    param(
        [string]$Path,
        [string]$Column,
        [string]$PortColumn,
        [string]$Delimiter,
        [int]$FallbackPort
    )

    $fullPath  = (Resolve-Path $Path).Path
    $extension = [System.IO.Path]::GetExtension($fullPath).ToLower()
    $jobs      = [System.Collections.Generic.List[hashtable]]::new()

    switch ($extension) {

        ".txt" {
            Write-Host "  Format : Plain text  (FQDN or FQDN:PORT per line)"
            foreach ($line in [System.IO.File]::ReadAllLines($fullPath)) {
                $trimmed = $line.Trim()
                if ($trimmed -eq "" -or $trimmed.StartsWith("#")) { continue }

                $lastColon  = $trimmed.LastIndexOf(":")
                $parsedPort = 0
                if ($lastColon -gt 0 -and
                    [int]::TryParse($trimmed.Substring($lastColon + 1), [ref]$parsedPort) -and
                    $parsedPort -gt 0 -and $parsedPort -le 65535) {
                    $jobs.Add(@{ FQDN = $trimmed.Substring(0, $lastColon).Trim(); Port = $parsedPort })
                } else {
                    $jobs.Add(@{ FQDN = $trimmed; Port = $FallbackPort })
                }
            }
        }

        ".csv" {
            Write-Host "  Format : CSV  (delimiter: '$Delimiter'  FQDN column: '$Column'  port column: '$PortColumn')"
            $rows = Import-Csv -Path $fullPath -Delimiter $Delimiter

            if ($rows.Count -eq 0) {
                Write-Host "  ERROR: CSV file appears to be empty." -ForegroundColor Red
                exit 1
            }

            $fqdnAliases = @($Column, "fqdn", "hostname", "host", "url", "name", "address")
            $headers     = $rows[0].PSObject.Properties.Name
            $matchedFqdn = $null
            foreach ($alias in $fqdnAliases) {
                $hit = $headers | Where-Object { $_ -ieq $alias } | Select-Object -First 1
                if ($hit) { $matchedFqdn = $hit; break }
            }
            if (-not $matchedFqdn) {
                Write-Host "  ERROR: Could not find FQDN column. Available: $($headers -join ', ')" -ForegroundColor Red
                Write-Host "  Use -CsvColumn <n> to specify it." -ForegroundColor Yellow
                exit 1
            }

            $matchedPort = $headers | Where-Object { $_ -ieq $PortColumn } | Select-Object -First 1

            foreach ($row in $rows) {
                $fqdn = $row.$matchedFqdn
                if (-not $fqdn -or $fqdn.Trim() -eq "") { continue }

                $port       = $FallbackPort
                $parsedPort = 0
                if ($matchedPort) {
                    $portVal = $row.$matchedPort
                    if ($portVal -and [int]::TryParse($portVal.Trim(), [ref]$parsedPort) -and
                        $parsedPort -gt 0 -and $parsedPort -le 65535) {
                        $port = $parsedPort
                    }
                }
                $jobs.Add(@{ FQDN = $fqdn.Trim(); Port = $port })
            }
        }

        default {
            Write-Host "  ERROR: Unsupported file type '$extension'. Supported: .txt  .csv" -ForegroundColor Red
            exit 1
        }
    }

    return $jobs
}

# ── Helper functions ─────────────────────────────────────────────────────────
function Get-StatusTag {
    param(
        $Result,
        [int]$CritDays,
        [int]$WarnDays
    )

    if ($Result.Error) {
        return "ERROR"
    }

    $d = $Result.DaysLeft
    $t = $Result.TotalDays

    if     ($d -lt 0)         { return ("EXPIRED  ({0} days ago)" -f [Math]::Abs($d)) }
    elseif ($d -le $CritDays) { return ("CRITICAL ({0,4} of {1} days left)" -f $d, $t) }
    elseif ($d -le $WarnDays) { return ("WARNING  ({0,4} of {1} days left)" -f $d, $t) }
    else                      { return ("OK       ({0,4} of {1} days left)" -f $d, $t) }
}

function Get-ResultColor {
    param(
        $Result,
        [int]$CritDays,
        [int]$WarnDays
    )

    if ($Result.Error) { return "Red" }

    $d = $Result.DaysLeft

    if     ($d -lt 0)         { return "Red" }
    elseif ($d -le $CritDays) { return "Red" }
    elseif ($d -le $WarnDays) { return "Yellow" }
    else                      { return "Green" }
}

function Get-StatusClass {
    param(
        $Result,
        [int]$CritDays,
        [int]$WarnDays
    )

    if ($Result.Error) { return "error" }

    $d = $Result.DaysLeft

    if     ($d -lt 0)         { return "critical" }
    elseif ($d -le $CritDays) { return "critical" }
    elseif ($d -le $WarnDays) { return "warning" }
    else                      { return "ok" }
}

function Get-IssuerDisplayName {
    param([string]$Issuer)

    if ([string]::IsNullOrWhiteSpace($Issuer)) {
        return "-"
    }

    foreach ($part in ($Issuer -split ",\s*")) {
        $trimmed = $part.Trim()
        if ($trimmed.StartsWith("CN=", [System.StringComparison]::OrdinalIgnoreCase)) {
            return $trimmed.Substring(3)
        }
    }

    return $Issuer
}

# ── Parallel execution via RunspacePool ──────────────────────────────────────
function Invoke-Parallel {
    param(
        [object[]]$Jobs,
        [int]     $TimeoutSeconds,
        [int]     $MaxThreads
    )

    $certCheckScript = {
        param($FQDN, $Port, $TimeoutMs)

        function Get-IssuerDisplayNameLocal {
            param([string]$Issuer)

            if ([string]::IsNullOrWhiteSpace($Issuer)) {
                return "-"
            }

            foreach ($part in ($Issuer -split ",\s*")) {
                $trimmed = $part.Trim()
                if ($trimmed.StartsWith("CN=", [System.StringComparison]::OrdinalIgnoreCase)) {
                    return $trimmed.Substring(3)
                }
            }

            return $Issuer
        }

        $result = [PSCustomObject]@{
            FQDN       = $FQDN
            Port       = $Port
            DaysLeft   = $null
            TotalDays  = $null
            ExpiryDate = $null
            Issuer     = $null
            SubjectCN  = $null
            Thumbprint = $null
            Error      = $null
        }

        try {
            $tcpClient = [System.Net.Sockets.TcpClient]::new()
            $connect   = $tcpClient.BeginConnect($FQDN, $Port, $null, $null)
            $waited    = $connect.AsyncWaitHandle.WaitOne($TimeoutMs, $false)

            if (-not $waited) {
                $tcpClient.Close()
                $result.Error = "Connection timed out"
                return $result
            }

            $tcpClient.EndConnect($connect)

            $certCallback = [System.Net.Security.RemoteCertificateValidationCallback]{
                param($sender, $cert, $chain, $errors) $true
            }

            $sslStream = [System.Net.Security.SslStream]::new(
                $tcpClient.GetStream(), $false, $certCallback
            )

            try {
                $sslStream.AuthenticateAsClient($FQDN)
                $cert  = $sslStream.RemoteCertificate
                $cert2 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($cert)

                $expiry    = $cert2.NotAfter.ToUniversalTime()
                $notBefore = $cert2.NotBefore.ToUniversalTime()
                $now       = [DateTime]::UtcNow
                $daysLeft  = [Math]::Floor(($expiry - $now).TotalDays)
                $totalDays = [Math]::Floor(($expiry - $notBefore).TotalDays)

                $cn = ""
                foreach ($part in ($cert2.Subject -split ",\s*")) {
                    if ($part.TrimStart().StartsWith("CN=")) {
                        $cn = $part.TrimStart().Substring(3)
                        break
                    }
                }

                $issuerDisplay = Get-IssuerDisplayNameLocal -Issuer $cert2.Issuer

                $result.DaysLeft   = $daysLeft
                $result.TotalDays  = $totalDays
                $result.ExpiryDate = $expiry.ToString("yyyy-MM-dd")
                $result.Issuer     = if ($issuerDisplay) { $issuerDisplay } else { "-" }
                $result.SubjectCN  = if ($cn) { $cn } else { "-" }
                $result.Thumbprint = $cert2.Thumbprint
            }
            finally {
                $sslStream.Dispose()
            }

            $tcpClient.Close()
        }
        catch [System.Net.Sockets.SocketException] {
            $result.Error = "Connection refused / host unreachable"
        }
        catch {
            $result.Error = $_.Exception.Message
        }

        return $result
    }

    $timeoutMs = $TimeoutSeconds * 1000
    $pool      = [System.Management.Automation.Runspaces.RunspaceFactory]::CreateRunspacePool(1, $MaxThreads)
    $pool.Open()

    $runspaces = [System.Collections.Generic.List[hashtable]]::new()

    foreach ($job in $Jobs) {
        $ps = [System.Management.Automation.PowerShell]::Create()
        $ps.RunspacePool = $pool
        [void]$ps.AddScript($certCheckScript)
        [void]$ps.AddArgument($job.FQDN)
        [void]$ps.AddArgument($job.Port)
        [void]$ps.AddArgument($timeoutMs)
        $runspaces.Add(@{ PS = $ps; Handle = $ps.BeginInvoke() })
    }

    $results = [System.Collections.Generic.List[object]]::new()
    $total   = $runspaces.Count
    $done    = 0

    foreach ($rs in $runspaces) {
        $r = $rs.PS.EndInvoke($rs.Handle)
        $rs.PS.Dispose()
        $results.Add($r[0])
        $done++
        $pct = [Math]::Floor($done / $total * 100)
        Write-Progress -Activity "Checking SSL certificates" `
                       -Status   "$done / $total checks completed" `
                       -PercentComplete $pct
    }

    Write-Progress -Activity "Checking SSL certificates" -Completed
    $pool.Close()
    $pool.Dispose()

    return $results
}

# ── Colour console output ─────────────────────────────────────────────────────
function Write-StatusLine {
    param(
        $Result,
        [int]$CritDays,
        [int]$WarnDays
    )

    $label      = ("{0}:{1}" -f $Result.FQDN, $Result.Port).PadRight(62)
    $issuerText = if ($Result.Issuer) { $Result.Issuer } else { "-" }

    if ($Result.Error) {
        Write-Host ("  {0}" -f $label) -NoNewline
        Write-Host ("  ERROR   : {0}" -f $Result.Error) -ForegroundColor Red -NoNewline
        Write-Host ("  |  Expires: {0}" -f "-") -NoNewline
        Write-Host ("  |  Issuer: {0}" -f "-")
        return
    }

    $tag   = Get-StatusTag -Result $Result -CritDays $CritDays -WarnDays $WarnDays
    $color = Get-ResultColor -Result $Result -CritDays $CritDays -WarnDays $WarnDays

    Write-Host ("  {0}  " -f $label) -NoNewline
    Write-Host ("{0}" -f $tag) -ForegroundColor $color -NoNewline
    Write-Host ("  |  Expires: ") -NoNewline
    Write-Host ("{0}" -f $Result.ExpiryDate) -ForegroundColor $color -NoNewline
    Write-Host ("  |  Issuer: {0}" -f $issuerText)
}

# ── Plain-text report line ────────────────────────────────────────────────────
function Get-ReportLine {
    param(
        $Result,
        [int]$CritDays,
        [int]$WarnDays
    )

    $label = ("{0}:{1}" -f $Result.FQDN, $Result.Port).PadRight(62)

    if ($Result.Error) {
        return "  {0}  ERROR   : {1}  |  Expires: -  |  Issuer: -" -f $label, $Result.Error
    }

    $tag       = Get-StatusTag -Result $Result -CritDays $CritDays -WarnDays $WarnDays
    $issuerTxt = if ($Result.Issuer) { $Result.Issuer } else { "-" }

    return "  {0}  {1}  |  Expires: {2}  |  Issuer: {3}" -f `
        $label, $tag, $Result.ExpiryDate, $issuerTxt
}

function New-HtmlReport {
    param(
        [object[]]$Results,
        [string]$Generated,
        [string]$Source,
        [string]$Ports,
        [int]$Entries,
        [int]$CntExpired,
        [int]$CntCritical,
        [int]$CntWarning,
        [int]$CntOK,
        [int]$CntErrors,
        [int]$CritDays,
        [int]$WarnDays
    )

    $rows = foreach ($r in $Results) {
        if ($r.Error) {
            @"
<tr>
    <td>$($r.FQDN)</td>
    <td>$($r.Port)</td>
    <td class="status error">ERROR</td>
    <td class="expires error">-</td>
    <td>-</td>
    <td>$($r.Error)</td>
</tr>
"@
        }
        else {
            $statusText  = Get-StatusTag   -Result $r -CritDays $CritDays -WarnDays $WarnDays
            $statusClass = Get-StatusClass -Result $r -CritDays $CritDays -WarnDays $WarnDays
            $issuerText  = if ($r.Issuer) { $r.Issuer } else { "-" }

            @"
<tr>
    <td>$($r.FQDN)</td>
    <td>$($r.Port)</td>
    <td class="status $statusClass">$statusText</td>
    <td class="expires $statusClass">$($r.ExpiryDate)</td>
    <td>$issuerText</td>
    <td>-</td>
</tr>
"@
        }
    }

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SSL Certificate Expiry Report</title>
<style>
    body {
        font-family: Segoe UI, Arial, sans-serif;
        margin: 24px;
        background: #ffffff;
        color: #222;
    }
    h1 {
        margin-bottom: 8px;
    }
    .meta, .summary {
        margin-bottom: 18px;
    }
    .summary span {
        display: inline-block;
        margin-right: 16px;
        font-weight: 600;
    }
    table {
        border-collapse: collapse;
        width: 100%;
        font-size: 14px;
    }
    th, td {
        border: 1px solid #d9d9d9;
        padding: 8px 10px;
        text-align: left;
        vertical-align: top;
    }
    th {
        background: #f3f3f3;
    }
    .ok {
        background-color: #dff0d8;
        color: #2e7d32;
        font-weight: 600;
    }
    .warning {
        background-color: #fff3cd;
        color: #8a6d3b;
        font-weight: 600;
    }
    .critical, .error {
        background-color: #f8d7da;
        color: #a94442;
        font-weight: 600;
    }
    .legend {
        margin-top: 18px;
        padding: 12px;
        border: 1px solid #d9d9d9;
        background: #fafafa;
    }
    .legend div {
        margin-bottom: 4px;
    }
</style>
</head>
<body>
    <h1>SSL Certificate Expiry Report</h1>

    <div class="meta">
        <div><strong>Generated:</strong> $Generated</div>
        <div><strong>Source:</strong> $Source</div>
        <div><strong>Ports:</strong> $Ports</div>
        <div><strong>Entries:</strong> $Entries</div>
    </div>

    <div class="summary">
        <span style="color:#a94442;">Expired: $CntExpired</span>
        <span style="color:#a94442;">Critical (≤ $CritDays days): $CntCritical</span>
        <span style="color:#8a6d3b;">Warning (≤ $WarnDays days): $CntWarning</span>
        <span style="color:#2e7d32;">OK: $CntOK</span>
        <span>Errors: $CntErrors</span>
    </div>

    <table>
        <thead>
            <tr>
                <th>FQDN</th>
                <th>Port</th>
                <th>Status</th>
                <th>Expiry Date</th>
                <th>Issuer</th>
                <th>Error</th>
            </tr>
        </thead>
        <tbody>
$($rows -join "`r`n")
        </tbody>
    </table>

    <div class="legend">
        <div><strong>Legend</strong></div>
        <div><strong>Expired / Critical</strong>: action required</div>
        <div><strong>Warning</strong>: renew soon</div>
        <div><strong>OK</strong>: healthy</div>
    </div>
</body>
</html>
"@
}

# ════════════════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "  SSL Certificate Expiry Checker" -ForegroundColor Cyan
Write-Host "  ════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# 1. Read FQDN:PORT pairs -----------------------------------------------------
Write-Host "  Input   : $InputFile"
Write-Host "  TXT Out : $OutputFile"
Write-Host "  HTML Out: $HtmlOutputFile"

$jobs     = Read-FQDNs -Path $InputFile -Column $CsvColumn -PortColumn $CsvPortColumn `
                       -Delimiter $CsvDelimiter -FallbackPort $DefaultPort
$jobCount = $jobs.Count

if ($jobCount -eq 0) {
    Write-Host "  ERROR: No entries found in the input file." -ForegroundColor Red
    exit 1
}

$portsUsed = ($jobs | ForEach-Object { $_.Port } | Sort-Object -Unique) -join ", "

Write-Host "  Found  : $jobCount entries"
Write-Host "  Ports  : $portsUsed"
Write-Host "  Threads: $Threads"
Write-Host ""
Write-Host "  Starting checks..." -ForegroundColor Cyan
Write-Host ""

# 2. Run all checks in parallel -----------------------------------------------
$results = Invoke-Parallel -Jobs $jobs -TimeoutSeconds $TimeoutSeconds -MaxThreads $Threads

# 3. Single flat list — sorted by days remaining, errors last -----------------
$sorted = $results | Sort-Object {
    if ($null -eq $_.DaysLeft) { 999999 }
    else                       { $_.DaysLeft }
}

# 4. Counters -----------------------------------------------------------------
$cntExpired  = @($sorted | Where-Object { $null -ne $_.DaysLeft -and $_.DaysLeft -lt 0 }).Count
$cntCritical = @($sorted | Where-Object { $null -ne $_.DaysLeft -and $_.DaysLeft -ge 0 -and $_.DaysLeft -le $WarnCriticalDays }).Count
$cntWarning  = @($sorted | Where-Object { $null -ne $_.DaysLeft -and $_.DaysLeft -gt $WarnCriticalDays -and $_.DaysLeft -le $WarnWarningDays }).Count
$cntOK       = @($sorted | Where-Object { $null -ne $_.DaysLeft -and $_.DaysLeft -gt $WarnWarningDays }).Count
$cntErrors   = @($sorted | Where-Object { $null -ne $_.Error }).Count

# 5. Assemble report ----------------------------------------------------------
$sep    = "-" * 125
$nowStr = $generatedDisplay

$reportLines = [System.Collections.Generic.List[string]]::new()
$reportLines.Add($sep)
$reportLines.Add("  SSL CERTIFICATE EXPIRY REPORT")
$reportLines.Add("  Generated : $nowStr")
$reportLines.Add("  Source    : $InputFile")
$reportLines.Add("  Ports     : $portsUsed")
$reportLines.Add("  Entries   : $jobCount")
$reportLines.Add("  Results   : Expired: $cntExpired  |  Critical (le ${WarnCriticalDays}d): $cntCritical  |  Warning (le ${WarnWarningDays}d): $cntWarning  |  OK: $cntOK  |  Errors: $cntErrors")
$reportLines.Add($sep)
$reportLines.Add("")
$reportLines.Add(("  {0}  {1}  {2}  {3}" -f "FQDN:PORT".PadRight(62), "STATUS".PadRight(22), "EXPIRY DATE".PadRight(12), "ISSUER"))
$reportLines.Add("  " + ("-" * 121))

foreach ($r in $sorted) {
    $reportLines.Add((Get-ReportLine -Result $r -CritDays $WarnCriticalDays -WarnDays $WarnWarningDays))
}

$reportLines.Add("")
$reportLines.Add($sep)
$reportLines.Add("  SORTED BY: days remaining (soonest expiring first, errors last)")
$reportLines.Add("")
$reportLines.Add("  LEGEND")
$reportLines.Add("  EXPIRED  : certificate has already expired")
$reportLines.Add("  CRITICAL : <= $WarnCriticalDays days remaining")
$reportLines.Add("  WARNING  : <= $WarnWarningDays days remaining")
$reportLines.Add("  OK       : >  $WarnWarningDays days remaining")
$reportLines.Add($sep)

# 6a. Write report to file -----------------------------------------------------
try {
    $reportLines | Set-Content -Path $OutputFile -Encoding UTF8
    Write-Host ""
    Write-Host "  Report saved to: $OutputFile" -ForegroundColor Green
} catch {
    Write-Host ""
    Write-Host "  ERROR: Could not write report to '$OutputFile'" -ForegroundColor Red
    Write-Host "  $_" -ForegroundColor Red
}
Write-Host ""

# 6b. Write HTML report to file ------------------------------------------------
try {
    $htmlReport = New-HtmlReport `
        -Results $sorted `
        -Generated $nowStr `
        -Source $InputFile `
        -Ports $portsUsed `
        -Entries $jobCount `
        -CntExpired $cntExpired `
        -CntCritical $cntCritical `
        -CntWarning $cntWarning `
        -CntOK $cntOK `
        -CntErrors $cntErrors `
        -CritDays $WarnCriticalDays `
        -WarnDays $WarnWarningDays

    $htmlReport | Set-Content -Path $HtmlOutputFile -Encoding UTF8

    Write-Host "  HTML report saved to: $HtmlOutputFile" -ForegroundColor Green
}
catch {
    Write-Host "  ERROR: Could not write HTML report to '$HtmlOutputFile'" -ForegroundColor Red
    Write-Host "  $_" -ForegroundColor Red
}

# 6c. Show report locations ---------------------------------------------------
Write-Host ""
Write-Host $sep
Write-Host "  REPORT FILES" -ForegroundColor Cyan
Write-Host "  TXT  : $OutputFile"
Write-Host "  HTML : $HtmlOutputFile"
Write-Host $sep
Write-Host ""

# 7. Colour-coded console output ----------------------------------------------
Write-Host $sep
Write-Host "  SSL CERTIFICATE EXPIRY REPORT" -ForegroundColor Cyan
Write-Host "  Generated : $nowStr"
Write-Host "  Ports     : $portsUsed"
Write-Host "  Entries   : $jobCount  |  " -NoNewline
Write-Host "Expired: $cntExpired  "   -ForegroundColor Red    -NoNewline
Write-Host "Critical: $cntCritical  " -ForegroundColor Red    -NoNewline
Write-Host "Warning: $cntWarning  "   -ForegroundColor Yellow -NoNewline
Write-Host "OK: $cntOK  "             -ForegroundColor Green  -NoNewline
Write-Host "Errors: $cntErrors"
Write-Host $sep
Write-Host ""
Write-Host ("  {0}  {1}  {2}  {3}" -f "FQDN:PORT".PadRight(62), "STATUS".PadRight(22), "EXPIRY DATE".PadRight(12), "ISSUER")
Write-Host ("  " + ("-" * 121))

foreach ($r in $sorted) {
    Write-StatusLine -Result $r -CritDays $WarnCriticalDays -WarnDays $WarnWarningDays
}

Write-Host ""
Write-Host $sep
Write-Host "  LEGEND"
Write-Host "  EXPIRED  / CRITICAL : " -NoNewline; Write-Host "Red    (action required)" -ForegroundColor Red
Write-Host "  WARNING             : " -NoNewline; Write-Host "Yellow (renew soon)"      -ForegroundColor Yellow
Write-Host "  OK                  : " -NoNewline; Write-Host "Green  (healthy)"         -ForegroundColor Green
Write-Host $sep
Write-Host ""

# 8. Prompt to open HTML report ----------------------------------------------
Write-Host ""
Write-Host $sep
Write-Host "  ACTION" -ForegroundColor Cyan
Write-Host $sep
Write-Host ""
do {
    $openHtml = Read-Host "  Do you want to open the HTML report now? (yes/no)"
    $openHtml = $openHtml.Trim().ToLower()
}
while ($openHtml -notin @("yes", "no"))

if ($openHtml -eq "yes") {
    try {
        Start-Process -FilePath $HtmlOutputFile
        Write-Host "  Opened HTML report: $HtmlOutputFile" -ForegroundColor Green
        Write-Host ""
    }
    catch {
        Write-Host "  ERROR: Could not open HTML report '$HtmlOutputFile'" -ForegroundColor Red
        Write-Host "  $_" -ForegroundColor Red
        Write-Host ""
    }
}
