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
    # Saves report as: D:\SSL_Expiry_Checker\SSL_expiry_report_20260306.txt
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
$dateStamp   = Get-Date -Format "yyyyMMdd"
$reportName  = "ssl_expiry_report_$dateStamp.txt"

if ($OutputFolder -ne "") {
    # Use the supplied folder, create it if it doesn't exist
    if (-not (Test-Path $OutputFolder)) {
        New-Item -ItemType Directory -Path $OutputFolder | Out-Null
    }
    $OutputFile = Join-Path (Resolve-Path $OutputFolder).Path $reportName
} else {
    # Default: same folder as the input file
    $inputFolder = Split-Path (Resolve-Path $InputFile).Path -Parent
    $OutputFile  = Join-Path $inputFolder $reportName
}

# ── Read FQDN:PORT pairs from TXT or CSV ─────────────────────────────────────
function Read-FQDNs {
    param([string]$Path, [string]$Column, [string]$PortColumn,
          [string]$Delimiter, [int]$FallbackPort)

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

# ── Parallel execution via RunspacePool ──────────────────────────────────────
function Invoke-Parallel {
    param(
        [object[]]$Jobs,
        [int]     $TimeoutSeconds,
        [int]     $MaxThreads
    )

    $certCheckScript = {
        param($FQDN, $Port, $TimeoutMs)

        $result = [PSCustomObject]@{
            FQDN       = $FQDN
            Port       = $Port
            DaysLeft   = $null
            TotalDays  = $null
            ExpiryDate = $null
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

                $result.DaysLeft   = $daysLeft
                $result.TotalDays  = $totalDays
                $result.ExpiryDate = $expiry.ToString("yyyy-MM-dd")
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
    param($Result, [int]$CritDays, [int]$WarnDays)

    $label = ("{0}:{1}" -f $Result.FQDN, $Result.Port).PadRight(62)

    if ($Result.Error) {
        Write-Host ("  {0}" -f $label) -NoNewline
        Write-Host ("  ERROR   : {0}" -f $Result.Error) -ForegroundColor Red
        return
    }

    $d = $Result.DaysLeft
    $t = $Result.TotalDays
    if      ($d -lt 0)         { $tag = "EXPIRED  ({0} days ago)"         -f [Math]::Abs($d); $color = "Red"    }
    elseif  ($d -le $CritDays) { $tag = "CRITICAL ({0,4} of {1} days left)" -f $d, $t;        $color = "Red"    }
    elseif  ($d -le $WarnDays) { $tag = "WARNING  ({0,4} of {1} days left)" -f $d, $t;        $color = "Yellow" }
    else                       { $tag = "OK       ({0,4} of {1} days left)" -f $d, $t;        $color = "Green"  }

    Write-Host ("  {0}  " -f $label) -NoNewline
    Write-Host ("{0}" -f $tag) -ForegroundColor $color -NoNewline
    Write-Host ("  |  Expires: {0}" -f $Result.ExpiryDate)
}

# ── Plain-text report line ────────────────────────────────────────────────────
function Get-ReportLine {
    param($Result, [int]$CritDays, [int]$WarnDays)

    $label = ("{0}:{1}" -f $Result.FQDN, $Result.Port).PadRight(62)

    if ($Result.Error) {
        return "  {0}  ERROR   : {1}" -f $label, $Result.Error
    }

    $d = $Result.DaysLeft
    $t = $Result.TotalDays
    if      ($d -lt 0)         { $tag = "EXPIRED  ({0} days ago)"           -f [Math]::Abs($d) }
    elseif  ($d -le $CritDays) { $tag = "CRITICAL ({0,4} of {1} days left)" -f $d, $t }
    elseif  ($d -le $WarnDays) { $tag = "WARNING  ({0,4} of {1} days left)" -f $d, $t }
    else                       { $tag = "OK       ({0,4} of {1} days left)" -f $d, $t }

    return "  {0}  {1}  |  Expires: {2}" -f `
        $label, $tag, $Result.ExpiryDate
}

# ════════════════════════════════════════════════════════════════════════════
#  MAIN
# ════════════════════════════════════════════════════════════════════════════

Write-Host ""
Write-Host "  SSL Certificate Expiry Checker" -ForegroundColor Cyan
Write-Host "  ════════════════════════════════" -ForegroundColor Cyan
Write-Host ""

# 1. Read FQDN:PORT pairs -----------------------------------------------------
Write-Host "  Input  : $InputFile"
Write-Host "  Output : $OutputFile"
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
$sep    = "-" * 95
$nowStr = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

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
$reportLines.Add(("  {0}  {1}  {2}" -f "FQDN:PORT".PadRight(62), "STATUS".PadRight(22), "EXPIRY DATE"))
$reportLines.Add("  " + ("-" * 91))

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

# 6. Write report to file -----------------------------------------------------
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
Write-Host ("  {0}  {1}  {2}" -f "FQDN:PORT".PadRight(62), "STATUS".PadRight(22), "EXPIRY DATE")
Write-Host ("  " + ("-" * 91))

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
