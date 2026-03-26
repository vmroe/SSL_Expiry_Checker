# SSL Certificate Expiry Checker (PowerShell)
A lightweight, parallelized PowerShell script to check SSL/TLS certificate expiry for a list of FQDNs and ports.
Designed for operational use in enterprise environments (e.g. VMware, NSX, load balancers, appliances), with TXT + HTML reporting, colorized console output, and parallel execution.

# Features
- Checks SSL certificates for multiple endpoints (FQDN + port)
- Parallel execution using runspaces (fast for large environments)

Generates two reports:
- Plain text (.txt)
- Styled HTML (.html)

Color-coded output:
- Red → Expired / Critical
- Yellow → Warning
- Green → OK

Includes:
- Expiry date
- Days remaining
- Certificate issuer (CA)
- Automatic report storage in ./Reports folder
- Unique timestamp per run (no overwriting)
- Interactive prompt (optional) to open HTML report
- Supports both TXT and CSV input formats
- No external modules required (pure PowerShell 5.1)

# Requirements
- Windows PowerShell 5.1
- Network connectivity to target hosts
- TLS-enabled services (HTTPS, vCenter, NSX, etc.)

# Input Formats
TXT format
- portal01.company.com:443
- portal02.company.com:5480
- portal03.company.com:9200
- portal04.company.com

If no port is specified → default port (443) is used

CSV format
fqdn,port
portal01.company.com,443
portal02.company.com,5480

You can customize column names using parameters.

# Usage
Basic usage
.\Check-SSLExpiry.ps1 -InputFile "C:\Scripts\fqdns.txt"
Custom output folder
.\Check-SSLExpiry.ps1 `
    -InputFile "C:\Scripts\fqdns.txt" `
    -OutputFolder "C:\Reports"
Automatically open HTML report
.\Check-SSLExpiry.ps1 `
    -InputFile "C:\Scripts\fqdns.txt" `
    -OpenHtml
Silent mode (no prompt)
.\Check-SSLExpiry.ps1 `
    -InputFile "C:\Scripts\fqdns.txt" `
    -NoPrompt

# Output
- Console Output
- Real-time progress bar
- Color-coded status overview
- Sorted by days remaining (ascending)

Example:
portal01.company.com:443     CRITICAL ( 12 of 365 days left) | Expires: 2026-04-07 | Issuer: DigiCert
portal02.company.com:443     OK       (210 of 365 days left) | Expires: 2026-10-01 | Issuer: Sectigo

# Generated Reports
Reports are saved in:
./Reports/

Example:
- ssl_expiry_report_2026-03-26_14-35-12.txt
- ssl_expiry_report_2026-03-26_14-35-12.html

HTML Report
- Clean, readable layout
- Color-coded rows
- Summary statistics
Suitable for:
- Operations teams
- Management reporting
- Audits

# Parameters
Parameter	Description
InputFile	Path to TXT or CSV input file
OutputFolder	Optional output directory
DefaultPort	Port used when not specified (default: 443)
CsvColumn	FQDN column name (default: fqdn)
CsvPortColumn	Port column name (default: port)
CsvDelimiter	CSV delimiter (default: ,)
TimeoutSeconds	Connection timeout (default: 10)
Threads	Parallel threads (default: 30)
WarnCriticalDays	Critical threshold (default: 245)
WarnWarningDays	Warning threshold (default: 365)
OpenHtml	Open HTML report automatically
NoPrompt	Disable interactive prompt

# How it works
Uses .NET TcpClient + SslStream to retrieve certificates
Extracts:
- Expiry date (NotAfter)
- Validity period
- Issuer CN
- Executes checks in parallel using RunspacePool
Aggregates results into:
- Console output
- TXT report
- HTML report

# Typical Use Cases
VMware environments:
- vCenter
- NSX Managers
- Aria components
- VCD cells
- Load balancers / reverse proxies
- Internal PKI monitoring
- Pre-audit compliance checks
- Operational health dashboards

# Notes
- Certificate validation is not enforced (self-signed certs are accepted)
- Script reports expiry only, not trust chain validity
- Ensure firewall rules allow outbound connections to target ports

# Future Enhancements (Ideas)
- Email reporting
- Teams / Slack notifications
- Scheduled task integration
- Export to CSV / JSON
- Threshold-based alerting

# License
MIT License
