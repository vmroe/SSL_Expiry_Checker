# Intro
Checks SSL certificate expiry for FQDNs listed in a TXT or CSV file. Port can be specified per entry directly in the input file.

Reads FQDN:PORT pairs from a plain text file or CSV file, connects to each host on the specified port over TLS, retrieves the certificate expiry date, and outputs a single list sorted by days remaining (soonest expiring first).

The report file is automatically named ssl_expiry_report_YYYYMMDD.txt and saved in the same folder as the input file, unless -OutputFolder is set.
No third-party modules or Excel required.

# Path to the input file.
TXT format  - one entry per line, port is optional:
- portal01.zone-a.company.com:443
- portal02.zone-a.company.com:5480
- portal03.zone-a.company.com:9200
- portal04.zone-a.company.com        <- uses -DefaultPort if no port given

CSV format  - a column for FQDN and an optional column for port:
- fqdn,port
- portal01.zone-a.company.com,443
- portal02.zone-a.company.com,5480
- Lines starting with # and blank lines are always skipped.

# OutputFolder
Folder where the dated report file will be saved.
Default: same folder as the input file.

# DefaultPort
Port to use when no port is specified on a line. Default: 443
    
# CsvColumn
Column header for FQDNs in a CSV file. Default: fqdn

# CsvPortColumn
Column header for ports in a CSV file. Default: port

# CsvDelimiter
Delimiter used in the CSV file. Default: , (comma)

# TimeoutSeconds
TCP connection timeout per host/port combination. Default: 10

# Threads
Number of parallel runspaces. Default: 30

# WarnCriticalDays
Days threshold below which a cert is flagged CRITICAL. Default: 245

# WarnWarningDays
Days threshold below which a cert is flagged WARNING. Default: 365

# EXAMPLE
Saves report as: D:\SSL_Expiry_Checker\SSL_expiry_report_20260306.txt
.\Check-SSLExpiry.ps1 -InputFile "D:\SSL_Expiry_Checker\fqdns.txt" -WarnCriticalDays 245 -WarnWarningDays 365

# EXAMPLE
Saves report as: D:\SSL_Expiry_Checker\Reports\ssl_expiry_report_20260306.txt
.\Check-SSLExpiry.ps1 -InputFile "D:\SSL_Expiry_Checker\fqdns.txt" -OutputFolder "D:\SSL_Expiry_Checker\Reports"
