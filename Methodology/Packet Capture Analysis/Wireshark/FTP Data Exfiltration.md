# FTP Data Exfiltration

Investigate for data exfiltration via FTP

### 1) Look for FTP sessions

    ftp || ftp-data

### 2) Look for credentials

    ftp.request.command == "USER" || ftp.request.command == "PASS"

### 3) Look for anomalies in filenames or credentials

    ftp contains "STOR"

Right-click on a packet, then

    Follow -> TCP Stream

### 4) Look for suspicious files

Suspicious file extensions: PDF, csv, TXT, xlsx

    ftp contains "csv"

### 5) Identify traffic with a large payload size

    ftp && frame.len > 90

Then, follow TCP stream as usual.
