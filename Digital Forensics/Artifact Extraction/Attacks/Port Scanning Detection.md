# Port Scanning Detection

### 1) Find IPs with multiple connection attempts to different ports

    grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' /var/log/syslog | sort | uniq -c | sort -rn | head -20

### 2) Find repeated connection attempts from same IP

    awk '/refused|denied|invalid/ {print $0}' /var/log/auth.log | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort | uniq -c | sort -rn

### 3) Look for SYN packets without established connections

    grep "SYN" /var/log/kern.log | grep -oE 'SRC=([0-9]{1,3}\.){3}[0-9]{1,3}' | cut -d= -f2 | sort | uniq -c | sort -rn

### 4) Multiple ports from same source

    grep "DPT=" /var/log/kern.log | grep -oE 'SRC=([0-9]{1,3}\.){3}[0-9]{1,3}.*DPT=[0-9]+' | awk '{print $1}' | sort | uniq -c | sort -rn

# Apache/Nginx Web Scanning

### 1) # IPs hitting many different URLs (potential web scanner)

    awk '{print $1}' /var/log/apache2/access.log | sort | uniq -c | awk '$1 > 100 {print $2, $1}' | sort -k2 -rn

### 2) 404 errors from same IP (directory enumeration)

    grep " 404 " /var/log/nginx/access.log | grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn

### 3) Rapid requests in short time window

    awk '{print $4, $1}' /var/log/apache2/access.log | grep "$(date +%d/%b/%Y:%H)" | cut -d' ' -f2 | sort | uniq -c | sort -rn

# SSH Brute Force

### 1) Failed SSH attempts

    grep "Failed password" /var/log/auth.log | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort | uniq -c | sort -rn

### 2) Multiple authentication failures

    grep "authentication failure" /var/log/auth.log | grep -oE 'rhost=([0-9]{1,3}\.){3}[0-9]{1,3}' | cut -d= -f2 | sort | uniq -c | sort -rn

### 3) Invalid user attempts (scanning for valid usernames)

    grep "Invalid user" /var/log/auth.log | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort | uniq -c | sort -rn

# Connection State Analysis

### 1) IPs with many half-open connections (SYN scan indicator)

    netstat -an | grep SYN_RECV | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn

### 2) Current connections by IP

    netstat -ntu | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort | uniq -c | sort -rn

# Time-Based Analysis

### 1) IPs appearing in last 5 minutes with high frequency

    awk -v d="$(date --date='5 minutes ago' '+%d/%b/%Y:%H:%M')" '$4 > "["d {print $1}' /var/log/apache2/access.log | sort | uniq -c | sort -rn

### 2) Find IPs scanning multiple ports in firewall logs

    awk '/DPT=/ {match($0, /SRC=([0-9.]+).*DPT=([0-9]+)/, a); print a[1], a[2]}' /var/log/kern.log | awk '{ip[$1]++; ports[$1]=ports[$1]","$2} END {for(i in ip) if(ip[i]>20) print i, ip[i], ports[i]}'

# One-Liner threat detection

### 1) Comprehensive scan detector: IPs with >50 connections in various logs

    (grep -h -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' /var/log/{auth.log,syslog,kern.log} 2>/dev/null || true) | sort | uniq -c | awk '$1 > 50 {print $2, $1 " connections"}' | sort -k2 -rn
