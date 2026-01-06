# IP Address Extraction

### 1) Extract IPv4 address from a file

    grep -E '\b((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b' file.txt

### 2) Extract only IPs

    grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' file.txt

### 3) Count unique IPs

    grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' file.txt | sort -u | wc -l

### 4) Show lines with IPs and line numbers

    grep -nE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' file.txt
