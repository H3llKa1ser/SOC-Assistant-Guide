# Data Exfiltration

### 1) Large Data Transfer

    index=network sourcetype=firewall OR sourcetype=proxy
    | where NOT (cidrmatch("10.0.0.0/8", dest_ip) OR cidrmatch("172.16.0.0/12", dest_ip) OR cidrmatch("192.168.0.0/16", dest_ip))
    | stats sum(bytes_out) as total_bytes by src_ip, dest_ip, user
    | eval total_mb = round(total_bytes/1024/1024, 2)
    | where total_mb > 500
    | sort -total_mb
    | table src_ip, dest_ip, user, total_mb

### 2) DNS Tunneling

    index=dns sourcetype=dns
    | eval query_length = len(query)
    | eval subdomain_count = mvcount(split(query, "."))
    | stats avg(query_length) as avg_len max(query_length) as max_len 
            dc(query) as unique_queries count as total_queries by src_ip
    | where avg_len > 50 OR max_len > 100 OR unique_queries > 1000
    | table src_ip, avg_len, max_len, unique_queries, total_queries

### 3) Cloud Storage

    index=proxy sourcetype=proxy
    | search dest IN ("*dropbox.com*", "*drive.google.com*", "*onedrive.live.com*", "*mega.nz*", 
                      "*box.com*", "*wetransfer.com*", "*pastebin.com*", "*amazonaws.com*")
    | search http_method IN ("POST", "PUT")
    | stats sum(bytes_out) as bytes_uploaded count by src_ip, user, dest
    | eval mb_uploaded = round(bytes_uploaded/1024/1024, 2)
    | where mb_uploaded > 50
    | table _time, src_ip, user, dest, mb_uploaded, count

### 4) Archive Compression

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Process_Name IN ("7z.exe", "7za.exe", "winrar.exe", "rar.exe", "zip.exe", "tar.exe", "gzip.exe")
            OR Process_Command_Line="*Compress-Archive*" OR Process_Command_Line="*makecab*"
    | rex field=Process_Command_Line "(?<archive_target>[A-Za-z]:\\\\[^\s\"]+\.(zip|rar|7z|tar|gz|cab))"
    | stats count values(archive_target) as archives by dest, user, Process_Name
    | table _time, dest, user, Process_Name, archives, count
