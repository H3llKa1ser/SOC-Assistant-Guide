# Command and Control (C2)

Implementation tips and tricks

| Consideration              | Recommendation                                                           |
|----------------------------|---------------------------------------------------------------------------|
| Tune thresholds            | Adjust count/time values based on your environment's baseline            |
| Whitelist legitimate traffic| Exclude known good destinations like CDNs, updates servers               |
| Combine with threat intel  | Integrate IOC feeds for known C2 infrastructure                           |
| Schedule as alerts         | Run critical queries as scheduled alerts with appropriate throttling      |
| Use lookups                | Create lookup tables for known good vs. suspicious indicators             |

### 1) Beaconing Detection (Regular Interval Communications)

    index=network sourcetype=firewall OR sourcetype=proxy
    | bin _time span=1m
    | stats count by src_ip, dest_ip, dest_port, _time
    | streamstats current=f last(_time) as prev_time by src_ip, dest_ip, dest_port
    | eval interval=_time-prev_time
    | stats count, stdev(interval) as stdev_interval, avg(interval) as avg_interval by src_ip, dest_ip, dest_port
    | where count > 50 AND stdev_interval < 60
    | sort - count

### 2) DNS C2

High Volume DNS Queries to a Single Domain

    index=dns
    | rex field=query "(?<subdomain>[^\.]+)\.(?<domain>[^\.]+\.[^\.]+)$"
    | stats count dc(subdomain) as unique_subdomains by domain, src_ip
    | where unique_subdomains > 100 OR count > 500
    | sort - unique_subdomains

Long DNS Queries

    index=dns
    | eval query_length=len(query)
    | where query_length > 50
    | stats count avg(query_length) as avg_len max(query_length) as max_len by src_ip, query
    | where avg_len > 60
    | sort - avg_len

TXT Record Abuse

    index=dns query_type=TXT
    | stats count by src_ip, query
    | where count > 10
    | sort - count

### 3) Unusual Outbound Connections

Non-Standard Ports for HTTP/HTTPS

    index=network sourcetype=firewall dest_port!=80 dest_port!=443 dest_port!=8080
    | where protocol="tcp"
    | stats count by src_ip, dest_ip, dest_port
    | where count > 50
    | sort - count

Connections to rare destinations

    index=network sourcetype=firewall action=allowed direction=outbound
    | stats count dc(src_ip) as unique_sources by dest_ip
    | where unique_sources < 3 AND count > 100
    | sort - count

### 4) Encrypted Traffic Anomalies

SSL/TLS to Non-Standard Ports

    index=network sourcetype=firewall app=ssl dest_port!=443
    | stats count by src_ip, dest_ip, dest_port
    | where count > 20
    | sort - count

Self-Signed or Untrusted Certificates

    index=proxy ssl_issuer=* 
    | where ssl_issuer=ssl_subject OR match(ssl_issuer, "^CN=")
    | stats count by src_ip, dest, ssl_issuer, ssl_subject
    | sort - count

### 4) HTTP C2

Suspicious User Agents

    index=proxy OR index=web
    | stats count by http_user_agent, src_ip
    | where match(http_user_agent, "^(curl|wget|python|powershell|Mozilla/4\.0|^$)") OR len(http_user_agent) < 10
    | sort - count

High Frequency to a single URL

    index=proxy
    | stats count by src_ip, url, dest
    | where count > 100
    | sort - count

POST requests with small responses

    index=proxy http_method=POST
    | where bytes_out > bytes_in
    | stats count sum(bytes_out) as total_out by src_ip, dest
    | where count > 50
    | sort - total_out

### 5) Known C2

Cobalt Strike

    index=proxy OR index=network
    | search (uri="*/submit.php*" OR uri="*/__utm.gif*" OR uri="*/pixel.gif*" OR uri="*/jquery-*.js*")
    | stats count by src_ip, dest, uri
    | sort - count

Empire/Metasploit

    index=proxy http_user_agent="*Mozilla/5.0*" uri="*login*" http_method=POST
    | stats count by src_ip, dest, uri
    | where count > 20
    | sort - count

### 6) Process-based C2

PowerShell encoded commands

    index=windows sourcetype=WinEventLog:Security OR sourcetype=sysmon EventCode=1
    | search (CommandLine="*-enc*" OR CommandLine="*-e *" OR CommandLine="*encodedcommand*" OR CommandLine="*FromBase64*")
    | stats count by Computer, User, CommandLine
    | sort - count

  Suspicious parent-child process relationships

    index=windows sourcetype=sysmon EventCode=1
    | search (ParentImage="*\\outlook.exe" OR ParentImage="*\\winword.exe" OR ParentImage="*\\excel.exe")
    | search (Image="*\\cmd.exe" OR Image="*\\powershell.exe" OR Image="*\\wscript.exe")
    | stats count by Computer, ParentImage, Image, CommandLine

## 7) Threat Intelligence Correlation

    index=network
    | lookup threat_intel_ip dest_ip as dest OUTPUT threat_category, threat_score
    | where isnotnull(threat_category)
    | stats count by src_ip, dest, threat_category, threat_score
    | sort - threat_score
