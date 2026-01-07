# DNS Tunneling

Investigate for potential Command and Control traffic and/or data exfiltration through DNS

### 1) Narrow down to DNS

    dns

### 2) Filter DNS queries with no response

    dns.flags.response == 0

### 3) Filter for long queries

Suspicious subdomain lengths 

    dns && frame.len > 70

### 4) Investigate suspicious domain

    dns && dns.qry.name contains SUSPICIOUS_DOMAIN

