# DNS Spoofing (AKA DNS Cache Poisoning)

### 1) Narrow down to DNS

    dns

### 2) Filter legitimate traffic

For example, filter Google DNS or Cloudflare DNS.

    dns.flags.response == 1 && ip.src == 8.8.8.8

### 3) Check DNS responses

    dns.flags.response==1

### 4) Check DNS response from the DNS server

    dns.flags.response == 1 && ip.src == 8.8.8.8

### 5) Check DNS requests for a specific domain of interest

    dns && dns.qry.name == "domain.local"

### 6) Check DNS requests for a specific domain of interest, originating from the DNS server

    dns.flags.response == 1 && ip.src == 8.8.8.8 && dns.qry.name == "domain.local"

### 7) Check DNS response other than the DNS server 

Indication of DNS spoofing

    dns.flags.response == 1 && ip.src != 8.8.8.8 && dns.qry.name == "domain.local"

## Attack Indicators

### 1) Multiple DNS responses for the same query: 

A legitimate resolver and a forged responder reply to the same query. This is the single most reliable indicator.

### 2) DNS response from an unexpected source: 

A DNS reply arrives from an IP address that does not match any configured resolver (like 8.8.8.8 or your DNS server).

### 3) Suspiciously short TTL (Time-To-Live) values: 

Attackers use very low TTLs (1 - 30s) to keep poisoned entries short-lived and reassert control.

### 4) Unsolicited DNS responses: 

A DNS reply appears without a corresponding DNS request from the victim.

