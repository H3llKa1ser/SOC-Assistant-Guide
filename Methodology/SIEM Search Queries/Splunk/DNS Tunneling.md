# DNS Tunneling

TIP: "index" and "sourcetype" values might have different names depending on use case.

### 1) Check for DNS logs

    index=data_exfil sourcetype=DNS_logs

### 2) Display the stats of DNS queries generated per source IP

    index="data_exfil" sourcetype="DNS_logs" | stats count by src_ip

### 3) Identify suspicious queries by filtering the stats

    index="data_exfil" sourcetype="dns_logs" | stats count by query | sort -count

### 4) Search for long query names (subdomain encoding)

    index="data_exfil" sourcetype="DNS_logs" | where len(query) > 30
