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

### 5) One-Liner query

    index=dns sourcetype=dns
    | eval query_length = len(query)
    | eval subdomain_count = mvcount(split(query, ".")) - 2
    | stats avg(query_length) as avg_length max(query_length) as max_length 
            count dc(query) as unique_queries by src_ip, query_type
    | where (avg_length > 50 OR max_length > 100) AND unique_queries > 100
    | sort -avg_length
    | table src_ip, query_type, avg_length, max_length, unique_queries
