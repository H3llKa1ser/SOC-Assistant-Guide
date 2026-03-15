# Use Cases

### 1) Extract Hostnames

    tshark -r file.pcapng -T fields -e dhcp.option.hostname | awk NF | sort -r | uniq -c | sort -r

### 2) Extract DNS Queries

    tshark -r file.pcap -T fields -e dns.qry.name | awk NF | sort -r | uniq -c | sort -r

### 3) Extract User Agents

    tshark -r file.pcap -T fields -e http.user_agent | awk NF | sort -r | uniq -c | sort -r

### 4) Extract Email Addresses

    tshark -r file.pcap -Y tshark -Y "http contains gmail.com" -V

### 5) Extract Server Banner

    tshark -r file.pcap -Y "http.server" -T fields -e http.server
