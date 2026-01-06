# Firewall Logs 

### 1) Check which IP address was most blocked by the Firewall

    cat firewall.log | grep "BLOCK" | cut -d' ' -f5 | cut -d: -f1 | sort -nr | uniq -c

### 2) Check if the malicious IP has made any successful attempts to connect

    cat firewall.log | grep TARGET_IP | grep "ALLOW"
