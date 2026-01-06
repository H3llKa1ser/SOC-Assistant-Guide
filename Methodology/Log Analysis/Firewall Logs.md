# Firewall Logs 

### 1) Check any blocked attempts 

    cat firewall.log | grep "BLOCK" | head

### 2) Check which IP address was most blocked by the Firewall

    cat firewall.log | grep "BLOCK" | cut -d' ' -f5 | cut -d: -f1 | sort -nr | uniq -c

### 3) Check if the malicious IP has made any successful attempts to connect

    cat firewall.log | grep TARGET_IP | grep "ALLOW"

### 4) Check if the IP tries to probe the internal network for other machines

    cat firewall.log | grep INTERNAL_COMPROMISED_IP | grep "ALLOW" | head

### 5) Check for potential data exfiltration attempts

    cat firewall.log | grep INTERNAL_COMPROMISED_IP | cut -d' ' -f5,6,7  |   uniq  | sort 
