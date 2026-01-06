# VPN Logs

### 1) Check which IP addresses have the most failed attempts (to check for potential brute-force attacks)

    cat vpn_auth.log | grep FAIL | cut -d' ' -f3 | sort -nr | uniq -c

### 2) Check more details about the target IP, like which user is being attacked, and if a successful attempt is detected, check the assigned internal IP. 

    cat vpn_auth.log | grep TARGET_IP
