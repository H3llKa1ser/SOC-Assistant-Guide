# IDS Logs

### 1) Check for potential unauthorized access in the IDS logs

    cat ids_alerts.log | grep INTERNAL_COMPROMISED_IP | head

### 2) Check for lateral movement via SMB in IDS

    cat ids_alerts.log | grep -n INTERNAL_COMPROMISED_IP | grep 'SMB' | cut -d' ' -f6,7,8,9,10,19,21 | head
