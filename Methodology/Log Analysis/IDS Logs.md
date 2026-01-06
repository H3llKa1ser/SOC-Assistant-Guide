# IDS Logs

### 1) Check for potential unauthorized access in the IDS logs

    cat ids_alerts.log | grep INTERNAL_COMPROMISED_IP | head

### 2) Check for lateral movement via SMB in IDS

    cat ids_alerts.log | grep -n INTERNAL_COMPROMISED_IP | grep 'SMB' | cut -d' ' -f6,7,8,9,10,19,21 | head

### 3) Check for potential C2 activity 

    cat ids_alerts.log | grep C2 | head

### 4) Check for activity of the compromised endpoint

    cat ids_alerts.log | grep -n INTERNAL_COMPROMISED_IP | cut -d' ' -f6,7,8,9,10,19,22,23 | head -n 15

### 5) Check which activity is being triggered most on the compromised endpoint

    cat ids_alerts.log | grep -n INTERNAL_COMPROMISED_IP | cut -d' ' -f6,7,8,9,10,19,22,23 | uniq -c | sort -nr | head
