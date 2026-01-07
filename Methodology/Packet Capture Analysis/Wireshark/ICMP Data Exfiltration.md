# ICMP Data Exfiltration

Investigate data exfiltration via ICMP

### 1) Narrow down ICMP 

    icmp

### 2) Check ICMP echo requests

    icmp.type == 8

### 3) Check large ICMP packets

    icmp.type == 8 and frame.len > 100
