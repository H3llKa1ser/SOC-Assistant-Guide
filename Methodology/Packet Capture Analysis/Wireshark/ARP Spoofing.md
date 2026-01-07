# ARP Spoofing

### 1) Narrow down to ARP traffic

    arp

### 2) Check ARP requests

    arp.opcode == 1

### 3) Check ARP responses

    arp.opcode == 2

### 4) Check gratuitous ARP 

May indicate an attacker maintaining their poison state

    arp.isgratuitous

### 5) Check ARP traffic associated with the Gateway

    arp && arp.src.proto_ipv4 == GATEWAY_IP && eth.src == GATEWAY_MAC

### 6) Check for MAC addresses associated with the Gateway IP

    arp.opcode == 2 && arp.src.proto_ipv4 == GATEWAY_IP

### 7) Verify ARP spoofing

    arp.opcode ==2 && _ws.col.info contains "GATEWAY_IP is at"

### 8) Examine suspicious MAC address

    arp.opcode == 2 && arp.src.proto_ipv4 == GATEWAY_IP && eth.src == MALICIOUS_MAC

### 9) Check for Duplicate IP-to-MAC Mappings

    arp.duplicate-address-detected || arp.duplicate-address-frame

## Attack Indicators

Duplicate MAC-to-IP Mappings: Multiple MAC addresses claiming the same IP address. Indicates impersonation.

Unsolicited ARP Replies: High number of ARP replies without matching requests ("gratuitous ARP").

Abnormal ARP Traffic Volume: A Large number of ARP packets in short intervals.

Unusual Traffic Routing: Traffic rerouted through the attacker’s MAC.

Gateway Redirection Patterns: Multiple destination MACs for the same gateway IP.

ARP Probe / Reply Loops: Many ARP requests with Who has 192.168.1.x? Tell 192.168.1.y patterns.
