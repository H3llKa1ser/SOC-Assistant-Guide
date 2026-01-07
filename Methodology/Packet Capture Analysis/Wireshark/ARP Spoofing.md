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

