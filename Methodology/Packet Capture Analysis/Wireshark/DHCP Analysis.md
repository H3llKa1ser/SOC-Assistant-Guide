# DHCP Analysis

### 1) Narrow down DHCP

    dhcp

### 2) Check DHCP requests

Contains the hostname information

    dhcp.option.dhcp == 3

#### Low hanging fruit:

Option 12: Hostname

    dhcp.option.hostname contains "keyword"

Option 50: Requested IP address

Option 51: Requested IP lease time

Option 61: Client's MAC address

### 3) Check DHCP accepted requests (DHCP ACK)

    dhcp.option.dhcp == 5

#### Low hanging fruit:

Option 15: Domain name

    dhcp.option.domain_name contains "keyword"

Option 51: Assigned IP lease time

### 4) Check DHCP denied requests (DHCP NAK)

    dhcp.option.dhcp == 6

#### Low hanging fruit: 

Option 56 Message gives rejection details/reason

    
