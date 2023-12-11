#### Contains info about the network interfacaes

### Location: /etc/network/interfaces (We can also use ifconfig or ip a to get information about MAC and IP addresses)

## Active Network connections

#### On a live system, knowing the active network connections provides additional content to the investigation.

## Tool: netstat -ano, ss -tulpn

## DNS Information

#### Contains the configuration for the DNS name assignment.

### Location: /etc/hosts

#### The information about DNS servers that a linux host talks to for DNS resolution is stored in the resolv.conf file

### Location: /etc/resolv.conf

## Running processes

#### If performing forensics on a live system, it is helpful to check the running processes

### Tool: ps
