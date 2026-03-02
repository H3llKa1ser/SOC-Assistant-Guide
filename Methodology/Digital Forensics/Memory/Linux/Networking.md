# Networking

### 1) Investigate IP information

    vol3 -f MEMDUMP.mem linux.ip.Addr > ipaddr.txt

### 2) Investigate network interface information

    vol3 -f MEMDUMP.mem linux.ip.link > iplink.txt

### 3) Investigate socket details

    vol3 -f MEMDUMP.mem linux.sockstat.Sockstat > sockstat.txt

