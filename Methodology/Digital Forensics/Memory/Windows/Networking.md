# Networking

## Active connections analysis

### 1) Dump network connections from memory

    vol -f MEMDUMP.mem windows.netscan > netscan.txt

### 2) Search for active listening ports

    cat netscan.txt | grep LISTENING

### 3) Established connections

    cat netscan.txt | grep ESTABLISHED

### 4) Search for port number

    cat netscan.txt | grep PORT_NUM
