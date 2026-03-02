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

### 5) Search for IP Address

    cat netscan.txt | grep IP

### 6) Search for process

    cat netscan.txt | grep PROCESS_NAME

## Remote access and C2 Communications investigation

### 1) Confirm process relationships

Dump processes and their PIDs as well as their command arguments

    vol -f MEMDUMP.mem windows.pslist > pslist.txt
    vol -f MEMDUMP.mem windows.cmdline > cmdline.txt

Filter vy process ID

    cat cmdline.txt | grep PID

### 2) Scan for code injection

    vol -f MEMDUMP.mem windows.malfind --pid PID > malfind_PID.txt
    cat malfind_PID.txt

Dump memory of the target process for further inspection

    vol -f MEMDUMP.mem windows.memmap --pid PID --dump

### 3) Confirming with YARA

    vol -f MEMDUMP.mem windows.vadyarascan --pid PID --yara-file MALWARE.yar

