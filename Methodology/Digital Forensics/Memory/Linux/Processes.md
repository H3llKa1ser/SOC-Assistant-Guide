# Processes

### 1) Identify correct Linux banner

    vol3 -f MEMDUMP.mem baners.banners

### 2) List all running processes

    vol3 -f MEMDUMP.mem linux.pslist.PsList > pslist.txt

### 3) Identify hidden processes that pslist plugin could not identify

    vol3 -f MEMDUMP.mem linux.psscan.PsScan > psscan.txt

### 4) Get processes with arguments

    vol3 -f MEMDUMP.mem linux.psaux.PsAux > psaux.txt

### 5) Enumerate memory mapping for processes 

    vol3 -f MEMDUMP.mem linux.proc.Maps > procmaps.txt
