# Processes

## Verify the memory dump

### 1) Calculate MD5 hash of the memory dump

    md5sum MEMDUMP.mem > newhash.txt

### 2) Compare the newly calculated hash with the hash received from another colleague that did the acquisition

    diff acquisitionhash.txt newhash.txt

## Extract processes

### 1) Extract

    vol3 -f MEMDUMP.mem windows.pslist > pslist.txt

### 2) Display extracted processes

    cat pslist.txt | less

## Search for suspicious processes

### 1) Typosquatting

    scvhost.exe
    explorere.exe
    lsasss.exe

### 2) Unusual paths

    svchost.exe in C:\Users\USER
    cmd.exe in C:\tmp

### 3) Masquerading

Mimic legitimate processes and system services

    dockerupdate.exe
    defenderAV.exe
    pdfupdateservice.exe

## Compare with a Baseline

### 1) Extract processes from Task Manager, then add to a file named:

    baseline.txt

### 2) Make the comparison

    awk 'NR >3{print $2}' baseline.txt | sort | uniq > baseline_procs.txt
    awk 'NR >3{print $3}' pslist.txt | sort | uniq > current_procs.txt
    comm -13 baseline_procs.txt current_procs.txt

## Link processes

### 1) Dump process tree

    vol3 -f MEMDUMP.mem windows.pstree > processtree.txt

### 2) Parse process tree

    cut -d$'\t' -f1,2,3 processtree.txt

## Uncover processes not part of the active processes list

### 1) Dump processes

    vol3 -f MEMDUMP.mem windows.psscan > psscan.txt

### 2) Prepare files for comparison

Extract PID and process name

    awk '{print $1,$3}' pslist.txt | sort > pslist_processed.txt
    awk '{print $1,$3}' psscan.txt | sort > psscan_processed.txt

### 3) Compare both files to potentially uncover hidden processes

    comm -23 psscan_processed.txt pslist_processed.txt

### 4) Use another module to cross reference findings

    vol3 -f MEMDUMP.mem windows.psxview > psxview.txt

### 5) Display all the lines where the pslist test equals false

    awk 'NR==3 || $4 == "False"' psxview.txt

## Dump process memory

### 1) Find the path of the main executable and its linked DLLs

Do the same for other suspicious processes identified

    vol3 -f MEMDUMP.mem windows.dlllist --pid PID > PID_dlllist.txt

### 2) Look for the path of the main executable

    cat PID_dlllist.txt

### 3) Dump process memory

    mkdir PID
    cd PID
    vol3 ../MEMDUMP.mem windows.dumpfiles --pid PID

### 4) Look for important files like macro documents and executables

Macros

    ls PID | grep -E ".docm|.dotm" -i

Executables

    ls PID | grep -E ".exe|.dat" -i

