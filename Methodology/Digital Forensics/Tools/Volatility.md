# Volatility

Memory Forensics Tool

## Installation

### 1) Clone the repo

    git clone https://github.com/volatilityfoundation/volatility3.git
    cd volatility3

### 2) Verify

    python3 vol.py -h

## Usage

### 1) Get OS information

Windows

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.info

Linux

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem linux.info

### 2) Active process enumeration

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.pslist

### 3) Hidden process enumeration

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.psscan

### 4) Process hierarchy

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.pstree

### 5) File, registry and thread enumeration

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.handles

### 6) Network connection enumeration

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.netstat

### 7) TCP/UDP Socket enumeration

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.netscan

### 8) DLL enumeration

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.dlllist

### 9) Malware enumeration

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.malfind
    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.vadinfo

### 10) System Service Descriptor Table (SSDT) Hook Detection

Use this AFTER discovering suspicious kernel modules or abnormal process behavior (rootkit hunting)

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.ssdt

 ### 11) Kernel Module enumeration

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.modules

### 12) Driver enumeration

Use this if you suspect Direct Kernel Object Manipulation (DKOM) or rookit behavior

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.driverscan

Use this to uncover stealthier drivers that modules "modules" and "driverscan" may not detect

     python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.modscan

### 13) Inspect callback functions for unknown drivers or non-standard modules

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.callbacks

### 14) Examine I/O Request Packet (IRP) for suspisious drivers

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.driverirp

### 15) Dump suspicious drivers or modules from memory for static analysis using debuggers

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.moddump

### 16) Extract memory regions form specific processes to conduct deeper analysis of injected code

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem windows.memmap

### 17) Search for strings, patterns and rules against a ruleset using a YARA file

    python3 vol.py -f ~/Desktop/Investigations/MEMDUMP.vmem yarascan
 

