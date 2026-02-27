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


