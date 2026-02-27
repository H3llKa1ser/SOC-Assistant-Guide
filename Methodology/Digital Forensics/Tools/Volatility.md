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
