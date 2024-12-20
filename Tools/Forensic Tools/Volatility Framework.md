# Memory Forensics with Volatility Framework

### Commands:

#### Basic Usage

    python3 vol.py -f DUMP_FILE.mem OS.PLUGIN

## Modules

### Windows

#### 1) Check network activity

    python3 vol.py -f FILE.mem windows.netstat

#### 2) List process information in a tree based on their parent process ID

    python3 vol.py -f FILE.mem windows.pstree
