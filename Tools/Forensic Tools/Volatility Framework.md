# Memory Forensics with Volatility Framework

### Commands:

#### Basic Usage

    python3 vol.py -f DUMP_FILE.mem OS.PLUGIN

## Modules

#### 1) Check network activity (Cross platform)

    python3 vol.py -f FILE.mem windows.netstat

#### 2) List process information in a tree based on their parent process ID (Cross platform)

    python3 vol.py -f FILE.mem windows.pstree

#### 3) Get image information about the image file (Cross platform)

    python3 vol.py -f FILE.mem windows.info

#### 4) List processes

    python3 vol.py -f FILE.mem windows.pslist

#### 5) Scan for hidden processes (rootkits). May cause False Positives!

    python3 vol.py -f FILE.mem windows.psscan

#### 6) List all DLLs associated with processes at the time of extraction

    python3 vol.py -f FILE.mem windows.dlllist

#### 7) Identify injected processes and their PIDs along with the offset address and a Hex, Ascii, and Disassembly view of the infected area.

     python3 vol.py -f FILE.mem windows.malfind

#### 8) Compare the memory file against YARA rules. Use either a YARA file as an argument or list rules within the command line

     python3 vol.py -f FILE.mem windows.yarascan

#### 9) Search for hooking. 

     python3 vol.py -f FILE.mem windows.ssdt

(SSDT stands for System Service Descriptor Table; the Windows kernel uses this table to look up system functions. An adversary can hook into this table and modify pointers to point to a location the rootkit controls.)

#### 10) Dump a list of loaded kernel modules

    python3 vol.py -f FILE.mem windows.modules

#### 11) Scan for drivers present on the system at the time of extraction (Use this AFTER modules plugin)

    python3 vol.py -f FILE.mem windows.driverscan

#### 12) Scan for API hooks (Used to bypass EDR)

    python3 vol.py -f FILE.mem windows.apihooks
