# Memory Dumps

Tools:

1) RAMMap (Sysinternals, Windows)

2) WinPmem

3) FTK Imager

4) Crash Dumps (Windows)

5) LiME (Linux, MacOS)

6) dd (Linux, MacOS)

## Types of Memory Dumps

| Type                              | Captures                                      | Use Case                                                                                      |
|-----------------------------------|-----------------------------------------------|-----------------------------------------------------------------------------------------------|
| **Full Memory Dump**              | Entire physical memory (RAM)                  | Full forensic analysis, malware behavior analysis, valuable for Cyber Threat Intelligence (CTI)|
| **Process Dump / Core Dump**      | Memory of a single process (heap, stack, code, modules) | Detect malware injection and analyze process behavior                                        |
| **Memory Region Dump**            | Specific region of a process (e.g., stack, heap, injected code) | Focused extraction of malware or shellcode                                                   |
| **Pagefile / Swapfile**           | Swapped-out virtual memory (`pagefile.sys`, `\swapfile`) | Collect memory from recently terminated or suspended processes                               |
| **Hibernation File Dump (Windows)**| RAM snapshot saved during sleep (`hiberfil.sys`) | Full memory capture from hibernated systems; use when live memory is unavailable             |
| **VM Memory Dump**                | Volatile memory of a virtual machine          | Safe malware testing and replayable incident analysis                                        |

## File Formats

### 1) Raw physical memory dump

    .raw .mem

### 2) Windows memory dump

    .dmp

### 3) Virtual Machines

    .vmem .vmsn .vmss .bin .sav (Convert the .sav file to analyze)

### 4) Process memory dump Linux (gcore tool)

    .core

### 5) Full memory dump (LiME tool)

    .lime

### 6) Expert Witness Format (EnCase tool)
