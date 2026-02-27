# Memory Acquisition

## Windows

### 1) Full Memory Capture

#### Capture Steps:

Start FTK Imager tool, then:

    Click File -> Capture Memory
    Enter destination path to save memory capture (external storage) -> Give the capture file a fitting name
    Choose whether to include the page file or not -> Click Capture Memory

#### Integrity assurance process:

Open Powershell as Administrator

Get MD5 file hash

    Get-FileHash -Path 'C:\Users\Administrator\Documents\Full Memory Capture\FS-ANALYSIS-07April2025.mem' -Algorithm MD5 

Note down the hash value.

### 2) Process Memory Dump

Tools: Sysinternals Suite

Dump content of the lsass.exe process (Example)

    .\procdump64.exe -ma lsass.exe C:\temp -accepteula

Ensure integrity

    Get-FileHash -Path 'C:\TMP\lsass.exe_250408_082640.dmp' -Algorithm MD5

### 3) Crash Dump

#### Steps:

Right-click the Winfows logo in the task bar, then click run.

Enter this to open the System Properties control panel

    sysdm.cpl
    Advanced Tab -> Settings (Under startup and recovery)

Configure the memory dump in the "System failure - Write debugging information" section.

Choose dump according to use case.
