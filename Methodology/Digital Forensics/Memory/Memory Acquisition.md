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
