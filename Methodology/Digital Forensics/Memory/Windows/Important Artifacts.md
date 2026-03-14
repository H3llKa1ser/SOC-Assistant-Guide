# Important Artifacts

### 1) pagefile.sys

This file is essentially an extension of the RAM memory

Location (Hidden):

    C:\pagefile.sys

Check in cmd:

    dir /a

Configuration related to the pagefile.sys location (SYSTEM)

    Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management


#### Extraction:

#### bulk_extractor 

Link: https://github.com/simsong/bulk_extractor

    bulk_extractor.exe -o output .\pagefile.sys

#### FTK Imager

Extract the file, then dump the content

    strings.exe .\pagefile.sys > pagefile_Strings.txt

### 2) hiberfil.sys (Hibernation file)

Location (hidden)

    C:\hiberfil.sys

Check in cmd:

    dir /a

#### Extraction

FTK Imager

Extract the file using FTK Imager

#### Uncompress the file

Hibernation recon download:

https://arsenalrecon.com/downloads

After downloading, use volatility to extract information from the memory file.

### 3) Crash Dump

You can extract a .dmp file from a suspicious process using Task Manager

    Ctrl+Shift+Escape
    Right-Click on the suspicious process
    Create a dump file

Then, open the tool WinDbg

https://aka.ms/windbg/download

Go to: Open Dump file and choose the .dmp file

In the command section, run these commands:

#### Analyse the dump

    !analyze -v

#### Time of the crash

    !time

#### System Information

    !sysinfo

#### Physical and memory usage of the system. Used to find processes running on the system at the time of crash as well.

    !vm

#### Process details

    !process 0 0

#### Running processes

    .tlist

#### Process Environment Block (PEB)

    !peb
