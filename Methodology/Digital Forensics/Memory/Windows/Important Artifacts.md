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
