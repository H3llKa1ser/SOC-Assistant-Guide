# Powershell Profile

### 1) Dump and read environmental variables to detect powershell PATH

    set > env_vars.txt
    type env_vars.txt

### 2) Reveal the path of $PSHOME

    where powershell.exe

### 3) List available profiles

    if exist "C:\Windows\System32\WindowsPowerShell\v1.0\Microsoft.PowerShell_profile.ps1" (echo PROFILE EXISTS) else (echo PROFILE DOES NOT EXIST)

    if exist "C:\Users\Administrator\Documents\profile.ps1" (echo PROFILE EXISTS) else (echo PROFILE DOES NOT EXIST)

    if exist "C:\Users\Administrator\Documents\WindowsPowerShell\profile.ps1" (echo PROFILE EXISTS) else (echo PROFILE DOES NOT EXIST)


    if exist "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1" (echo PROFILE EXISTS) else (echo PROFILE DOES NOT EXIST)

### 4) Enumerate a Powershell Profile

    type "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"
