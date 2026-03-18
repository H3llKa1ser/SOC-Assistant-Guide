# Credential Dumping

### 1) Detect Credential Dumping via Suspicious Modules

    DeviceImageLoadEvents
    | where InitiatingProcessFileName in~ ("mimikatz.exe", "procdump.exe")
    | where FileName in~ ("dbgcore.dll", "comsvcs.dll")

### 2) Detect LSASS Memory Access

    DeviceProcessEvents
    | where FileName in~ ("procdump.exe", "mimikatz.exe", "taskmgr.exe")
    | where ProcessCommandLine contains "lsass"

### 3) Unusual Access to SAM/SECURITY/NTDS Files

    DeviceFileEvents
    | where FileName in~ ("SAM", "SECURITY", "SYSTEM", "ntds.dit")
    | where FolderPath has_any ("\\Windows\\System32\\config", "C:\\Windows\\NTDS")
    | where ActionType == "FileRead"

### 4) PowerShell Commands Related to Credential Dumping

    DeviceProcessEvents
    | where FileName =~ "powershell.exe"
    | where ProcessCommandLine has_any ("Get-Credential", "Invoke-Mimikatz", "DumpCreds", "lsass")
    | project Timestamp, DeviceName, ProcessCommandLine, InitiatingProcessAccountName
