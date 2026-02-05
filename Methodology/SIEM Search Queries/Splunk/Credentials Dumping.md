# Post-Exploitation

## Credential Dumping

### 1) LSASS Memory Access / Dumping (Mimikatz)

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4663
    | search Object_Name="*\\lsass.exe" AND Access_Mask IN ("0x1010", "0x1038", "0x143A")
    | stats count by dest, user, Process_Name, Access_Mask
    | table _time, dest, user, Process_Name, Access_Mask, count

### 2) Cred Dump tool detection

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Process_Name IN ("*mimikatz*", "*procdump*", "*sqldumper*", "*comsvcs*")
      OR Process_Command_Line="*sekurlsa*" OR Process_Command_Line="*lsadump*"
      OR Process_Command_Line="*kerberos::*" OR Process_Command_Line="*MiniDump*"
      OR (Process_Name="rundll32.exe" AND Process_Command_Line="*comsvcs*MiniDump*")
    | stats count by dest, user, Process_Name, Process_Command_Line
    | table _time, dest, user, Process_Name, Process_Command_Line

### 3) SAM/SYSTEM/SECURITY Registry Hives

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Process_Command_Line="*reg*save*" 
            AND (Process_Command_Line="*HKLM\\SAM*" OR Process_Command_Line="*HKLM\\SYSTEM*" 
                 OR Process_Command_Line="*HKLM\\SECURITY*")
    | stats count by dest, user, Process_Command_Line
    | table _time, dest, user, Process_Command_Line

### 4) NTDS.dit (Domain Creds)

    index=wineventlog sourcetype="WinEventLog:Security" EventCode IN (4663, 4688)
    | search Object_Name="*ntds.dit*" OR Process_Command_Line="*ntdsutil*" 
            OR Process_Command_Line="*vssadmin*shadow*" OR Process_Command_Line="*esentutl*"
    | stats count by dest, user, Process_Name, Process_Command_Line, Object_Name
    | table _time, dest, user, Process_Name, Process_Command_Line, Object_Name

### 5) DCSync

Detects replication requests from non-DC systems.

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4662
    | search Properties="*Replicating Directory Changes*" OR Properties="*DS-Replication-Get-Changes*"
    | lookup dc_list.csv src_ip OUTPUT is_dc
    | where is_dc!="true"
    | stats count by src_ip, user, dest
    | table _time, src_ip, user, dest, count
