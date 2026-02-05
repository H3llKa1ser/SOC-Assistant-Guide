# Credential Dumping

### 1) LSASS Memory Access / Dumping (Mimikatz)

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4663
    | search Object_Name="*\\lsass.exe" AND Access_Mask IN ("0x1010", "0x1038", "0x143A")
    | stats count by dest, user, Process_Name, Access_Mask
    | table _time, dest, user, Process_Name, Access_Mask, count

OR

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4663
    | search Object_Name="*\\lsass.exe"
    | eval suspicious_access = case(
        Access_Mask="0x1010", "PROCESS_VM_READ",
        Access_Mask="0x1038", "PROCESS_VM_READ+QUERY",
        Access_Mask="0x1F0FFF", "PROCESS_ALL_ACCESS",
        Access_Mask="0x1FFFFF", "FULL_CONTROL",
        Access_Mask="0x143A", "MINIDUMP_ACCESS",
        true(), "Other")
    | where suspicious_access!="Other"
    | stats count values(Access_Mask) as access_masks values(suspicious_access) as access_types by dest, user, Process_Name
    | table _time, dest, user, Process_Name, access_types, access_masks, count

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

OR

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4662
    | search Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" 
         OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"
         OR Properties="*89e95b76-444d-4c62-991a-0facbeda640c*"
    | eval attack_type = case(
        match(Properties, "1131f6aa"), "DS-Replication-Get-Changes",
        match(Properties, "1131f6ad"), "DS-Replication-Get-Changes-All",
        match(Properties, "89e95b76"), "DS-Replication-Get-Changes-In-Filtered-Set",
        true(), "Unknown")
    | lookup domain_controllers.csv src_ip OUTPUT is_dc
    | where is_dc!="true" OR isnull(is_dc)
    | stats count values(attack_type) as replication_rights by src_ip, user, dest
    | table _time, src_ip, user, dest, replication_rights, count

### 6) Mimikatz Execution Patterns

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Process_Command_Line="*sekurlsa::*" OR Process_Command_Line="*lsadump::*"
            OR Process_Command_Line="*kerberos::*" OR Process_Command_Line="*crypto::*"
            OR Process_Command_Line="*privilege::debug*" OR Process_Command_Line="*token::*"
            OR Process_Name="*mimikatz*" OR Process_Name="*mimi32*" OR Process_Name="*mimi64*"
            OR Process_Name="*pypykatz*"
    | stats count by dest, user, Process_Name, Process_Command_Line
    | table _time, dest, user, Process_Name, Process_Command_Line, count

### 7) LSASS Dump via comsvcs.dll

Detects credential dumping using legitimate Windows DLLs.

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Process_Name="rundll32.exe" 
            AND (Process_Command_Line="*comsvcs*MiniDump*" OR Process_Command_Line="*comsvcs.dll*#24*")
    | stats count by dest, user, Process_Command_Line, Parent_Process_Name
    | table _time, dest, user, Parent_Process_Name, Process_Command_Line

### 8) Procdump LSASS Dumping

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Process_Name="*procdump*" 
            AND (Process_Command_Line="*lsass*" OR Process_Command_Line="*-ma*")
    | stats count by dest, user, Process_Command_Line
    | table _time, dest, user, Process_Command_Line, count

### 9) Taks Manager LSASS Dumping

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Parent_Process_Name="*taskmgr.exe" AND Process_Command_Line="*lsass*"
    | append [
        search index=wineventlog EventCode=4663 Object_Name="*\\lsass.DMP"
    ]
    | stats count by dest, user, Process_Name, Object_Name
    | table _time, dest, user, Process_Name, Object_Name

### 10) Shadow Copy Abuse

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search (Process_Command_Line="*vssadmin*create shadow*" OR Process_Command_Line="*wmic shadowcopy*"
              OR Process_Command_Line="*diskshadow*" OR Process_Command_Line="*esentutl*")
            OR (Process_Command_Line="*\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*"
                AND (Process_Command_Line="*sam*" OR Process_Command_Line="*system*" 
                     OR Process_Command_Line="*ntds*" OR Process_Command_Line="*security*"))
    | stats count values(Process_Command_Line) as commands by dest, user
    | table _time, dest, user, commands, count

### 11) LSA Secrets Dumping

    index=wineventlog sourcetype="WinEventLog:Security" EventCode IN (4688, 4663)
    | search Process_Command_Line="*lsadump*" OR Object_Name="*\\SECURITY\\Policy\\Secrets*"
            OR Process_Command_Line="*secretsdump*" OR Process_Command_Line="*LSASecretsDump*"
    | stats count by dest, user, Process_Name, Process_Command_Line, Object_Name
    | table _time, dest, user, Process_Name, Process_Command_Line, Object_Name

### 12) Kerberoasting

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4769
    | search Ticket_Encryption_Type=0x17 OR Ticket_Encryption_Type=0x18
    | where Service_Name!="krbtgt" AND NOT match(Service_Name, "\$$")
    | bin _time span=5m
    | stats dc(Service_Name) as unique_services count as ticket_requests 
            values(Service_Name) as services by src_ip, user, _time
    | where unique_services > 5
    | table _time, src_ip, user, unique_services, ticket_requests, services

### 13) AS-REPRoasting

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4768
    | search Ticket_Encryption_Type=0x17
    | stats count dc(user) as unique_users values(user) as users by src_ip
    | where unique_users > 3 OR count > 10
    | table _time, src_ip, unique_users, count, users

### 14) Browser Credential Dumping

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4663
    | search Object_Name="*\\AppData\\Local\\Google\\Chrome\\User Data\\*Login Data*"
            OR Object_Name="*\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles\\*logins.json*"
            OR Object_Name="*\\AppData\\Local\\Microsoft\\Edge\\User Data\\*Login Data*"
            OR Object_Name="*\\AppData\\Local\\BraveSoftware\\*Login Data*"
    | where Process_Name!="chrome.exe" AND Process_Name!="firefox.exe" 
            AND Process_Name!="msedge.exe" AND Process_Name!="brave.exe"
    | stats count by dest, user, Process_Name, Object_Name
    | table _time, dest, user, Process_Name, Object_Name, count

### 15) Windows Credentials Manager

    index=wineventlog sourcetype="WinEventLog:Security" EventCode IN (4663, 4688)
    | search Object_Name="*\\Microsoft\\Credentials\\*" 
            OR Object_Name="*\\Microsoft\\Protect\\*"
            OR Process_Command_Line="*vaultcmd*" 
            OR Process_Command_Line="*cmdkey*"
            OR Process_Command_Line="*Get-VaultCredential*"
    | stats count by dest, user, Process_Name, Object_Name, Process_Command_Line
    | table _time, dest, user, Process_Name, Object_Name, Process_Command_Line

### 16) SSH Key Theft

    index=linux sourcetype=auditd type="SYSCALL"
    | search (name="*id_rsa*" OR name="*id_dsa*" OR name="*id_ecdsa*" OR name="*id_ed25519*"
              OR name="*authorized_keys*" OR name="*known_hosts*")
            AND syscall IN ("open", "openat", "read")
    | where exe!="/usr/bin/ssh" AND exe!="/usr/sbin/sshd"
    | stats count by host, uid, exe, name
    | table _time, host, uid, exe, name, count

### 17) Cloud Creds

    index=wineventlog OR index=linux EventCode=4663 OR type="SYSCALL"
    | search Object_Name="*\\.aws\\credentials*" OR Object_Name="*\\.azure\\*"
            OR Object_Name="*\\.config\\gcloud\\*" OR name="*.aws/credentials*"
            OR name="*application_default_credentials.json*"
    | stats count by host, user, Process_Name, Object_Name, name
    | table _time, host, user, Process_Name, Object_Name, name
