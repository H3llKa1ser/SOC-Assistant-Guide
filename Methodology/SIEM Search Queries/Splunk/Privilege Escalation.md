# Privilege Escalation

## Windows

### 1) Token Manipulation / Impersonation

Detects token theft and impersonation attacks.

    index=wineventlog sourcetype="WinEventLog:Security" EventCode IN (4624, 4648)
    | where Logon_Type=9 OR (EventCode=4648 AND Target_User_Name!=Current_User_Name)
    | eval impersonation = if(Target_User_Name!=Current_User_Name, "true", "false")
    | stats count dc(Target_User_Name) as impersonated_users values(Target_User_Name) as targets 
            by Current_User_Name, src_ip, dest
    | where impersonated_users > 1
    | table _time, Current_User_Name, src_ip, dest, impersonated_users, targets

### 2) Scheduled Task creation for escalation/persistence

Detects suspicious scheduled task creation.

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4698
    | rex field=Task_Content "<Command>(?<command>[^<]+)</Command>"
    | rex field=Task_Content "<Arguments>(?<arguments>[^<]+)</Arguments>"
    | rex field=Task_Content "<UserId>(?<run_as_user>[^<]+)</UserId>"
    | where run_as_user LIKE "%SYSTEM%" OR run_as_user LIKE "%Administrator%"
    | search command IN ("*powershell*", "*cmd*", "*wscript*", "*mshta*", "*rundll32*")
    | stats count by dest, Task_Name, command, arguments, run_as_user, user
    | table _time, dest, user, Task_Name, command, arguments, run_as_user

### 3) Service creation with SYSTEM privileges

Detects new services configured to run as SYSTEM.

    index=wineventlog sourcetype="WinEventLog:System" EventCode=7045
    | where Service_Start_Type="auto start" OR Service_Account LIKE "%LocalSystem%"
    | search Service_File_Name IN ("*cmd*", "*powershell*", "*temp*", "*appdata*", "*programdata*", "*.ps1*")
    | stats count by dest, Service_Name, Service_File_Name, Service_Account, user
    | table _time, dest, user, Service_Name, Service_File_Name, Service_Account

### 4) UAC Bypass attempts

Detects common UAC bypass techniques.

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | where (Process_Name="*fodhelper.exe" AND Parent_Process_Name!="*explorer.exe")
        OR (Process_Name="*eventvwr.exe" AND Parent_Process_Name!="*explorer.exe")
        OR (Process_Name="*computerdefaults.exe" AND Parent_Process_Name!="*explorer.exe")
        OR (Process_Name="*sdclt.exe" AND Parent_Process_Name!="*explorer.exe")
        OR (Process_Command_Line LIKE "*ms-settings*" AND Process_Command_Line LIKE "*shell*")
    | stats count by dest, user, Process_Name, Parent_Process_Name, Process_Command_Line
    | table _time, dest, user, Process_Name, Parent_Process_Name, Process_Command_Line

### 5) DLL Hijacking

Detects DLL loading from unusual locations.

    index=wineventlog sourcetype="WinEventLog:Sysmon" EventCode=7
    | where NOT ImageLoaded LIKE "%\\Windows\\System32\\%" 
        AND NOT ImageLoaded LIKE "%\\Windows\\SysWOW64\\%"
        AND NOT ImageLoaded LIKE "%\\Program Files%"
    | rex field=Image "(?<process_dir>.*)\\\\[^\\\\]+$"
    | rex field=ImageLoaded "(?<dll_dir>.*)\\\\[^\\\\]+$"
    | where process_dir!=dll_dir
    | stats count by dest, Image, ImageLoaded, Signed
    | where Signed="false"
    | table _time, dest, Image, ImageLoaded, Signed

### 6) Named Pipe Impersonation

Detects named pipe creation used for privilege escalation.

    index=wineventlog sourcetype="WinEventLog:Sysmon" EventCode IN (17, 18)
    | search PipeName IN ("*\\spoolss*", "*\\samr*", "*\\lsarpc*", "*\\netlogon*", "*\\srvsvc*")
        OR PipeName LIKE "*\\pipe\\%"
    | stats count by dest, Image, PipeName, User
    | where count > 10
    | table _time, dest, User, Image, PipeName, count

### 7) Kernel Driver Load (Rootkit)

Detects unsigned or suspicious driver loads.

    index=wineventlog sourcetype="WinEventLog:Sysmon" EventCode=6
    | where Signed="false" OR SignatureStatus!="Valid"
    | stats count by dest, ImageLoaded, Signature, SignatureStatus
    | table _time, dest, ImageLoaded, Signature, SignatureStatus

### 8) Bring Your Own Vulnerable Driver (BYOVD)

Detects known vulnerable driver installations.

    index=wineventlog sourcetype="WinEventLog:Sysmon" EventCode=6
    | rex field=ImageLoaded "\\\\(?<driver_name>[^\\\\]+)$"
    | lookup vulnerable_drivers.csv driver_name OUTPUT vulnerability_info
    | where isnotnull(vulnerability_info)
    | stats count by dest, ImageLoaded, driver_name, vulnerability_info
    | table _time, dest, ImageLoaded, driver_name, vulnerability_info

## Linux

### 1) Sudo PrivEsc (GTFOBins)

Detects sudo mis-configurations being exploited.

    index=linux sourcetype=linux_secure
    | search "sudo:" AND ("COMMAND=" OR "command")
    | rex field=_raw "COMMAND=(?<command>.+)$"
    | where match(command, "(\/bin\/bash|\/bin\/sh|vi\s|vim\s|nano\s|less\s|more\s|awk\s|find\s|nmap\s|python|perl|ruby|lua)")
    | stats count by host, user, command
    | table _time, host, user, command

### 2) SUID/SGID

Detects execution of suspicious SUID binaries.

    index=linux sourcetype=linux_audit type=EXECVE
    | where euid=0 AND uid!=0
    | stats count by host, exe, uid, euid, comm
    | table _time, host, uid, euid, exe, comm

### 3) Container Escape

Detects container breakout attempts.

    index=linux OR index=container
    | search (cmdline="*nsenter*" OR cmdline="*--privileged*" OR cmdline="*/proc/1/*" 
              OR cmdline="*mount*cgroup*" OR cmdline="*release_agent*")
    | stats count by host, container_id, user, cmdline
    | table _time, host, container_id, user, cmdline

## Cloud

### 1)  AWS IAM PrivEsc

Detects IAM policy modifications for escalation.

    index=aws sourcetype=aws:cloudtrail
    | search eventName IN ("CreatePolicyVersion", "SetDefaultPolicyVersion", "AttachUserPolicy", 
                            "AttachRolePolicy", "AttachGroupPolicy", "PutUserPolicy", "PutRolePolicy", 
                            "PutGroupPolicy", "CreateAccessKey", "UpdateAssumeRolePolicy", 
                            "AddUserToGroup", "UpdateLoginProfile", "CreateLoginProfile")
    | stats count values(eventName) as escalation_actions dc(eventName) as action_count 
            by userIdentity.arn, sourceIPAddress, userIdentity.principalId
    | where action_count > 2
    | sort -action_count
    | table _time, userIdentity.arn, sourceIPAddress, action_count, escalation_actions

### 2) Azure Role Assignment Escalation

Detects privilege escalation in Azure RBAC.

    index=azure sourcetype=azure:activity operationName.localizedValue="Create role assignment"
    | spath input=properties.requestbody
    | search properties.roleDefinitionId IN ("*Owner*", "*Contributor*", "*User Access Administrator*")
    | stats count by caller, callerIpAddress, properties.principalId, properties.roleDefinitionId
    | table _time, caller, callerIpAddress, properties.principalId, properties.roleDefinitionId

### 3) GCP Service Account Key Creation

Detects service account key creation for persistence/escalation.

    index=gcp sourcetype=google:gcp:pubsub:message
    | spath input=data.protoPayload
    | search methodName="*CreateServiceAccountKey*" OR methodName="*SetIamPolicy*"
    | stats count by authenticationInfo.principalEmail, callerIp, methodName, resourceName
    | table _time, authenticationInfo.principalEmail, callerIp, methodName, resourceName
