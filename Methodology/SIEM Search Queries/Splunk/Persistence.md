# Persistence

### 1) Registry Run Key

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Process_Command_Line="*reg*add*" 
            AND (Process_Command_Line="*\\CurrentVersion\\Run*" 
                 OR Process_Command_Line="*\\CurrentVersion\\RunOnce*"
                 OR Process_Command_Line="*\\CurrentVersion\\RunServices*"
                 OR Process_Command_Line="*\\CurrentVersion\\Policies\\Explorer\\Run*")
    | stats count by dest, user, Process_Command_Line
    | table _time, dest, user, Process_Command_Line

### 2) Winlogon Persistence

    index=wineventlog sourcetype="WinEventLog:Security" EventCode IN (4657, 4688)
    | search (Object_Name="*\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon*" 
              AND Object_Value_Name IN ("Shell", "Userinit", "Notify", "TaskMan"))
            OR Process_Command_Line="*Winlogon*Shell*"
            OR Process_Command_Line="*Winlogon*Userinit*"
    | stats count by dest, user, Object_Name, Object_Value_Name, New_Value, Process_Command_Line
    | table _time, dest, user, Object_Name, Object_Value_Name, New_Value, Process_Command_Line

### 3) Scheduled Task

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4698
    | rex field=Task_Content "<Command>(?<task_command>[^<]+)</Command>"
    | rex field=Task_Content "<Arguments>(?<task_args>[^<]+)</Arguments>"
    | rex field=Task_Content "<UserId>(?<run_as>[^<]+)</UserId>"
    | eval suspicious = if(match(task_command, "(?i)(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32|certutil|bitsadmin)")
        OR match(task_command, "(?i)(\\temp\\|\\appdata\\|\\public\\|\\programdata\\)"), 1, 0)
    | where suspicious=1
    | stats count by dest, user, Task_Name, task_command, task_args, run_as
    | table _time, dest, user, Task_Name, run_as, task_command, task_args

### 4) Service Creation via sc.exe

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Process_Name="sc.exe" 
    | search Process_Command_Line="*create*" OR Process_Command_Line="*config*"
    | rex field=Process_Command_Line "(?:create|config)\s+(?<service_name>\w+)"
    | rex field=Process_Command_Line "binPath=\s*[\"']?(?<bin_path>[^\"']+)"
    | stats count by dest, user, service_name, bin_path, Process_Command_Line
    | table _time, dest, user, service_name, bin_path

### 5) Service Registry Modification

    index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
    | search TargetObject="*\\SYSTEM\\CurrentControlSet\\Services\\*\\ImagePath*"
      OR TargetObject="*\\SYSTEM\\CurrentControlSet\\Services\\*\\FailureCommand*"
      OR TargetObject="*\\SYSTEM\\CurrentControlSet\\Services\\*\\Parameters\\ServiceDll*"
    | rex field=TargetObject "Services\\\\(?<service_name>[^\\\\]+)"
    | where NOT match(Details, "(?i)(system32|syswow64|program files|windows)")
    | stats count by dest, user, service_name, TargetObject, Details
    | table _time, dest, user, service_name, TargetObject, Details

### 6) COM Object Hijacking

    index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
    | search TargetObject="*\\Classes\\CLSID\\*\\InprocServer32*"
      OR TargetObject="*\\Classes\\CLSID\\*\\LocalServer32*"
      OR TargetObject="*\\Classes\\CLSID\\*\\TreatAs*"
    | where NOT match(Details, "(?i)(system32|syswow64|program files)")
    | rex field=TargetObject "CLSID\\\\(?<clsid>\{[^\}]+\})"
    | stats count by dest, user, clsid, Details
    | table _time, dest, user, clsid, Details

### 7) AppInit DLLs

    index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
    | search TargetObject="*\\Windows\\CurrentVersion\\Windows\\AppInit_DLLs*"
      OR TargetObject="*\\Windows\\CurrentVersion\\Windows\\LoadAppInit_DLLs*"
    | stats count by dest, user, TargetObject, Details
    | table _time, dest, user, TargetObject, Details

### 8) Shell Extention Handlers

    index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13
    | search TargetObject="*\\ShellEx\\*" 
      OR TargetObject="*\\shellex\\ContextMenuHandlers\\*"
      OR TargetObject="*\\shellex\\PropertySheetHandlers\\*"
      OR TargetObject="*\\shellex\\ColumnHandlers\\*"
    | where NOT match(Details, "(?i)(system32|program files)")
    | stats count by dest, user, TargetObject, Details
    | table _time, dest, user, TargetObject, Details
