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

