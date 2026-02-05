# Defense Evasion

### 1) AV / EDR Tampering

    index=wineventlog sourcetype="WinEventLog:Security" EventCode IN (4688, 4689, 7036)
    | search Process_Command_Line="*Stop-Service*" OR Process_Command_Line="*sc stop*" 
            OR Process_Command_Line="*taskkill*" OR Process_Command_Line="*net stop*"
    | search Process_Command_Line="*defender*" OR Process_Command_Line="*sense*" 
            OR Process_Command_Line="*crowdstrike*" OR Process_Command_Line="*carbon*"
            OR Process_Command_Line="*cylance*" OR Process_Command_Line="*sentinel*"
            OR Process_Command_Line="*symantec*" OR Process_Command_Line="*mcafee*"
    | stats count by dest, user, Process_Command_Line
    | table _time, dest, user, Process_Command_Line

### 2) Windows Event Log Tampering

    index=wineventlog sourcetype="WinEventLog:Security" EventCode IN (1102, 104)
      OR (EventCode=4688 AND (Process_Command_Line="*wevtutil*cl*" OR Process_Command_Line="*Clear-EventLog*"))
    | stats count by dest, user, EventCode, Process_Command_Line
    | table _time, dest, user, EventCode, Process_Command_Line

### 3) AMSI Bypass

    index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
    | search ScriptBlockText="*AmsiUtils*" OR ScriptBlockText="*amsiInitFailed*" 
            OR ScriptBlockText="*AmsiScanBuffer*" OR ScriptBlockText="*Disable-Amsi*"
            OR ScriptBlockText="*[Ref].Assembly.GetType*AMSI*"
    | stats count values(ScriptBlockText) as scripts by dest, user
    | table _time, dest, user, scripts

### 4) Timestomping

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4663
    | search Object_Name="*\\$STANDARD_INFORMATION*" OR Object_Name="*\\$FILE_NAME*"
    | stats count by dest, user, Process_Name, Object_Name
    | table _time, dest, user, Process_Name, Object_Name
