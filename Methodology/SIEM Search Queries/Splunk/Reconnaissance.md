# Reconnaissance

### 1) AD Enumeration

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Process_Command_Line="*net group*" OR Process_Command_Line="*net user*" 
            OR Process_Command_Line="*net localgroup*" OR Process_Command_Line="*dsquery*"
            OR Process_Command_Line="*nltest*" OR Process_Command_Line="*ldapsearch*"
            OR Process_Command_Line="*Get-AD*" OR Process_Command_Line="*Get-Domain*"
    | stats count values(Process_Command_Line) as commands by dest, user
    | where count > 5
    | table _time, dest, user, count, commands

### 2) Bloodhound / Sharphound

    index=wineventlog sourcetype="WinEventLog:Security" 
    | search (EventCode=4688 AND (Process_Name="*SharpHound*" OR Process_Name="*bloodhound*" 
             OR Process_Command_Line="*Invoke-BloodHound*" OR Process_Command_Line="*-CollectionMethod*"))
      OR (EventCode=5145 AND Relative_Target_Name="*.json" AND Share_Name="*ADMIN$*")
    | stats count by dest, user, Process_Name, Process_Command_Line
    | table _time, dest, user, Process_Name, Process_Command_Line

### 3) Internal Network Enumeration

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Process_Command_Line="*arp -a*" OR Process_Command_Line="*ipconfig /all*"
            OR Process_Command_Line="*netstat*" OR Process_Command_Line="*nbtstat*"
            OR Process_Command_Line="*net view*" OR Process_Command_Line="*ping -n*"
            OR Process_Command_Line="*tracert*" OR Process_Command_Line="*nslookup*"
    | bin _time span=5m
    | stats count dc(Process_Command_Line) as unique_commands values(Process_Command_Line) as commands by dest, user, _time
    | where unique_commands > 3
    | table _time, dest, user, unique_commands, commands
