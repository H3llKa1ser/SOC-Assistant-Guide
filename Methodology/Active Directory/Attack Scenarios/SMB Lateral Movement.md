# SMB Lateral Movement

### 1) Investigating Event 5140 File Share Access

    index=win EventCode=5140 Share_Name IN ("*\\ADMIN$\*", "*\\C$\*")
    | table _time, host, Source_Address, user, Share_Name
    | sort _time

### 2) Understand baseline activity of suspected user 

    index=win EventCode=5140 user={USER_ACCOUNT}
    | table _time, Source_Address, Share_Name, host
    | sort _time

### 3) Investigate Source Machine

    index=win EventCode=4624 Source_Network_Address={SOURCE_IP} user=*$
    | stats count by user, Source_Network_Address
    | sort -count

### 4) Identify commands from the Source Machine

Remove the dollar sign first from the previous query

    index=win EventCode=1 host={SOURCE_HOST} CommandLine="*ADMIN$*"
    | table _time, User, Image, CommandLine
    | sort _time

## TIP: 

The net use command is just one way attackers access admin shares. C2 frameworks like Cobalt Strike and Metasploit have built-in SMB modules that connect to shares without spawning net.exe, meaning they won't generate Sysmon Event 1 process creation events. In those cases, Event 4648 on the source machine can still reveal which credentials were used and which servers were targeted, even when the command itself doesn't appear in process creation logs. Event 5140 on the destination side also still fires regardless of how the connection was made.
