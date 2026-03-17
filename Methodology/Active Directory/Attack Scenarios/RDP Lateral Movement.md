# RDP Lateral Movement

### 1) Check for discovery commands on a host from a generated alert 

    index=win EventCode=1 host=TARGET_HOST
    | search CommandLine IN ("*nltest*", "*net * user*", "*net * group*", "*net * view*")
    | table _time, host, User, Image, CommandLine, LogonId
    | sort _time

### 2) Identify how an attacker has reached the target host

    index=win EventCode=4624 host=TARGET_HOST Logon_ID={LOGON_ID}
    | table _time, user, Logon_Type, Source_Network_Address, Logon_ID****

### 3) Identify the Source Hostname

    index=win EventCode=4624 Source_Network_Address={SOURCE_IP} user=*$
    | stats count by user, Source_Network_Address
    | sort -count

### 4) Find evidence for outbound RDP connection on the source

    index=win EventCode=1 host={SOURCE_SERVER} Image="*mstsc.exe*"
    | table _time, User, Image, CommandLine, LogonId
    | sort _time

### 5) Check how an attacker reached the intermediate server (RDP Chaining)

    index=win EventCode=4624 host={SOURCE_SERVER} Logon_ID={LOGON_ID}
    | table _time, user, Logon_Type, Source_Network_Address, Logon_ID

