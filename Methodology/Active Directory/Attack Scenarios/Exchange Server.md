# Exchange Server

## OWA Brute-force attack investigation

### 1) Find authentication failures against OWA

    index=iis cs_uri_stem="/owa/auth.owa" cs_method=POST
    | bin _time span=5m
    | stats count by _time, c_ip
    | where count > 10
    | sort - count

### 2) Identify targeted account

    index=win EventCode=4625
    | stats count by user, Logon_Type
    | sort - count

### 3) Correlate logins with Windows Security logs

    index=win EventCode IN (4624, 4625) user="{TARGETED_USER}" Logon_Type=8
    | table _time, EventCode, user, Process_Name, Logon_Type
    | sort _time

### 4) Check for post-authentication activity (/ecp admin panel and /powershell remote powershell access)

    index=iis c_ip="{ATTACKER_IP}"
    | stats count by cs_uri_stem
    | sort - count
