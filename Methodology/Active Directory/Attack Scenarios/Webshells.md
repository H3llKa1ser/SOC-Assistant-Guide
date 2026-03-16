# Webshells

## Steps

### 1) Identify scanning activity

    index=iis sc_status=404
    | stats count by c_ip
    | sort - count

### 2) Find the suspicious .aspx file

    index=iis c_ip={SUSPICIOUS_IP} sc_status=200
    | stats count by cs_uri_stem
    | sort - count

### 3) Filter for the suspicious .aspx file

    index=iis cs_uri_stem="*/{WEBSHELL_FILENAME}"
    | table _time, c_ip, cs_method, cs_uri_query, sc_status
    | sort _time

### 4) Trace the process chain in Sysmon

    index=win EventCode=1 ParentImage="*\\w3wp.exe"
    | table _time, ParentImage, CommandLine
    | sort _time

### 5) Find when the webshell was deployed

    index=win EventCode=11 TargetFilename="*{WEBSHELL_FILENAME}"
    | table _time, Image, TargetFilename

No Sysmon method

    index=iis cs_method=POST cs_uri_query="*{WEBSHELL_FILENAME}"
    | table _time, c_ip, cs_uri_stem, cs_uri_query, sc_status
    | sort _time  
