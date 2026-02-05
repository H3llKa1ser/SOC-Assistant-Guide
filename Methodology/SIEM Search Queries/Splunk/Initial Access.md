# Initial Access

## Phishing and Malicious documents

### 1) Office document spawning suspicious processes

Detects macro-enabled documents launching malicious payloads.

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Parent_Process_Name IN ("*winword.exe", "*excel.exe", "*powerpnt.exe", "*outlook.exe", "*msaccess.exe")
    | where Process_Name IN ("*cmd.exe", "*powershell.exe", "*wscript.exe", "*cscript.exe", "*mshta.exe", 
                              "*regsvr32.exe", "*rundll32.exe", "*certutil.exe", "*bitsadmin.exe")
    | stats count by dest, user, Parent_Process_Name, Process_Name, Process_Command_Line
    | table _time, dest, user, Parent_Process_Name, Process_Name, Process_Command_Line

### 2) Suspicious email attachment extensions

Identifies potentially malicious email attachments.

    index=email sourcetype=mail
    | rex field=attachment "\.(?<extension>[^\.]+)$"
    | where extension IN ("exe", "scr", "bat", "cmd", "ps1", "vbs", "js", "jse", "wsf", "wsh", 
                           "hta", "iso", "img", "vhd", "vhdx", "dll", "lnk", "jar")
    | stats count values(attachment) as attachments by sender, recipient, subject
    | where count > 0
    | table _time, sender, recipient, subject, attachments

### 3) HTML Smuggling

Detects HTML files writing executables to disk.

    index=wineventlog sourcetype="WinEventLog:Sysmon" EventCode=11
    | where (TargetFilename LIKE "%.exe" OR TargetFilename LIKE "%.dll" OR TargetFilename LIKE "%.js")
    | search Image IN ("*chrome.exe", "*firefox.exe", "*msedge.exe", "*iexplore.exe")
    | stats count by dest, user, Image, TargetFilename
    | table _time, dest, user, Image, TargetFilename

## Public-Facing Applications

### 1) Web Shell detection via Process Ancestry

Identifies web server processes spawning suspicious children.

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Parent_Process_Name IN ("*w3wp.exe", "*httpd.exe", "*nginx.exe", "*tomcat*.exe", "*java.exe", "*node.exe", "*php-cgi.exe")
    | where Process_Name IN ("*cmd.exe", "*powershell.exe", "*whoami.exe", "*net.exe", "*net1.exe", 
                              "*ipconfig.exe", "*systeminfo.exe", "*tasklist.exe")
    | stats count values(Process_Command_Line) as commands by dest, Parent_Process_Name, Process_Name, user
    | table _time, dest, user, Parent_Process_Name, Process_Name, commands

### 2) Web Application attack signatures (you can split the attack signatures in different SPL queries)

Detects SQLi, XSS, RCE attempts in web logs.

    index=web sourcetype=access_combined OR sourcetype=iis
    | eval attack_type = case(
        match(uri_query, "(?i)(union\s+select|select\s+.*from|insert\s+into|drop\s+table|;--|\/\*|\*\/)"), "SQL_Injection",
        match(uri_query, "(?i)(<script|javascript:|onerror=|onload=|onclick=)"), "XSS",
        match(uri_query, "(?i)(\.\.\/|\.\.\\\\|\/etc\/passwd|\/windows\/system32)"), "Path_Traversal",
        match(uri_query, "(?i)(cmd=|exec=|system\(|passthru\(|shell_exec|eval\()"), "Command_Injection",
        match(uri_query, "(?i)(\$\{jndi:|log4j|%24%7Bjndi)"), "Log4Shell",
        match(uri_query, "(?i)(base64_decode|gzinflate|str_rot13)"), "PHP_Injection",
        true(), "None")
    | where attack_type!="None"
    | stats count by src_ip, uri_path, attack_type, status
    | where count > 5
    | sort -count
    | table _time, src_ip, attack_type, uri_path, status, count

### 3) Red Team tooling User-Agents

Detects known exploitation tool signatures.

    index=web sourcetype=access_combined OR sourcetype=iis
    | search http_user_agent IN ("*Cobalt Strike*", "*Metasploit*", "*Nmap*", "*sqlmap*", "*Nikto*", 
                                  "*Burp*", "*OWASP*", "*masscan*", "*Nuclei*", "*gobuster*", "*dirbuster*",
                                  "*python-requests*", "*curl*", "*wget*", "*Go-http-client*")
      OR http_user_agent="" OR http_user_agent="-"
    | stats count dc(uri_path) as unique_paths by src_ip, http_user_agent
    | where count > 20
    | table _time, src_ip, http_user_agent, count, unique_paths

## External Remote Services

### 1) Brute force attacks on Remote Access Services

Detects brute force on VPN, RDP, SSH.

    index=auth sourcetype IN ("vpn", "linux_secure", "WinEventLog:Security")
    | eval service = case(
        sourcetype="vpn", "VPN",
        match(_raw, "sshd"), "SSH",
        EventCode IN (4624, 4625) AND Logon_Type=10, "RDP",
        true(), "Other")
    | where service!="Other"
    | stats count(eval(action="failure" OR match(_raw, "Failed|Invalid|denied"))) as failures 
            count(eval(action="success" OR match(_raw, "Accepted|succeeded"))) as successes by src_ip, service
    | where failures > 20
    | eval success_rate = round(successes/(failures+successes)*100, 2)
    | sort -failures
    | table src_ip, service, failures, successes, success_rate

### 2) VPN login from unusual geolocation

Identifies VPN access from unexpected countries.

    index=vpn sourcetype=vpn action=success
    | iplocation src_ip
    | lookup user_normal_locations.csv user OUTPUT expected_country
    | where Country!=expected_country
    | stats count values(Country) as login_countries by user, src_ip
    | table _time, user, src_ip, login_countries, expected_country

### 3) Impossible Travel

Detects logins from geographically impossible locations.

    index=auth action=success
    | iplocation src_ip
    | sort user, _time
    | streamstats current=f last(_time) as prev_time last(lat) as prev_lat last(lon) as prev_lon last(City) as prev_city by user
    | eval time_diff_hours = (_time - prev_time) / 3600
    | eval distance_km = 6371 * 2 * asin(sqrt(pow(sin((lat - prev_lat) * 3.14159 / 180 / 2), 2) + 
                         cos(prev_lat * 3.14159 / 180) * cos(lat * 3.14159 / 180) * 
                         pow(sin((lon - prev_lon) * 3.14159 / 180 / 2), 2)))
    | eval required_speed = distance_km / time_diff_hours
    | where required_speed > 800 AND time_diff_hours > 0
    | table _time, user, prev_city, City, time_diff_hours, distance_km, required_speed

## Supply Chain Compromise

### 1) Third-Party Software compromise indicators

Detects suspicious activity from trusted software.

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Parent_Process_Name IN ("*solarwinds*", "*orion*", "*teamviewer*", "*anydesk*", 
                                      "*connectwise*", "*kaseya*", "*bomgar*", "*zoho*")
    | where Process_Name IN ("*cmd.exe", "*powershell.exe", "*rundll32.exe", "*regsvr32.exe", 
                              "*mshta.exe", "*certutil.exe")
    | stats count by dest, user, Parent_Process_Name, Process_Name, Process_Command_Line
    | table _time, dest, user, Parent_Process_Name, Process_Name, Process_Command_Line

### 2) Drive-By compromise

Detects browser processes spawning unusual children.

    index=wineventlog sourcetype="WinEventLog:Security" EventCode=4688
    | search Parent_Process_Name IN ("*chrome.exe", "*firefox.exe", "*msedge.exe", "*iexplore.exe")
    | where NOT Process_Name IN ("*chrome.exe", "*firefox.exe", "*msedge.exe", "*iexplore.exe", 
                                  "*gpu-process*", "*renderer*", "*crashpad*")
    | where Process_Name IN ("*cmd.exe", "*powershell.exe", "*wscript.exe", "*mshta.exe", "*rundll32.exe")
    | stats count by dest, user, Parent_Process_Name, Process_Name, Process_Command_Line
    | table _time, dest, user, Parent_Process_Name, Process_Name, Process_Command_Line
