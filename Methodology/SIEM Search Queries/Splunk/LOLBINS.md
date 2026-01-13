# LOLBINS

### 1) PowerShell

    index=wineventlog OR index=sysmon (EventCode=4688 OR EventCode=1 OR EventCode=4104) (CommandLine="*powershell*IEX*" OR CommandLine="*powershell*-EncodedCommand*" OR CommandLine="*powershell*-Exec Bypass*" OR CommandLine="*Invoke-WebRequest*" OR CommandLine="*DownloadString*" OR CommandLine="*Invoke-RestMethod*") | stats count values(Host) as hosts values(User) as users values(ParentImage) as parents by CommandLine

### 2) WMIC

    index=sysmon OR index=wineventlog (EventCode=1 OR EventCode=4688) (CommandLine="*\\wmic.exe*process call create*" OR CommandLine="*wmic /node:* process call create*" OR CommandLine="*wmic*process get Name,CommandLine*") | stats count values(Host) as hosts values(User) as users values(ParentImage) as parents by CommandLine

### 3) Certutil

    index=sysmon OR index=wineventlog (EventCode=1 OR EventCode=4688 OR EventCode=4663) (Image="*\\certutil.exe" OR CommandLine="*certutil*") (CommandLine="* -urlcache * -f *" OR CommandLine="* -decode *" OR CommandLine="* -encode *") | stats count values(Host) as hosts values(User) as users values(ParentImage) as parents by CommandLine

### 4) MSHTA

    index=sysmon (EventCode=1 OR EventCode=4688) Image="*\\mshta.exe" (CommandLine="*http*://*" OR CommandLine="*javascript:*" OR CommandLine="*.hta") | stats count by host, user, ParentImage, CommandLine

### 5) Rundll32

    index=sysmon (EventCode=1 OR EventCode=4688 OR EventCode=7) Image="*\\rundll32.exe" (CommandLine="*\\Users\\Public\\*" OR CommandLine="*url.dll,FileProtocolHandler*" OR CommandLine="*\\Windows\\Temp\\*") | stats count by host, user, ParentImage, CommandLine

### 6) Schtasks / Task scheduler

    index=wineventlog EventCode=4698 OR EventCode=4699 OR index=sysmon (EventCode=1 OR EventCode=4688) (CommandLine="*schtasks* /Create*" OR CommandLine="*schtasks* /Run*" OR Image="*\\taskeng.exe" OR EventCode=4698) | stats count by host, user, EventCode, TaskName, CommandLine
