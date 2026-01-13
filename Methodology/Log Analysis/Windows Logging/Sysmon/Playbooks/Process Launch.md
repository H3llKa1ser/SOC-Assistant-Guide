# Process Launch

Analyze a potentially malicious process using Sysmon

### 1) Open Sysmon logs and filter for event ID 1

### 2) Review the fields from the process and binary info groups. The red flags are:

Image is in an uncommon directory like C:\Temp or C:\Users\Public

Process is suspiciously named like aa.exe or jqyvpqldou.exe

Process hash (MD5 or SHA256) matches as malware on VirusTotal

### 3) Review the fields from the parent process group. The red flags are:

Parent matches red flags from step 2 (suspicious name, path, or hash)

Parent is not expected (e.g. Notepad launching some CMD commands)

### 4) If still in doubt, go up the process tree until you are confident in your verdict:

Find the preceding event where ProcessId equals ParentProcessId in your event

Analyze it by following steps 2 and 3 (suspicious parent, name, path, or hash)

### 5) Finally, trace the attack chain by filtering all Security and Sysmon events with the same Logon ID
