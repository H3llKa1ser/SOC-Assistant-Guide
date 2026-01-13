# Process Activities

Analyze process behavior based on file and network activity

### 1) Copy the ProcessId field from the event ID 1

### 2) Search for other Sysmon events with the same ProcessId

### 3) Your red flags for network connection events are:

Connection to external IPs on port 80 or on non-standard ports like 4444

Connection to known malicious IPs (e.g. by checking on VirusTotal)

DNS queries to suspicious domains (*.top, *.click, or hpdaykfpadvsl.com)

### 4) Your red flags for file and registry changes are:

Files dropped to staging directories like C:\Temp or C:\Users\Public

Dropped file is a script (.bat or .ps1) or an executable file (.exe or .com)

Created files or registry keys are used for persistence 
