# Sysmon

Use these queries based on the event code of a Sysmon log file.

### 1) Network-based activity

    index=main EventCode=3 ComputerName=COMPUTER-NAME | table _time ComputerName Image SourceIp SourcePort DestinationIp DestinationPort Protocol

### 2) Get file hash of a suspicious process

    index=task4 ("malicious.exe" OR "C:\\Windows\\Temp\\malicious.exe") | search (EventCode=11 OR "file hash" OR "md5" OR "hash") | table _time, host, _raw
