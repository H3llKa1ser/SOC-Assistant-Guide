# NTDS.dit Extraction

#### Event ID

- 1 (Sysmon)

- 4688

## Splunk Queries

#### ntdsutil

### 1) Search for ntdsutil execution

    index=task6 EventCode=1 Image="*\ntdsutil.exe"
    | table _time, host, User, ParentImage, Image, CommandLine

### 2) Check if the extraction produced the expected file

    index=task6 EventCode=11 TargetFilename="*ntds.dit" Image="*\\ntdsutil.exe"
    | table _time, Image, TargetFilename

#### vssadmin shadow copy

### 1) Search for the shadow copy creation

    index=task6 EventCode=1 Image="*\vssadmin.exe" CommandLine="*create shadow*"
    | table _time, host, User, ParentImage, Image, CommandLine

### 2) Look for copy commands that target sensitive files form the shadow copy path

    index=task6 EventCode=1 CommandLine="*HarddiskVolumeShadowCopy*" (CommandLine="*ntds*" OR CommandLine="*SYSTEM*")
    | table _time, host, User, ParentImage, Image, CommandLine

