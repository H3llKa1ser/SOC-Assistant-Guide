# PsExec Lateral Movement

### 1) Investigate PsExec on the destination side (unique signature appears here)

    index=win EventCode=7045
    | table _time, host, Service_Name, Service_File_Name, Service_Type, Service_Start_Type, Service_Account
    | sort _time

### 2) Investigate commands run on host with PsExec

    index=win EventCode=1 host={DESTINATION_HOST} ParentImage="*PSEXESVC*"
    | table _time, host, User, ParentImage, Image, CommandLine
    | sort _time

### 3) Named Pipe Artifacts 

    index=win EventCode=17 Image="*PSEXESVC*"
    | table _time, host, Image, PipeName
    | sort _time

### 4) Investigate PsExec Usage with event ID 5145 (Detailed File Share)

    index=win EventCode=5145 host={DESTINATION_HOST} Relative_Target_Name="*PSEXE*"
    | table _time, user, Source_Address, Share_Name, Relative_Target_Name
    | sort _time

### 5) Investigate PsExec on the source side

    index=win EventCode=1 host={SOURCE_HOST}
    | search Image="*PsExec*"
    | table _time, host, User, Image, CommandLine
    | sort _time

