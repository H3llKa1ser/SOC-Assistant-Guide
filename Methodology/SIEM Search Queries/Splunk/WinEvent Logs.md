# WinEvent Logs

### 1) User account creation

    index=winenv EventCode=4720 OR EventCode=4722 | table _time EventCode ComputerName Subject_Account_Name Target_Account_Name New_Account_Account_Name Keywords

### 2) Service creation

    index=winenv EventCode=7045 OR EventCode=7036 ComputerName=COMPUTER-NAME |  table _time EventCode ComputerName Service_Name Service_Account Service_File_Name Message

### 3) Check parent process ID 

    index=main host="WIN-H015" EventCode=PARENT_PROCESS_ID
    | table _time, EventCode, _raw

### 4) Check privileged groups that are enumerated by an attacker

    index=main host=HOST-NAME ("localgroup" OR Administrators OR "Remote Desktop Users") | table _time EventCode user CommandLine

### 5) Check the name of a workstation and its network connections

    index=main host=HOST-NAME EventCode=4624 
    | dedup user Workstation_Name
    | table _time user Workstation_Name Source_Network_Address IpAddress
