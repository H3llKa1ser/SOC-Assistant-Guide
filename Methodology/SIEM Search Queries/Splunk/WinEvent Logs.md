# WinEvent Logs

### 1) User account creation

    index=winenv EventCode=4720 OR EventCode=4722 | table _time EventCode ComputerName Subject_Account_Name Target_Account_Name New_Account_Account_Name Keywords

### 2) Service creation

    index=winenv EventCode=7045 OR EventCode=7036 ComputerName=COMPUTER-NAME |  table _time EventCode ComputerName Service_Name Service_Account Service_File_Name Message
