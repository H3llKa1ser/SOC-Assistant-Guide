# Authentication Events

### 1) TGT Requests

    index=* EventCode=4768
    | table _time, Account_Name, Client_Address, Ticket_Encryption_Type

### 2) NTLM authentication

    index=* EventCode=4776
    | table _time, Logon_Account, Source_Workstation

### 3) Successful login via NTLM 

    index=* EventCode=4624 Account_Name=USER.NAME Authentication_Package=NTLM
    | table _time host user Workstation_Name Source_Network_Address Authentication_Package

