# VPN

## VPN Credential Attack investigation

### 1) Identify the scope of the attack

NPS Denial events

    index=win EventCode=6273
    | stats count by User_Account_Name, Client_IP_Address
    | sort - count

### 2) Find the compromised account

    index=win EventCode IN (6273,6272) User_Account_Name={COMPROMISED_USER}
    | table _time, EventCode, User_Account_Name, Client_IP_Address

### 3) Correlate with security logon events

    index=win EventCode IN (4624, 4625) user={COMPROMISED_USER}
    | table _time, host, user, EventCode, Logon_Type
    | sort _time
