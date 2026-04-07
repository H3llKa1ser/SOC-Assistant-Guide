# AS-REP Roasting

#### Event ID

- 4768

## Indicators

- Pre_Authentication_Type=0

- DONT_REQUIRE_PREAUTH flag on an account

### 1) Look all TGT request events to check what normal traffic looks like

    index=task3 EventCode=4768
    | table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address
    | sort _time

### 2) Isolate AS-REP Roasting attempt

    index=task3 EventCode=4768 Pre_Authentication_Type=0
    | table _time, Account_Name, Pre_Authentication_Type, Ticket_Encryption_Type, Client_Address

### 3) Check if the account authenticated. If not, it might be an AS-REP Roasting attack.

    index=task3 (EventCode=4624 OR EventCode=4769)
    | search Account_Name="{ACCOUNT_NAME}"
    | table _time, EventCode, Account_Name, Client_Address

