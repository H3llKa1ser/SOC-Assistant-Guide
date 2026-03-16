# Baseline Activity

### 1) Compare the total count of authentication events for computer accounts vs user accounts

    index=* EventCode IN (4624, 4768, 4769)
    | eval AccountType=if(like(Account_Name, "%$%"), "Computer Account", "User Account")
    | stats count by AccountType, EventCode
    | sort AccountType, -count

### 2) Stack Counting

    index=* EventCode=4769 NOT Account_Name="*$*"
    | stats count by Account_Name
    | sort -count

