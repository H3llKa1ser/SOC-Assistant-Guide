# Accounts

## Account Lifecycle Events

| Event ID | What Happened |
|---------|---------------|
| 4720 | Account created |
| 4722 | Account enabled |
| 4724 | Password reset attempted |
| 4725 | Account disabled |
| 4740 | Account locked out |

### 1) Check account creation activity

    index=* EventCode=4720
    | table _time, SAM_Account_Name, Subject_Account_Name

# Groups

## Group Membership Events

| Event ID | What Happened | Group Scope |
|---------|---------------|-------------|
| 4728 | Member added to the global security group | Domain-wide |
| 4732 | Member added to local security group | Machine-level (domain local on DCs) |
| 4756 | Member added to universal security group | Entire forest |

### 1) Check group membership changes

    index=* (EventCode=4728 OR EventCode=4732 OR EventCode=4756)
    | table _time, Member_Account_Name, Group_Name, Subject_Account_Name

