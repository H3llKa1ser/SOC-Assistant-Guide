# Backdoored User Accounts

### 1) Open Security logs and filter for 4720 / 4732 event IDs

### 2) Manually review every event; your red flags are:

No one from your IT department can confirm the action

Changes were made during non-working hours or on weekends

The subject user's name is unknown or unexpected to you (e.g. "adm.old.2008" creating new Windows users)

The target user's name does not follow a usual naming pattern (e.g. "backup" instead of "thm_svc_backup")

### 3) If you confirmed that the action was malicious, find out the login details:

Copy the Logon ID field from your 4720 / 4732 event

Find the corresponding login event with the same Logon ID

Refer to the workbooks from the previous task for further analysis

### 4) Resetting Passwords

Detect it with Security event ID: 4724

#### In short: here are the event IDs to use to detect a potential backdoored user:

1) 4720 (User account created)

2) 4732 (Account was added to a security/privileged group)

3) 4724 (User account password reset)
