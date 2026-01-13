# Security Logs

## Authentication

Important event IDs:

1) 4624

2) 4625

Detailed analysis:

| Event ID | Purpose | Logging | Limitations |
|--------|---------|---------|-------------|
| 4624 (Successful Logon) | Detect suspicious RDP or network logins and identify the attack starting point | Logged on the target machine (the system being accessed) | Noisy — hundreds of logon events per minute on heavily loaded servers |
| 4625 (Failed Logon) | Detect brute force, password spraying, or vulnerability scanning | Logged on the target machine (the system being accessed) | Inconsistent — logs contain many caveats that can lead to misinterpretation |

## User Management

Important event IDs are detailed below

| Event ID | Description | Malicious Usage |
|--------|-------------|-----------------|
| 4720 / 4722 / 4738 | A user account was created, enabled, or changed | Attackers may create a backdoor account or enable an old/dormant account to maintain persistence |
| 4725 / 4726 | A user account was disabled or deleted | Advanced threat actors may disable privileged SOC or admin accounts to delay detection and response |
| 4723 / 4724 | A user changed their password or a user’s password was reset | With sufficient permissions, attackers may reset passwords to gain access to target accounts |
| 4732 / 4733 | A user was added to or removed from a security group | Attackers commonly add backdoor accounts to privileged groups such as **Administrators** |

