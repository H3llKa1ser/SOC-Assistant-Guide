# Security Logs

Important event IDs:

1) 4624

2) 4625

Detailed analysis:

| Event ID | Purpose | Logging | Limitations |
|--------|---------|---------|-------------|
| 4624 (Successful Logon) | Detect suspicious RDP or network logins and identify the attack starting point | Logged on the target machine (the system being accessed) | Noisy — hundreds of logon events per minute on heavily loaded servers |
| 4625 (Failed Logon) | Detect brute force, password spraying, or vulnerability scanning | Logged on the target machine (the system being accessed) | Inconsistent — logs contain many caveats that can lead to misinterpretation |

