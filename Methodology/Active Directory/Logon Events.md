# Logon Events

## Event IDs

| Event ID | What Happened |
|---------|---------------|
| 4624 | Successful logon |
| 4625 | Failed logon |

## Logon Types

| Type | Meaning | Example |
|-----|--------|---------|
| 2 | Interactive | User at keyboard, physical console |
| 3 | Network | File share access, WMI queries, remote administration |
| 4 | Batch | Scheduled tasks running under a user account |
| 5 | Service | Windows services starting under a service account |
| 7 | Unlock | User unlocking a previously locked workstation |
| 10 | RemoteInteractive | RDP session |

## Logon Types for Lateral Movement Indicators

| Logon Type | Meaning | Common Protocol | What It Tells Us |
|------------|--------|-----------------|------------------|
| 3 | Network logon | SMB, PsExec | Remote access without an interactive session |
| 7 | Unlock/Reconnect | RDP | Session reconnect or workstation unlock |
| 10 | RemoteInteractive | RDP | Full desktop session |

### 1) Check distribution of logon types

    index=* EventCode=4624
    | stats count by Logon_Type
    | sort -count
