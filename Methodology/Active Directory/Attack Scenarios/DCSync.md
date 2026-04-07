# DCSync

## Detection Indicators

- DS-Replication-Get-Changes-All {1131f6ad-9c07-11d1-f79f-00c04fc2dcd2}

- NON-machine account (no $) tries to replicate DC.

## Detection Requirements

1) Enable "Audit Directory Security Access via Group Policy.

2) A SACL (System Access Control List) must be set on the domain partition to audit replication operations.

#### Event ID

- 4662

## Detection Fields

| Field         | What It Contains                                          | Why It Matters                                                                               |
|---------------|-----------------------------------------------------------|----------------------------------------------------------------------------------------------|
| **user**      | The account performing the replication                     | Identifies who is running DCSync                                                             |
| **Access_Mask** | `0x100` (Control Access)                                 | Indicates an extended right was exercised                                                    |
| **Properties** | Shows "Control Access" (GUIDs in raw event)               | The replication GUIDs confirm DCSync                                                         |
| **Logon_ID**  | Hex session identifier                                     | Links to event 4624 (logon) for source IP correlation                                        |

## Normal vs Suspicious Replication

| Pattern       | Normal                                                     | Suspicious                                                                                  |
|---------------|------------------------------------------------------------|---------------------------------------------------------------------------------------------|
| **user**      | Machine account ending in `$` (e.g., `THM-DC$`)             | Human user account (not ending in `$`)                                                      |
| **Source host** | Another domain controller                                 | A workstation or non-DC server                                                              |
| **Frequency** | Regular intervals matching replication schedule            | One-time or burst of requests                                                               |
| **Scope**     | Specific partition changes                                  | Requesting all credentials (`-just-dc-ntlm` or full dump)                                   |

## Splunk Queries

### 1) Isolate any human user performing DC replication (remove the $ filter to monitor all accounts)

    index=task5 EventCode=4662 "1131f6ad" user!="*$"
    | table _time, user, Access_Mask, Properties
    | sort _time

### 2) Identify the compromised user

    index=task5 EventCode=4662 Access_Mask=0x100 user={COMPROMISED_USER} "1131f6ad"
    | table _time, host, user, Logon_ID

### 3) Identify the source IP Address and Logon Type

    index=task5 EventCode=4624 Logon_ID={LOGON_ID}
    | table _time, host, user, Source_Network_Address, Logon_Type
