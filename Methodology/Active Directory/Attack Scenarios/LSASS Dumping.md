# LSASS Dumping

#### Event ID

- 10 (Sysmon)

Resource: https://www.splunk.com/en_us/blog/security/you-bet-your-lsass-hunting-lsass-access.html

## Detection fields

| Field            | What It Contains                                         | Why It Matters                                                                                           |
|------------------|----------------------------------------------------------|----------------------------------------------------------------------------------------------------------|
| **SourceImage**  | Full path of the process accessing LSASS                  | Identifies the tool used for the dump                                                                    |
| **SourceUser**   | The user account running the source process               | Identifies the compromised account — `SYSTEM` is expected; a domain user account is suspicious           |
| **TargetImage**  | Full path of the target process (`lsass.exe`)              | Confirms LSASS was the target                                                                            |
| **GrantedAccess**| Hex access mask showing requested permissions             | Different dumping tools request different access levels                                                  |
| **CallTrace**    | DLL call stack leading to the access                      | Reveals the method used (MiniDump API, injection, etc.)                                                  |

## GrantedAccess Field

| Access Right                       | Hex Value   | Purpose                                 |
|-------------------------------------|-------------|-----------------------------------------|
| **PROCESS_QUERY_LIMITED_INFORMATION** | `0x1000`   | Query basic process information         |
| **PROCESS_QUERY_INFORMATION**         | `0x0400`   | Query detailed process information      |
| **PROCESS_VM_READ**                   | `0x0010`   | Read process memory                      |
| **PROCESS_ALL_ACCESS**                | `0x1FFFFF` | Full access to the process               |

## CallTrace Field

#### Detect different dump methods:

1) Known DLLs like dbgcore.dll and dbghelp.dll indicate the MiniDump API was used. This is how ProcDump and comsvcs.dll create memory dumps. It's a legitimate API being used for a malicious purpose.

2) UNKNOWN memory offsets (addresses not mapped to any known DLL) indicate injected code. This is the signature of Cobalt Strike beacons, Meterpreter, and other in-memory implants that access LSASS from injected shellcode.


## Legitimate Windows Operations

| Full Process Path                         | Typical GrantedAccess | Why                                                                                       |
|-------------------------------------------|------------------------|-------------------------------------------------------------------------------------------|
| `C:\Windows\System32\csrss.exe`           | `0x1000` or `0x1400`   | Windows subsystem, manages processes                                                      |
| `C:\Windows\System32\WerFault.exe`        | `0x1000`               | Windows Error Reporting crash handler                                                     |
| `C:\Windows\System32\svchost.exe`         | `0x1010`               | Various service functions; normal at this access level                                    |
| AV/EDR agent paths                        | Varies                 | Security products monitor LSASS to provide protection                                     |

## Splunk Queries

### 1) See every process that accessed LSASS

    index=task4 EventCode=10 TargetImage="*\\lsass.exe"
    | stats count by SourceImage, GrantedAccess

### 2) Identify the suspicious process from previous query, then examine its CallTrace to understand the method used for the dump

    index=task4 EventCode=10 TargetImage="*\\lsass.exe" SourceImage={SUSPICIOUS_PROCESS}
    | table _time, SourceImage, SourceUser, GrantedAccess, CallTrace

