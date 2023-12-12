# SYSMON (SYSINTERNALS)

## EVENT IDs

### ID 1 = Process Creation (Looks for processes that have been created)

### ID 3 = Network Connection (Looks for events that occur remotely)

### ID 7 = Image Loaded (Used when hunting DLL injection and DLL hijacking attacks)

### ID 8 = CreateRemoteThead (Monitors for processes injecting code into other processes)

### ID 11 = File Created

### ID 12/13/14 = Registry Event

### ID 15 = FileCreateStreamHash (Searches for files created in an alternate data stream ADS)

### ID 22 = DNS Event (Logs all DNS queries and events)

#### Sysmon can use config files like SwiftOnSecurity and ION-Storm

## SYSMON BEST PRACTICES

#### Exclude > Include

#### CLI gives you further control (Get-WinEvent, wevtutil.exe)

#### Know your environment before implementation
