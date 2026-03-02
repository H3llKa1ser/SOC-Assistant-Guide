# User Activity

## Tracking Sessions

### 1) Dump user sessions from memory

    vol -f MEMDUMP.mem windows.sessions > sessions.txt

### 2) Dump loaded registry hives

    vol -f MEMDUMP.mem windows.registry.hivelist > hivelist.txt

### 3) GUI activity (UserAssist)

    vol -f MEMDUMP.mem windows.registry.userassist > userassist.txt
