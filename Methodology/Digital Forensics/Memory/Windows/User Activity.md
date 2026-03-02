# User Activity

## Tracking Sessions

### 1) Dump user sessions from memory

    vol -f MEMDUMP.mem windows.sessions > sessions.txt

### 2) Dump loaded registry hives

    vol -f MEMDUMP.mem windows.registry.hivelist > hivelist.txt

### 3) GUI activity (UserAssist)

    vol -f MEMDUMP.mem windows.registry.userassist > userassist.txt

## File Access and Command Execution

### 1) Investigate processes and file executions

    vol -f MEMDUMP.mem windows.cmdline > cmdline.txt

### 2) File Access

    vol -f MEMDUMP.mem windows.handles > handles.txt

Search for target process

    cat handles.txt | grep PROCESS_NAME

