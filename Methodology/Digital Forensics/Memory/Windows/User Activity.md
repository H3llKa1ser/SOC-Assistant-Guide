# User Activity

Tools:

1) Volatility

2) oletools https://github.com/decalage2/oletools/blob/master/oletools/olevba.py

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

## User Execution

### 1) Dump files from a specific process

    vol -f MEMDUMP.mem -o PID/ windows.dumpfiles --pid PID

Identify target file in the dump

    ls PID/ | grep dotm

Copy file out of the dump directory for analysis

    cp PID/FILE.dotm.dat .

Confirm the file type

    file FILE.dotm.dat

### 2) Confirm Macro Execution

Unzip the .dotm.dat file

    unzip FILE.dotm.dat

Extract potentially malicious macro

    olevba word/vbaProject.bin
