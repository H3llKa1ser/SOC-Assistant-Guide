# Startup

### 1) List boot startup programs

Tool: Autorunsc (Sysinternals)

    .\autorunsc64.exe -a b * -h | tee boot.txt

### 2) List programs and commands executed in startup sequence

    Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | fl | tee autorun-cmds.txt

### 3) List user logon startup programs

Tool: Autorunsc (Sysinternals)

    .\autorunsc64.exe -a l * -h | tee logon.txt

