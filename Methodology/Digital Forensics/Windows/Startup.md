# Startup

### 1) List boot startup programs

Tool: Autorunsc (Sysinternals)

    .\autorunsc64.exe -a b * -h | tee boot.txt

### 2) List programs and commands executed in startup sequence

    Get-CimInstance Win32_StartupCommand | Select-Object Name, command, Location, User | fl | tee autorun-cmds.txt

### 3) List user logon startup programs

Tool: Autorunsc (Sysinternals)

    .\autorunsc64.exe -a l * -h | tee logon.txt

### 4) Get details for logon and user initialization registry keys

    $winlogonPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"; "Userinit: $((Get-ItemProperty -Path $winlogonPath -Name 'Userinit').Userinit)"; "Shell: $((Get-ItemProperty -Path $winlogonPath -Name 'Shell').Shell)"

### 5) List details of a registry key

    Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\NetSh" | tee netsh-records.txt
