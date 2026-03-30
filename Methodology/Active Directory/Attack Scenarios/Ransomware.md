# Ransomware

## Pre-Encryption Detection

### 1) Delete shadow copies

vssadmin.exe

    vssadmin.exe delete Shadows /all /quiet

wmic.exe

    wmic shadowcopy delete /nointeractive

#### Event IDs

    1 (Sysmon)
    4688 (Windows Event Security Logs)

### 2) Delete backups

reagentc.exe

    reagentc.exe /disable

wbadmin.exe

    wbadmin.exe delete catalog -quiet

#### Event IDs:

    4688 (Windows Event Security Logs)
    1 (Sysmon)

### 3) Delete Logs

PowerShell

    Clear-EventLog -LogName Security

wevtutil

    wevtutil cl System

#### Event IDs

    1 (Sysmon)
    4688 and 1102 (Windows Event Security Logs)

## Ransom Deployment and Encryption Detection

### 1) GPO Deployment

#### Event IDs

Uploaded ransom to SYSVOL share

    11 (Sysmon) in SYSVOL + 5145 (Share Access)

New GPO created on DC
    
    5137 (Directory service object was creatde) + 5136 (Directory service object was modified)

Attacker chooses one method to deploy his ransomware

### Startup

#### Event IDs

    11 (Sysmon) + 5136

Startup configured on targets systems

    13 (Sysmon) on multiple systems

Executing ransom

    1 (Sysmon) OR 4688 on multiple systems

### 2) WMIC

Remote ransomware execution

    wmic /node:IP /user:USER /password:PASSWORD process call create "C:\Users\USER.NAME\AppData\Local\ransom.exe"

#### Event IDs

    1 (Sysmon)

### 3) Scheduled Tasks

schtasks.exe

    schtasks /create /s DC.domain.local /u DOMAIN\USER.NAME /p PASSWORD /tn "Regular System Update New" /tr "C:\WindowszTemp\updater.exe" /sc daily /st 09:00 /ru SYSTEM /f

#### Event IDs

    1 (Sysmon) OR 4688 (Windows Event Security Logs) with process is schtasks OR 4698 (scheduled task creation on destination machines)

### 3) Remote Monitoring and Managenent (RMM)

#### Tools:

AnyDesk
ScreenConnect

#### Event IDs

    1 (Sysmon)
