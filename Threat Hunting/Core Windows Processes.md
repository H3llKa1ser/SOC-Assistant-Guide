# CORE WINDOWS PROCESSES AND HOW TO DETECT MALICIOUS BEHAVIOR

## System

#### PID = 4

#### Image Path = N/A

#### Parent Process = None

#### Number of instances = One

#### User account = Local System

#### Start time = At boot time

### UNUSUAL BEHAVIORS

#### 1) A parent process (aside from System Idle process (0))

#### 2) Multiple instances of "System" (should only be one instance)

#### 3) A different PID (PID IS ALWAYS 4)

#### 4) Not running in session 0

## Session Manager Subsystem (smss.exe) AKA Windows Session Manager

#### This process starts the kernel and user modes of the Windows Subsystem (win32k.sys(kernel mode), winsrv.dll (user mode) csrss.exe (user mode)

## Session 0 = Isolated windows session for the operating system 

## Session 1 = User session  (AKA Userland)

#### smss.exe is also responsible for creating environment variables, virtual memory paging files and starts winlogon.exe

#### Image Path = %SYSTEMROOT%\System32\smss.exe

#### Parent Process = System

#### Number of instances = One master instance and child instance per session. The child iunstance exits after creating the session.

#### User account = Local System

#### Start time = Within seconds of boot time for the master instance

## UNUSUAL BEHAVIORS

