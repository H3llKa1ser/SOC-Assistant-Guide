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

#### 1) A different parent process other than system (4)

#### 2) The image path is different from C:\Windows\System32

#### 3) More than one running process. (Children self-terminate and exit after each new session)

#### 4) The running user is not SYSTEM user

#### 5) Unexpected registry entries for subsystem

## Client Server Runtime Subsystem (csrss.exe)

#### It's the user mode of the windows subsystem. This process is always running and is critical to system operation. If this process is terminated by chance, it will result in system failure.

#### This process is responsible for the Win32 console window and process thread creation and deletion.

#### This process is also responsible for making the windows API available to other processes, handling the windows shutdown process.

### Note: csrss.exe and winlogon.exe are called from smss.exe at startup for session 1

#### PID = 392 (session 0) 512 (session 1)

#### Image Path = %SYSTEMROOT%\System32\csrss.exe

#### Parent Process = Created by an instance of smss.exe

#### Number of instances = 2 or more

#### User account = Local System

#### Start Time = Within seconds of boot time for the first 2 instances (session 0/1). Start times for additional instances occur as new sessions are created, although only sessions 0 and 1 are often created.

## UNUSUAL BEHAVIOR

#### 1) An actual parent process (smss.exe calls this process and self-terminates)

#### 2) Image file path other than C:\\Windows\System32

#### 3) Subtle misspellings to hide rogue processes, masquerading as csrss.exe in plain sight

#### 4) The user is not SYSTEM
