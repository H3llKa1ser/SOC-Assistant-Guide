# CORE WINDOWS PROCESSES AND HOW TO DETECT MALICIOUS BEHAVIOR

## System

#### PID = 4

#### Image Path = N/A

#### Parent Process = None

#### Number of instances = One

#### User account = Local System

#### Start time = At boot time

## UNUSUAL BEHAVIORS

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

## UNUSUAL BEHAVIORS

#### 1) An actual parent process (smss.exe calls this process and self-terminates)

#### 2) Image file path other than C:\\Windows\System32

#### 3) Subtle misspellings to hide rogue processes, masquerading as csrss.exe in plain sight

#### 4) The user is not SYSTEM

## Wndows Initialization Process (wininit.exe)

#### It's responsible for launching services.exe, lsass.exe and lsaiso.exe within session 0.

#### Note: lsaiso.exe is a process associated with Credential Guard and Keyguard. You will only see this process if Credential Guard is enabled.

#### Image Path = %SYSTEMROOT%\System32\wininit.exe

#### Parent Process = Created by an instance of smss.exe

#### Number of instances = 1

#### Iser account = Local System

#### Start time = Within seconds of boot time

## UNUSUAL BEHAVIORS

#### 1) An actual parent process (smss.exe calls it, then self-terminates)

#### 2) Subtle misspellings to hide rigue processes in plain sight

#### 3) Multiple tunning instances

#### 4) Not running as SYSTEM

## Service Control Manager (services.exe)

#### It's responsible to handle system services: Loading services, interacting with services and starting or ending services.

#### It maintatins a database that can be queried using a windows built-in utility: sc.exe

#### Information regarding services is stored in the registry: HKLM\CurrentControlSet\Services

#### It also loads device drivers marked as auto-start into memory.

#### When a user logs into a machine successfully, this process is responsible for setting the value of Last Known God control set, to that of the CurrentControlSet in registry.

#### This process is the parent of several other key processes: svchost.exe, spoolsv.exe, msmpeng.exe and dllhost.exe

#### Image Path = %SYSTEMROOT%\System32\services.exe

#### Parent process = wininit.exe

#### Number of instances = 1

#### User account = Local System

#### Start time = Within seconds of boot time

## UNUSUAL BEHAVIORS

#### 1) Aparent process other than wininit.exe

#### 2) Image file path other than C:\Windows\System32

#### 3) Subtle misspellings to hide process in plain sight

#### 4) Multiple running instances

#### 5) Not running as SYSTEM

## Service Host (svchost.exe)

#### It's responsible for hosting and managing windows services

#### The services running in this process are implemented as Dynamic Link Libraries (DLL).

#### The DLL to implement is stored in the registry for the service under the "Parameters" subkey in "Service DLL".

#### The full path is "HKLM\SYSTEM\CurrentControlSet\Services\"SERVICE NAME"\Parameters

#### A legitimate svchost.exe process is called with a key identifier that is "-k" in the binary path.

#### Since svchost.exe will always have multiple running processes on any windows system, this process has been a TARGET FOR MALICIOUS USE. 

#### Adversaries create malware to masquerade as this process and try to hide the malware svchost.exe or misspell it slightly, such as "scvhost.exe".

#### By doing so, the intention is to go under the radar. Another tactic is to call/install a malicious service (DLL).

#### Image Path %SYSTEMROOT%\System32\svchost.exe

#### Parent process = services.exe

#### Number of instances = MANY

#### User account = Varies(SYSTEM, Network Service, Local Service, etc) depending on the svchost.exe instance.

#### In windows 10, some instances run as the logged-in user.

#### Start time = Typically within seconds of boot time. Other instances of svchost.exe can be started after boot.

## UNUSUAL BEHAVIORS

#### 1) A parent process other than services.exe

#### 2) Image file path other than c:\windows\system32

#### 3) Subtle misspelings to hide rogue processes in plain sight

#### 4) The absence of the "-k" parameter

## Local Security Authority Subsystem Service (lsass.exe)

#### It's responsible for enforcing the security policy on the system. It verifies users logging on to a windows computer or server, handles password changes and creates access tokens. It also writes to the windows security log.

#### It creates security tokens for Security Account Manager (SAM), Active Directory (AD) and NETLOGON. It uses authentication packages specified in "HKLM\System\CurrentControlSet\Control\Lsa"

#### Lsass.exe is another process adversaries target. Common tools such as Mimikatz are used to dump credentials, or adversaries mimic this process to hide in plain sight.

#### Again, they do this by either naming their malwaer by this process name or simply misspelling the malware slightly.

#### Image Path = %SYSTEMROOT%\System32\lsass.exe

#### Parent process = wininit.exe

#### Number of instances = 1

#### User account = Local system

#### Start time = Within seconds of boot time.

## UNUSUAL BEHAVIORS

#### 1) Aparent process other than wininit.exe

#### 2) Image file path other than C:\Windows\System32

#### 3) Subtle misspellings to hide process in plain sight

#### 4) Multiple running instances

#### 5) Not running as SYSTEM

## Windows Logon (winlogon.exe)

#### It's responsible for handling the Secure Attention Sequence (SAS)

#### It's the CTRL+ALT+DELETE key combination users press to enter username & password.

#### This process is also responsible for loading the user profile. It loads the users NTUSER.DAT into HKCU, and userinit.exe loads the user's shell.

#### It's also responsible for locking the screen and running the user's screensaver, among other functions.

#### Note: smss.exe launches this process along with a copy of csrss.exe within session 1.

#### Image Path = %SYSTEMROOT%\System32\winlogon.exe

#### Parent Process = Created by an instance of smss.exe that exits, so analysis tools do not provide the parent process name.

#### Number of instances = 1 or more

#### User account = Local system

#### Start time = Within seconds of boot time for the first instance (Session 1). Additional instances occur as new sessions are created, typically through Remote Desktop or Fast User Switch Logons.

## UNUSUAL BEHAVIORS

#### 1) An actual process (smss.exe calls this process and self-terminates)

#### 2) Image file path other than C:\Windows\System32

#### 3) Subtle misspellings to hide processes in plain sight.

#### 4) Not running as SYSTEM

#### 5) Shell value is the registry other than explorer.exe

## Windows Explorer (explorer.exe)

#### This process gives the user access to their folders and files.

#### It also provides functionality for other features, such as the Start Menu and Taskbar.

#### Userinit.exe exits after swapning explorer.exe. Because of this, the parent process is non-existent.

#### Image Path = %SYSTEMROOT%\explorer.exe

#### Parent Process = Created by userinit.exe and exits.

#### Number of instances = One or more per interactively logged-in user.

#### User account = Logged-in users

#### Start time = First instance when the first interactive user logon session begins.

## UNUSUAL BEHAVIORS

#### 1) An actual parent process (userinit.exe calls it then exits)

#### 2) Image file path other than C:\Windows

#### 3) Running as an unknown user

#### 4) Subtle misspellings to hide rogue processes in plain sight

#### 5) Outbound TCP/IP Connections
