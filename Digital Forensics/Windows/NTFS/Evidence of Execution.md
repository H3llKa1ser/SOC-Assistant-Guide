# Windows Prefetch Files

### Location: C:\Windows\prefetch (Extension: .pf)

#### Prefetch files contain the last run times of the app, the number of times the app was run and any files and devices handles used by the file

### Tool: Prefetch Parser (PECmd.exe EZTools)

# Windows 10 Timeline

### Location: C:\Users\USER\AppData\Local\ConnectedDevicesPlatform\{randomfolder}\ActivitiesCache.db

#### Windows 10 stores recently used apps and files in an SQLite database called the windows 10 timeline.

#### It contains the application that was executed and the focus time of the application.

### Tool: WxTCmd.exe EZTools

# Windows Jump Lists

### Location: C:\Users\USER\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations

#### Jumplists help users go directly to their recently used files from the taskbar.

#### We can view jumplists by right-clicking an application's icon in the taskbar.

#### Jumplists include info about the apps executed, first and last time of execution of the application against an AppID.

### Tool: JLECmd.exe EZTools

# Shortcut Files

### Locations: 

### C:\Users\USER\AppData\Roaming\Microsoft\Windows\Recent

### C:\Users\USER\AppData\Roaming\Microsoft\Office\Recent

#### Shortcut files contain information about the first and last opened times of the file and path of the opened file, along with some other data.

### Tool: Lnk Explorer (LECmd.exe EZTools)

# Internet Explorer/Microsoft Edge history

### Location: C:\Users\USER\AppData\Local\Microsoft\Windows\WebCache\WebCacheV*.dat

### File prefix in the browser history file: file://*

#### IE/Edge browsing history includes files opened in the system as well, whether those files were opened using the browser or not.

### Tool: Autopsy

# External Devices/USB device forensics

### Location: C:\Windows\inf\setupapi.dev.log

#### Any related info about the setup of a device newly attached to a system is stored in setupapi.dev.log

#### This log contains the device serial number and the first/last time when the device was connected.
