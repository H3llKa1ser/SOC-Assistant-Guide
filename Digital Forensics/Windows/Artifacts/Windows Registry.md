## Tool to access registry: regedit.exe

### Notes: MRU = Most Recently Used

## Structure of the registry:

### 1) HKEY_CURRENTUSER (HKCU)

### 2) HKEY_USERS (HKU)

### 3) HKEY_LOCAL_MACHINE (HKLM)

### 4) HKEY_CLASSES_ROOT (HKCR)

### 5) HKEY_CURRENT_CONFIG 

## REGISTRY HIVES

### Location: C:\Windows\System32\Config

### 1) DEFAULT (HKEY_USERS\DEFAULT)

### 2) SAM (HKLM\SAM)

### 3) SECURITY (HKLM\SECURITY)

### 4) SOFTWARE (HKLM\Software)

### 5) SYSTEM (HKLM\SYSTEM)

## HIVES CONTAINING USER INFORMATION

### 1) NTUSER.DAT(HKCU when a user logs in) (Located in C:\Users\USERNAME\)

### 2) USRCLASS.DAT (HKCU\Software\CLASSES) (Located in C:\Users\USER\AppData\Local\Microsoft\Windows)

#### Note: These 2 files are hidden files

## AmCache File

#### Windows creates this hive to save information on programs that were recently run on the system.

### Located: C:\Windows\AppCompat\Programs\AmCache.hve

## TRANSACTION LOGS AND BACKUPS

### The transaction log for each hive is stored as a .LOG file in the same directory as the hive itself.

### Transaction logs are considered as the journal of the changelog of the registry hive.

### Transaction logs can have the latest changes in the registry that haven't made their way to the registry hives themselves.

### Registry backups are the opposite of transaction logs.

### The backups of the registry hives are located in C:\Windows\System32\Config\RegBack every 10 days.

# WHERE TO LOOK FOR DATA IN THE REGISTRY?

## OS Version

### Location: SOFTWARE\Microsoft\Windows NT\CurrentVersion

## Control set that the machine booted with

### Location: SYSTEM\ControlSet001

## Last known good configuration 

### Location: SYSTEM\ControlSet002 SYSTEM\Select\LastKnownGood

## Most accurate system information (Current control set)

### Location: HKLM\SYSTEM\CurrentControlSet

## Computer Name

### Location: SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName

## Timezone Information

### Location: SYSTEM\CurrentControlSet\Control\TimeZoneInformation

## Network Interfaces and past networks

### Location: SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\interfaces

## Past networks and last time connection

### Location: SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Unmanaged SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Signatures\Managed

## Info about services

### Location: SYSTEM\CurrentControlSet\Services (Start key 0x02 = Service will start at boot)

## Autostart programs AKA Autoruns

### Locations:

### NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Run

### NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\RunOnce

### Software\Microsoft\Windows\CurrentVersion\RunOnce

### Software\Microsoft\Windows\CurrentVersion\policies\Explorer\run

### Software\Microsoft\Windows\CurrentVersion\Run

## SAM hive and user information

### Location: SAM\Domains\Account\Users

## Recently Opened Files

### Location: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\"Insert File extension here e.g. PDF"

## Microsoft Office

### Location: NTUSER.DAT\Software\Microsoft\Office\VERSION

## Office 365

### Location: NTUSER.DAT\Software\Microsoft\Office\VERSION\UserMRU\LiveID_####\FileMRU
