## Tool to access registry: regedit.exe

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
