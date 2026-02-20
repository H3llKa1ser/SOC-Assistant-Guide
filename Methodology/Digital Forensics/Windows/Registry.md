# Registry

Tools:

1) Registry Explorer (Eric Zimmerman Tools)

2) Regedit

3) FTK Imager

4) RECmd (Eric Zimmerman Tools)

5) RegRipper

Important registry hives location

    C:\Windows\System32\config\
    C:\Users\USER\ (NTUSER.dat)

Important registry hives:

1) NTUSER.dat

2) SAM

3) SYSTEM

4) SOFTWARE

## File Explorer

### 1) TypedPaths registry key

Identify directories searched or accessed through the file explorer's address bar.

Location

    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths

### 2) WordWheel Query registry key

Keeps track of all the terms searched in file explorer.

Location: 

    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery

### 3) RecentDocs registry key

Identify information about recently accessed documents.

Location:

    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs

### 4) Comdlg32 (Common dialogue box)

This is used by applications to allow users to btowse files or folders.

Important registry keys:

#### LastVisitedMRU (Most Recently Used)

Contains entries like folder paths the user has navigated to or accessed.

Location:

    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU

#### OpenSaveMRU

Contains information about most recently saved files and folders.

Location: 

    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU

### 5) User Assist registry key

Records usage of programs and files.

Location:

    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist

Important info:

1) Windows Explorer

        {CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}

2) Shortcut files or .lnk

        {F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}

### 6) RunMRU registry key

Stores information about the most recently executed prorgams via Run dialogue window.

Location: 

    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU

### 7) Persistence on Startup

Location:

    HKLM\Software\Microsoft\Windows\CurrentVersion\Run

## Amcache (Appcompatcache/Shimcache)

Use this to extract artifacts to prove evidence of execution

Tools:

1) AmcacheParser (Eric Zimmerman Tools)

2) Timeline Explorer (Eric Zimmerman Tools)

3) AppCompatCacheParser

#### TIP: AmCache refreshes itself every restart

### 1) Parse AmCache file

    .\AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" --csv C:\Users\Administrator\Desktop --csvf Amcache_Parsed.csv

### 2) Parse ShimCache file

    .\AppCompatCacheParser.exe --csv output

## ShellBags

Tools:

1) ShellBags Explorer (Eric Zimmerman Tools)

2) Regedit

Give information about which folders were accessed, when and how they were viewed.

Important key hives

1) NTUSER.dat

        %USERPROFILE%\NTUSER.dat

2) USRCLASS.dat

        %USERPROFILE%\AppData\Local\Microsoft\Windows\UsrClass.dat

### 1) Main registry hive

Location:

    Computer\HKEY_CURRENT_USER\Software\Classes\Local Settings\Software\Microsoft\Windows\Shell

## Data Extraction

### 1) Search for a text in key names in a specific registry

    RECmd.exe -f c:\Users\Administrator\Desktop\collection\c\windows\System32\config\SAM --sk TEXT

### 2) View key details

    RECmd.exe -f c:\Users\Administrator\Desktop\collection\c\windows\System32\config\SAM --kn SAM\Domains\Account\Users\Names\Administrator
