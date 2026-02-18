# Registry

Tools:

1) Registry Explorer (Eric Zimmerman Tools)

2) Regedit

Important registry hives location

    C:\Windows\System32\config\

Important registry hives:

1) NTUSER.dat

2) SAM

3) SYSTEM

4) SOFTWARE

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

