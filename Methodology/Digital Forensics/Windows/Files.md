# Files

Tools:

1) LECmd (Eric Zimmerman Tools)

2) Timeline Explorer (Eric Zimmerman Tools)

## Recently Accessed Files

#### .LNK Files location

    C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent Items

### 1) Parse LNK files

    .\LECmd.exe -d C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent --csvf Parsed-LNK.csv --csv C:\Users\Administrator\Desktop

### 2) Parse a specific LNK file

    .\LECmd.exe -f C:\Users\USER\AppData\Roaming\Microsoft\Windows\Recent\FILE.lnk

Then, run the TimelineExplorer program and drag the .csv file to it for analysis

## File Execution

Tools:

1) PECmd (Eric Zimmerman Tools)

2) Timeline Explorer (Eric Zimmerman Tools)

#### Prefetch location

    C:\Windows\Prefetch

### 1) Parse Prefetch files

    .\PECmd.exe -d "C:\Windows\Prefetch" --csv C:\Users\Administrator\Desktop --csvf Prefetch-Parsed.csv

## Amcache (Appcompatcache/Shimcache)

Tools:

1) AmcacheParser (Eric Zimmerman Tools)

2) Timeline Explorer (Eric Zimmerman Tools)

#### TIP: AmCache refreshes itself every restart

### 1) Parse AmCache hile

    .\AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" --csv C:\Users\Administrator\Desktop --csvf Amcache_Parsed.csv

## Jump Lists

They note which files were opened, what apps were used and which websites were visited.

Tools:

1) JumpListExplorer (Eric Zimmerman Tools)

Locations:

    %APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations
    %APPDATA%\Microsoft\Windows\Recent\CustomDestinations
