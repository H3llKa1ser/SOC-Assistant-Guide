# Files

Tools:

1) LECmd (Eric Zimmerman Tools)

2) Timeline Explorer (Eric Zimmerman Tools)

## Recently Accessed Files

#### .LNK Files location

    C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent Items

### 1) Parse LNK files

    .\LECmd.exe -d C:\Users\Administrator\AppData\Roaming\Microsoft\Windows\Recent --csvf Parsed-LNK.csv --csv C:\Users\Administrator\Desktop

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

### 1) Parse AmCache hile

    .\AmcacheParser.exe -f "C:\Windows\appcompat\Programs\Amcache.hve" --csv C:\Users\Administrator\Desktop --csvf Amcache_Parsed.csv
