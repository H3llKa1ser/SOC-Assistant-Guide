# Artifacts

## Plist files (Property list)

Extension: .plist

### 1) Read BLOB files

##### MacOS

    plutil -p FILE.plist

##### Linux

Link: https://github.com/libimobiledevice/libplist

    plistutil -p FILE.plist

## Database files

Extension: .db

Tools: 

1) DB Browser for SQLite https://sqlitebrowser.org/

2) APOLLO https://github.com/mac4n6/APOLLO

### 1) Extract information from database files

    python3 apollo.py extract -osql_json -pyolo -vyolo modules tmp_apollo 

## Logs

### 1) Apple System Logs (ASL)

Location:

    open -a Console /private/var/log/asl/LOG.asl

##### Parse asl log files

Tool: https://github.com/ydkhatri/mac_apt

### 2) System Logs

Location:

    /private/var/log/system.log

##### Read logs

    zgrep KEYWORD system.log*

### 3) Unified Logs

Locations:

    /private/var/db/diagnostics/*.tracev3
    /private/var/db/uuidtext

##### Parse logs

Tools: 

1) Unified Logs Parser https://github.com/mandiant/macos-UnifiedLogs

2) Mac_apt: https://github.com/ydkhatri/mac_apt

##### Show logs on a last specific timeframe

    log show --last 1m (Lats minute example)

##### Filter the logs for specific information

    log show --predicate 'subsystem=="com.apple.sharing" and category=="AirDrop" and eventMessage contains "Discoverable"'
