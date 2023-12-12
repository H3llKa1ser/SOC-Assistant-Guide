# EVIDENCE OF EXECUTION

## User Assist

#### Contains information about the programs that launched, when they launched and how many times they were executed. (Can't find CLI programs)

### Location: NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count

## Shimcache AKA Application Compatibility Cache

## Tool to use: AppCompatCache Parser

## Example: AppCompatCacheParser.exe --csv PATH/TO/SAVE/OUTPUT -f PATH/TO/SYSTEM/HIVE/FOR_DATA_PARSING -c CONTROL_SET_TO_PARSE

### Location: SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache

## Last Executed Programs

### Location: C:\Windows\appcompat\Programs\AmCache.hve\Root\File\{Volume GUID}\

## Background Activity Monitor / Desktop Activity Moderator (BAM/DAM)

### Locations:

### SYSTEM\CurrentControlSet\Services\bam\Usersettings\{SID}

### SYSTEM\CurrentControlSet\Services\dam\Usersettings\{SID}
