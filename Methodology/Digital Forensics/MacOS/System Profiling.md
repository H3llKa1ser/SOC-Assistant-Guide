# System Profiling

### 1) OS Version

View System information (Mount the System volume first)

    cat /System/Library/CoreServices/SystemVersion.plist

### 2) Serial Number

Locations:

    /private/var/folders/*/<DARWIN_USER_DIR>/C/locationd/consolidated.db
    /private/var/folders/*/<DARWIN_USER_DIR>/C/locationd/cache_encryptedA.db

In DB Browser for SQLite, after loading the files, to see the serial number, go to 

    Browse Data -> TableInfo table

### 3) OS Installation date

    stat -x /private/var/db/.AppleSetupDone

More details about OS Installation and updates

    cat /private/var/db/softwareupdate/journal.plist

### 4) Time Zone

Current time zone

    ls -la /etc/localtime 

Alternative way to check

    plutil -p /Library/Preferences/.GlobalPreferences.plist

Check if location services are active

    plutil -p /Library/Preferences/com.apple.timezone.auto.plist

### 5) Boot, Reboot and Shutdown times

    zgrep BOOT_TIME system.log.* 

Check for shutdown events

    log show --info --predicate 'eventMessage contains "com.apple.system.loginwindow" and eventMessage contains "SessionAgentNotificationCenter"' 
