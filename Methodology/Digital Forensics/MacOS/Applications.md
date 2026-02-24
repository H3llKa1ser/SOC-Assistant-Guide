# Applications

## Common Apps

### 1) Package Containers

Location:

    ls -la /Applications

Extension:

    .app (Is a directory)
    Right-click on an app -> Show Package Contents

### 2) Application Install History

    plistutil -p /Library/Receipts/InstallHistory.plist
    cat /Library/Receipts/InstallHistory.plist

More details about an app

    plutil -p /private/var/db/receipts/APP_NAME.plist

Installation details

    cat /var/log/install.log | grep Installed
