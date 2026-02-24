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

## Autostart

### 1) Launch Agents (User) and Launch Daemons (System)

Locations:

    /System/Library
    /Library
    ~/Library

Tools: plistutil / plutil

### 2) Saved Application State

Locations:

##### Legacy Applications

    ~/Library/Saved Application State/<application>.savedState

##### Sandboxed macOS Applications

    ~/Library/Containers/<application>/Data/Library/Application Support/<application>/Saved Application State/<application>.savedState
