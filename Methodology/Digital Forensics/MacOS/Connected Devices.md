# Connected Devices

### 1) Mounted Volumes

Check the FXDesktopVolumesPositions key

    plutil -p /Users/USER/Library/Preferences/com.apple.finder.plist

### 2) iDevices

    plutil -p /Users/USER/Library/Preferences/com.apple.iPod.plist 

### 3) Bluetooth Connections

File:

    knowledgeC.db

Information to look for:

    /bluetooth/isConnected

Module: APOLLO'S knowledge_audio_bluetooth_connected

### 4) Printers

    plutil -p /Users/USER/Library/Preferences/org.cups.PrintingPrefs.plist 
