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

## Notifications and Permissions

### 1) Notifications

Location:

    /Users/USER/Library/Group\ Containers/group.com.apple.usernoted/db2

Tools: APOLLO's notification_db module

#### TIP: Convert notofication data presented in Hex to ASCII (Cyberchef) and save it as a plist file, then view with plistutil.

### 2) Permissions

Locations:

    /Library/Application Support/com.apple.TCC/TCC.db
    ~/Library/Application Support/com.apple.TCC/TCC.db

Tools: APOLLO's tcc_db module

AUTH_REASON Tab

    2 (User Consent)
    4 (System Set)

## Contacts, Calls and Messages

### 1) Contacts

Location:

    ~/Library/Application Support/AddressBook

Metadata files: .plist

Source files: .db

Contact using apps location:

    /private/var/db/CoreDuet/People/interactionC.db

Tool: APOLLO's interaction_contact_interactions module

#### TIP: If iCloud sync is enabled, it will include all interactions with contacts regardless of the device being accessed from.

### 2) Calls

Location:

    ~/Library/Application Support/CallHistoryDB/CallHistory.storedata

Tool: APOLLO's call_history module

#### Same TIP as above.

### 3) Messages

Locations:

    ~/Library/Messages/chat.db
    ~/Library/Messages/Attachments

Tool: APOLLO's sms_chat module

## Productivity Apps

### 1) Emails

Location:

    ~/Library/Mail/V#/<UUID>/*.mbox

Useful Directories

    All Mail.mbox
    Trash.mbox
    Sent Mail.mbox
    Drafts.mbox

Important file to read:

    plistutil -p Info.plist

Messages and Attachments location example:

    ls * /Users/USER/Library/Mail/V10/DEC2D507-7869-4151-98C3-E2F920A935CF/[Gmail].mbox/All Mail.mbox/708E1A15-F24E-40B5-8A69-FFD9A89FF251/Data

### 2) Calendar

Location:

    ~/Library/Group\ Containers/group.com.apple.calendar/Calendar.sqlitedb

Useful table:

    CalendarItem

Caclulate timestamps:

    Timestamp + 978307200 = Epoch timestamp (Convert to epoch converter to get the date: https://www.epochconverter.com/)

### 3) Notes

Location:

    ~/Library/Group\ Containers/group.com.apple.notes/NoteStore.sqlite

#### Parse the details of the database using mac_apt NOTES module

    python3 mac_apt.py -o OUTPUT -c DD DISK_IMAGE NOTES

Attachments location:

    ~/Library/Group\ Containers/group.com.apple.notes/Accounts/<UUID>/Media

Thumbnails location:

    ~/Library/Group\ Containers/group.com.apple.notes/Accounts/<UUID>/Previews

### 4) Reminders

Location:

    ~/Library/Group\ Containers/group.com.apple.reminders/Container_v1/Stores

Useful table:

    ZREMCDREMINDER

### 5) Office Applications

Locations:

    ~/Library/Containers/com.microsoft.APP/Data
    ~/Library/Containers/com.microsoft.APP/Data/Library/Preferences

View with plistutil / plutil

## Browser History, Downloads and Bookmarks

### 1) Safari

Location:

    ~/Library/Safari

Important files:

    Downloads.plist
    UserNotificationPermissions.plist
    Bookmarks.plist
    History.db

Tool: APOLLO's safari_history module

Safari Cache

    ~/Library/Containers/com.apple.Safari/Data/Library/Caches

Important information:

    TabSnapshots (Session restore)
    WebKitCache (Browser Cache)

### 2) Other Browsers

Similar locations like Safari

#### Chrome

    ~/Library/Application\ Support/Google/Chrome/Default
    ~/Library/Application\ Support/Google/Chrome/Default/Sessions/
    ~/Library/Application\ Support/Google/Chrome/Default/Extensions
