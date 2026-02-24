# File System

## File System Events Store DB

Locations:

    ./.fseventsd
    /System/Volumes/Data/.fseventsd

Tools:

1) Mac_apt

### 1) Parse the files into .csv or .db format

    sudo python3 mac_apt.py -o . -c MOUNTED / FSEVENTS

## DS Store

Tools:

1) DS_Store-parser https://github.com/hanwenzhu/.DS_Store-parser

### 1) Parse DS Store file

    python3 parse.py /Users/.DS_Store

## Most Recently Used (MRU)

### 1) Check the FXRecentFolders key.

    plutil -p /Users/USER/Library/Preferences/com.apple.finder.plist 

### 2) Check Microsoft Applications

    plutil -p /Users/USER/Library/Containers/com.microsoft.Excel.securebookmarks.plist

