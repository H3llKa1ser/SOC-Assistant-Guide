# Microsoft Edge

Tools: 

1) ChromeCacheView

2) Hindsight

Location:

    C:\Users\USER\AppData\Local\Microsoft\Edge\User Data\Default

### 1) Locate user directory for Microsoft Edge artifacts

    ls C:\Users\ | foreach {ls "C:\Users\$_\AppData\Local\Microsoft\Edge\User Data\Default" 2>$null | findstr Directory}

### 2) Load a user's cache data with ChromeCacheView

Go to:

    File -> Select Cache Folder -> Browse for Cache_Data file of the user of your choice -> OK

### 3) Use Hindsight GUI tool to investigate

Launch the server locally

    .\hindsight_gui.exe

Access URL on any browser

    http://localhost:8080/

In the Profile Path, insert your target user's Default directory profile, then click run.

    C:\Users\USER\AppData\Local\Microsoft\Edge\User Data\Default

Load the results using SQLite DB in browser OR you can save the resutls in a DB file.

    View SQLite DB in Browser
    Save SQLite DB

#### SQL Queries to use

Investigate URLs visited by the user

    SELECT timestamp,url,title,visit_duration,visit_count,typed_count FROM 'timeline' WHERE type = 'url' LIMIT 0,30

Investigate download attempts made

    SELECT timestamp,url,title,value FROM timeline WHERE type = 'download' LIMIT 0,30

View cookies' metadata

    SELECT type,origin,key,value FROM 'storage' LIMIT 0,30

