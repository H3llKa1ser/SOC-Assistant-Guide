# Microsoft Edge

Tools: 

1) ChromeCacheView

Location:

    C:\Users\USER\AppData\Local\Microsoft\Edge\User Data\Default

### 1) Locate user directory for Microsoft Edge artifacts

    ls C:\Users\ | foreach {ls "C:\Users\$_\AppData\Local\Microsoft\Edge\User Data\Default" 2>$null | findstr Directory}

### 2) Load a user's cache data with ChromeCacheView

Go to:

    File -> Select Cache Folder -> Browse for Cache_Data file of the user of your choice -> OK
