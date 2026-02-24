# Accounts

### 1) User account details

    sudo cat /private/var/db/dslocal/nodes/Default/users/USER.plist 

### 2) User login history

    plutil -p /Library/Preferences/com.apple.loginwindow.plist

### 3) SSH Connections

    cat .ssh/known_hosts

### 4) Privileged accounts

    sudo cat /etc/sudoers

### 5) Login and logout events

Login event: USER_PROCESS

Logout event: DEAD_PROCESS

    zgrep login system.log*

#### Find login events

    grep USER_PROCESS asl.csv

### 6) Screen locl/unlock

#### Read from parsed unified logs

    grep com.apple.sessionagent.screenIsLocked output.csv
    grep com.apple.sessionagent.screenIsUnlocked output.csv
