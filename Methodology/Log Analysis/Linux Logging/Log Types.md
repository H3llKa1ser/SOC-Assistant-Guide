# Log Types

Here are various log types you can find in a Linux machine.

## Log file location

    /var/log/

### 1) System log file

Location:

    /var/log/syslog
    /var/log/messages

This log file logs various activities in a Linux system.

#### Filter cronjob logs

    cat /var/log/syslog | grep CRON
    cat /var/log/syslog | grep -v CRON (Exclude cron logs)

#### Filter timesync events

    cat /var/log/syslog | grep "timesync"

### 2) Authentication log file

Location:

    /var/log/auth.log
    /var/log/secure (RHEL)

#### Filter login and logout events

    cat /var/log/auth.log | grep -E 'session opened|session closed'

Types of sessions:

##### 1) Local, on-keyboard login/logout

    pam_unix(login:session)

##### 2) Remote login via SSH

    pam_unix(sshd:session)

##### 3) Remote login via SMB

    pam_unix(samba:session)

##### 4) Cron sessions

    pam_unix(cron:session)

##### 5) Sudo sessions

    pam_unix(sudo:session)

#### Filter SSH logins

    cat /var/log/auth.log | grep "sshd" | grep -E 'Accepted|Failed'

#### Filter launched commands

    cat /var/log/auth.log | grep -E 'COMMAND='

#### Filter user management events

    cat /var/log/auth.log | grep -E '(passwd|useradd|usermod|userdel)\['

### 3) Bash History

    cat /home/user/.bash_history

### 4) Kernel log file

Location

    /var/log/kern.log

### 5) Package Manager log file

Locations:

    /var/log/dpkg.log (Debian)
    /var/log/apt (Debian)
    /var/log/dnf.log (RHEL)
    /var/log/yum.log (RHEL)

 
