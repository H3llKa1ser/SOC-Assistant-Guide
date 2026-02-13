# Processes

### 1) View processes

    ps aux

### 2) View processes specific to a user

    ps -u USER

### 3) Get a comprehensive view of al processes on the system in a hierarchical format

    ps -eFH

### 4) View any files associated with a process

    sudo lsof -p PID

### 5) List the parent processes as well as their PIDs of a specific process

    pstree -p -s PID

### 6) Filter specific processes

    ps -f PID_1 PID_2 PID_3

### 7) Dynamically investigate processes

    top -d SECONDS -c -u USER

# Cronjobs

Tools and resources:

1) Pspy: https://github.com/DominicBreuker/pspy

2) Crontab Guru: https://crontab.guru/

### 1) Check for system-wide crontabs

    cat /etc/crontab

More system cronjob directory locations

    /etc/cron.hourly
    /etc/cron.daily
    /etc/cron.weekly
    /etc/cron.monthly
    /etc/cron.d

### 2) Check for user-level crontabs

    ls -la /var/spool/cron/crontabs

View contents and crontabs of a specific user

    crontab -l -u USER

One-Liner for investigating crontabs for each user in the system

    sudo bash -c 'for user in $(cut -f1 -d: /etc/passwd); do entries=$(crontab -u $user -l 2>/dev/null | grep -v "^#"); if [ -n "$entries" ]; then echo "$user: Crontab entry found!"; echo "$entries"; echo; fi; done'

### 3) Filter contents for any logs related to cron

    sudo grep cron /var/log/syslog

Check for failed cron logs

    sudo grep cron /var/log/syslog | grep -E 'failed|error|fatal'

Filter for specific users

    sudo grep cron /var/log/syslog | grep -i 'USER'
