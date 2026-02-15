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

### 4) Pspy

Leave it for a few minutes to gather any running processes in the system for analysis.

    pspy64

## Services

### 1) List all system services

    sudo systemctl list-units --all --type=service

### 2) List running services

    sudo systemctl list-units --type=service --state=running

### 3) Check the status of a specific service

    sudo systemctl status SERVICE_NAME.service

After that, you can view the associated executable for the service.

### 4) Inspect service configuration files

    cat /etc/systemd/system/SERVICE_NAME.service

### 5) Inspect service logs

    sudo journalctl -f -u SERVICE_NAME.service

## Autostart Scripts

### 1) System scripts

    /etc/init.d/
    /etc/rc.d/
    /etc/systemd/system/

### 2) User scripts

    ~/.config/autostart/
    ~/.config/

User scripts format

    .desktop

## Application and Browser Artifacts

### 1) Verify which applications have been installed on the system

    sudo dpkg -l

### 2) Search for hidden information files from text editors

Vim

    find /home/ -type f -name ".viminfo" 2>/dev/null

Nano

    find /home/ -type f -name ".nano_history" 2>/dev/null

Emacs

    find /home/ -type f -name ".emacs" 2>/dev/null
    find /home/ -type f -name ".emacs.d" 2>/dev/null

### 3) Search for browser data in all users' home directories

    sudo find /home -type d \( -path "*/.mozilla/firefox" -o -path "*/.config/google-chrome" \) 2>/dev/null

### 4) Check the contents of the browser directory of a user to enumerate their profile

    sudo ls -al /home/USER/.mozilla/firefox

### 5) Dump all browser data for a specific user

    dumpzilla '/home/USER/.mozilla/firefox/fsd89fs8df90.default/' --All
