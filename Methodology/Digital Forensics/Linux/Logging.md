# Logging

### 1) View kernel logs

    cat /var/log/kern.log
    cat /var/log/dmesg

Search for a specific event

    sudo dmesg -T | grep 'whatever'

### 2) View authentication logs

    cat /var/log/auth.log

Search for successful logins

    grep 'Accepted password' /var/log/auth.log

Search for elevated privilege command execution

    grep 'sudo' /var/log/auth.log

Search for failed login attempts

    cat /var/log/btmp

Search for every login and logout activity

    cat /var/log/wtmp

### 3) View system messages

    cat /var/log/syslog

Search for crontabs messages

    grep 'CRON' /var/log/syslog

Search for kernel messages

    grep 'kernel' /var/log/syslog

Syslog configuration file

    /etc/rsyslog.conf
    /etc/syslog.conf
    /etc/rsyslog.d/50-default.conf

### 4) Journal

Configuration file

    /etc/systemd/journald.conf

Filter logs by date and time

    sudo journalctl --since "YYYY-MM-DD HH:MM:SS" --until "YYYY-MM-DD HH:MM:SS"

Filter logs by a specific time

    sudo journalctl --since "1 hour ago"

Filter logs by service

    sudo journalctl -u SERVICE_NAME.service

Filter logs by priority

    sudo journalctl -p crit
