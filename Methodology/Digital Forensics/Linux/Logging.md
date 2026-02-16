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

    sudo grep -i "failure" /var/log/auth.log
    cat /var/log/btmp

Search for every login and logout activity

    cat /var/log/wtmp

Search for sessions opened for a user

    sudo grep -i "session opened" /var/log/auth.log

Filter by date and time

    sudo awk '/2024-06-04 15:30:00/,/2024-06-05 15:29:59/' /var/log/auth.log

Relative time filtering

    sudo grep "$(date --date='2 hours ago' '+%b %e %H:')" /var/log/auth.log

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

### 5) Auditd

Rules location

    /etc/audit/audit.rules (Persistent)
    auditctl (Temporary)

Monitor actions on a specific file

    sudo auditctl -w /tmp/file.txt -p wra -k KEY

Monitor execve syscalls

    sudo auditctl -a always,exit -F arch=b64 -S execve -k KEY

Audit logs

    cat /var/log/audit/audit.log

Query audit logs

    sudo ausearch -i -k KEY

Generate reports

    sudo ausearch -i -k KEY | ausreport -f REPORT_LOGS

Real-time monitoring

    audispd
