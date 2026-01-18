# Audit Daemon (Auditd)

Location

    /var/log/audit/audit.log

Command:

    ausearch

Auditd rules location

    /etc/audit/rules.d/audit.rules

Example usage:

### 1) Filter based on an auditd rule

    ausearch -i -k KEY_NAME

### 2) Filter based on a command

    ausearch -i -x whoami

### 3) Filter based on process ID 

Used in conjunction with the previous command to create a process tree analysis. Repeat the same command, but with a different PID for the parent and grandparent process ID

    ausearch -i --pid PID

### 4) List all child processes

    ausearch -i --ppid PPID | grep 'proctitle'

### 5) Read a specific audit.log file from other than the default location

    ausearch -i -if audit.log

### 6) Look for file changes inside /etc/systemd (Malicious service detection)

    ausearch -i -f /etc/systemd

### 7) Look for execution of a crontab

    ausearch -i -x crontab

### 8) Search if SSH keys have been modified

    ausearch -i -f /.ssh/authorized_keys
