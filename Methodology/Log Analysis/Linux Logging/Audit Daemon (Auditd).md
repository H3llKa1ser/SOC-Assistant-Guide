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

### 2) Use grep for simpler output

    ausearch -i -k KEY_NAME | grep "proctitle"

### 3) Filter based on a command

    ausearch -i -x whoami

### 4) Filter based on process ID (Used in conjunction with the previous command to create a process tree analysis. Repeat the same command, but with a different PID for the parent and grandparent process ID)

    ausearch -i --pid PID
