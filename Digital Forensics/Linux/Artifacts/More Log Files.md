## Location of all log files: /var/log

## Syslog

#### It contains messages that are recorded by the host about system activity.

### Location: /var/log/syslog (Access it with "tail, head, more, less")

#### We can use * (Wildcard) to search through all of the syslogs. With the passage of time, the linux machine rotates older logs into files such as syslog.1, syslog.2, etc.

## Auth Logs

### Location: /var/log/auth.log

## Third-party logs

### Location: /var/log/

#### Contains logs from 3rd party software. (Example: MySQL, apache, samba, etc.)
