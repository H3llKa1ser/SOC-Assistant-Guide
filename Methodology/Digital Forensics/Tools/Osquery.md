# Osquery

Osquery website

    https://osquery.io/schema/5.12.1/

### 1) Enter interactive shell of osquery

    sudo osqueryi

### 2) User accounts currently on the host

    osquery> Select username, uid, description from users;

### 3) Process information

    osquery> Select pid, name, parent,path from processes;

### 4) Processes running from tmp directory

    osquery> SELECT pid, name, path FROM processes WHERE path LIKE '/tmp/%' OR path LIKE '/var/tmp/%';

### 5) Fileless Malware hunt

    osquery> SELECT pid, name, path, cmdline, start_time FROM processes WHERE on_disk = 0;

### 6) Orphan processes

    osquery> SELECT pid, name, parent, path FROM processes WHERE parent NOT IN (SELECT pid from processes);

### 7) Processes run from user directories

    osquery> SELECT pid, name, path, cmdline, start_time FROM processes WHERE path LIKE '/home/%' OR path LIKE '/Users/%';
