# Osquery

Osquery website

    https://osquery.io/schema/5.12.1/

### 1) Enter interactive shell of osquery

    sudo osqueryi

### 2) User accounts currently on the host

    osquery> Select username, uid, description from users;

## Processes

### 1) Process information

    osquery> Select pid, name, parent, path from processes;

### 2) Processes running from tmp directory

    osquery> SELECT pid, name, path FROM processes WHERE path LIKE '/tmp/%' OR path LIKE '/var/tmp/%';

### 3) Fileless Malware hunt

    osquery> SELECT pid, name, path, cmdline, start_time FROM processes WHERE on_disk = 0;

### 4) Orphan processes

    osquery> SELECT pid, name, parent, path FROM processes WHERE parent NOT IN (SELECT pid from processes);

### 5) Processes run from user directories

    osquery> SELECT pid, name, path, cmdline, start_time FROM processes WHERE path LIKE '/home/%' OR path LIKE '/Users/%';

### 6) Analyzer a specific process in detail

    osquery> select pid, name, path from processes where pid = 'PID';

## Networking

### 1) List network connections

    osquery> SELECT pid, family, remote_address, remote_port, local_address, local_port, state FROM process_open_sockets LIMIT 20;

### 2) Remote Connections (C2 communication detection)

    osquery> SELECT pid, fd, socket, local_address, remote_address, local_port, remote_port FROM process_open_sockets WHERE remote_address IS NOT NULL;

### 3) DNS Queries

    osquery> SELECT * FROM dns_resolvers;

### 4) Network Interfaces

    osquery> SELECT interface, address, mask, broadcast FROM interface_addresses;

### 5) Listening ports

    osquery> SELECT * FROM listening_ports;

## Files

### 1) List all opened files that are associated with the corresponding processes

    osquery> SELECT pid, fd, path FROM process_open_files;

### 2) Search for files being accessed from the tmp directory (can be another directory, change accordingly)

    osquery> SELECT pid, fd, path FROM process_open_files where path LIKE '/tmp/%';

### 3) Hidden files in root directory (can be in another location, change accordingly)

    osquery> SELECT filename, path, directory, size, type FROM file WHERE path LIKE '/.%';

### 4) Recently modified files

    osquery> SELECT filename, path, directory, type, size FROM file WHERE path LIKE '/etc/%' AND (mtime > (strftime('%s', 'now') - 86400));

### 5) Recently modified binaries

    osquery> SELECT filename, path, directory, mtime FROM file WHERE path LIKE '/opt/%' OR path LIKE '/bin/' AND (mtime > (strftime('%s', 'now') - 86400));
