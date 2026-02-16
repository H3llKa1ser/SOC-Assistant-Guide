# Osquery

Osquery website

    https://osquery.io/schema/5.12.1/

### 1) Enter interactive shell of osquery

    sudo osqueryi

### 2) User accounts currently on the host

    osquery> Select username, uid, description from users;

## Processes

### 1) Process information

    osquery> Select pid, name, parent,path from processes;

### 2) Processes running from tmp directory

    osquery> SELECT pid, name, path FROM processes WHERE path LIKE '/tmp/%' OR path LIKE '/var/tmp/%';

### 3) Fileless Malware hunt

    osquery> SELECT pid, name, path, cmdline, start_time FROM processes WHERE on_disk = 0;

### 4) Orphan processes

    osquery> SELECT pid, name, parent, path FROM processes WHERE parent NOT IN (SELECT pid from processes);

### 5) Processes run from user directories

    osquery> SELECT pid, name, path, cmdline, start_time FROM processes WHERE path LIKE '/home/%' OR path LIKE '/Users/%';

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
