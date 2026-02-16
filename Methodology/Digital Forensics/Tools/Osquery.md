# Osquery

Osquery website

    https://osquery.io/schema/5.12.1/

### 1) Enter interactive shell of osquery

    sudo osqueryi

### 2) User accounts currently on the host

    osquery> Select username, uid, description from users;

### 3) Process information

    osquery> Select pid, name, parent,path from processes;
