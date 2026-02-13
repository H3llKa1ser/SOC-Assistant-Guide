# Linux Processes

### 1) Examine running processes on a Linux host

    sudo ps aux

Filter for a specific process

    sudo ps aux | grep PROCESS_NAME

### 2) Examine files and resources connected with our process of choice

    sudo lsof -p PID

### 3) Check for network connections associated with a process

    sudo lsof -i -P -n
