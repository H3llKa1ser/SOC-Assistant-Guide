# Processes

### 1) View processes

    ps aux

### 2) View processes specific to a user

    ps -u USER

### 3) Get a comprehensive view of al processes on the system in a hierarchical format

    ps -eFH

### 4) View any files associated with a process

    sudo lsof -p PID

### 5) List the parent processes as well as their PIDs of a specific process

    pstree -p -s PID

### 6) Filter specific processes

    ps -f PID_1 PID_2 PID_3

### 7) Dynamically investigate processes

    top -d SECONDS -c -u USER
