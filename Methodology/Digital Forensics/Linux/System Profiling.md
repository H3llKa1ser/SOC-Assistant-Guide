# System Profiling

Here are some basic commands to create a system profile for your investigations.

### 1) Basic System Information

    uname -a

### 2) Hostname

    hostnamectl

### 3) System's current status

    uptime

### 4) Hardware Information

CPU Architecture

    lscpu

### 5) Disk Usage

    df -h

### 6) Block devices (disks and partitions)

    lsblk

### 7) Free Storage

    free -h

### 8) Package Managers

Debian

    dpkg -l

Apt

    apt list --installed | head -n 30

### 9) Networking

Configuration details

    ip a
    ifconfig

Routing table

    ip r
    route

Active connections

    ss -tulpn
    netstat -ano
