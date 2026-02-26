# Backup Creation

Tool: Libimobiledevice https://libimobiledevice.org/

### 1) After connecting the iPhone with our device, verify

    ideviceinfo

### 2) Create backup

Ensure encryption mode is on to take a full backup

    idevicebackup2 -i encryption on

Then

    idevicebackup2 backup --full ./backup


