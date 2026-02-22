# Image Mounting

Tools:

1)  apfs-fuse https://github.com/sgan81/apfs-fuse

2) Diskutil

### 1) List all volumes in the container

    apfsutil mac-disk.img

### 2) Mount the disk image

    sudo apfs-fuse mac-disk.img mac/

### 3) Mount a specific data volume

    sudo apfs-fuse -v NUM mac-disk.img mac/

### 4) List attached disk information

    diskutil apfs list
