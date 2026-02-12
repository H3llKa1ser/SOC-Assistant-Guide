# Extended File System (EXT)

OS: Linux

## EXT Analysis

### 1) Check for partitions and file systems

    sudo lsblk

### 2) Inspect the superblock

    sudo dd if=/dev/loop0 bs=1024 count=1 skip=1 | hexdump -C

### 3) Inspect the superblock in human readable format

    sudo dumpe2fs /dev/loop0

### 4) Access a specific file system

    sudo debugfs /dev/loop0

### 5) Check permissions and stats of current directory

    stat .

## Inode Metadata

### 1) Get information for files

    sudo stat /mnt/ext4/file.txt

Use debugfs for more information

    sudo debugfs /dev/loop0
    debugfs: stat <INODE_NUM>

