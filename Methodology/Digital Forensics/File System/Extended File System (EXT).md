# Extended File System (EXT)

OS: Linux

Tools:

1) Autopsy

        ./autopsy --nosplash

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

## File Recovery

### 1) Search for a file with a known string of your choice inside the file system

    sudo strings -t d /dev/loop0 | grep -i "AAAAAAAA"

### 2) Calculate the offset by using the provided offset from previous command times the block size

    echo $((FILE_OFFSET / BLOCK_SIZE))

### 3) Recover the file

    sudo dd if=/dev/loop0 bs=BLOCK_SIZE skip=RESULT_OF_PREVIOUS_COMMAND count=1 of=/tmp/recovered_file

## Timestamps

### 1) Analyze timestamp data for a file/directory

    sudo stat /tmp/file.txt
    sudo stat /tmp/dir/

