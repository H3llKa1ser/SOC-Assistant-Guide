# Forensic Imaging

## Preparation phase for recording our actions

### 1) Enable command history in the shell

    set -o history

### 2) Ensure that the command history is appended to the hisotry file instead of overwriting it

    shopt -s histappend

### 3) Ensure all commands are recorded in history

    export HISTCONTROL=

### 4) All commands are saved in history

    export HISTIGNORE=

### 5) Set the file where the command history is saved

    export HISTFILE=~/.bash_history

### 6) Set no limits on the number of lines stored in the history file

    export HISTFILESIZE=-1

### 7) Set no limits of the number of commands retained in shell history

    export HISTSIZE=-1

### 8) Format timestamps in the history as "YYYY-MM-DD HH" for each command

    export HISTTIMEFORMAT="%F-%R "

### 9) See the attached devices on target machine

    df

### 10) List block devices

    lsblk -a

### 11) Get more information about the device

    sudo losetup -l /dev/loop0

Acquire UUID of the image

    sudo blkid /dev/loop0 

## Create a forensic image

### 1) Create a forensic image

    sudo dc3dd if=/dev/loop0 of=example.img log=imaging_loop0.txt

### 2) Verify the successful image creation

    ls -lah example.img

## Integrity Checking

### 1) List the block devices

    sudo lsblk -l

### 2) Get SHA256 hash of the forensic image, then make the cross-verification with the device if it has the same hash

    sudo sha256sum example.img
    sudo sha256sum /dev/loop0

## Mount the image

### 1) List attached devices

    df -h

### 2) Create a mount point directory

    sudo mkdir -p /mnt/example

### 3) Mount the image

    sudo mount -o loop example.img /mnt/example

### 4) Explore the mount point

    ls /mnt/example
