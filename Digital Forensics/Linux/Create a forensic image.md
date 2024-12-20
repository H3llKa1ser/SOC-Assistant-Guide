# Create a forensic image on Linux

### Steps:

#### 1) List the block devices on our system

    sudo lsblk -l

### OR

    sudo df -h

#### 2) Create an image of a target device we want to copy, and log the output in a .txt file

    sudo dc3dd if=/dev/DEVICE_WE_WANT_TO_COPY of=IMAGE_FILE.img log=OUTPUT.txt

#### 3) Make an integrity check by comparing hash values from the device with the image we just created

    sudo md5sum IMAGE.img

    sudo md5sum /dev/DEVICE

### OR (better hashing algorithm)

    sudo sha256sum IMAGE.img

    sudo sha256sum /dev/DEVICE

#### 4) Create a mount point directory

    sudo mkdir -p /mnt/MOUNT

#### 5) Mount the image on the mounting point

    sudo mount -o OUTPUT IMAGE.img /mnt/MOUNT
