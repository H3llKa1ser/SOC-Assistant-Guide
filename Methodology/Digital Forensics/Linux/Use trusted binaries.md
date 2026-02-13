# Use trusted binaries for investigation

Mount a USB drive with a clean installation, then modify the PATH and LD_LIBRARY_PATH to use the trusted binaries in our USB drive to prevent the accidental execution of malicious code.

    export PATH=/mnt/usb/bin:/mnt/usb/sbin
    export LD_LIBRARY_PATH=/mnt/usb/lib:/mnt/usb/lib64
