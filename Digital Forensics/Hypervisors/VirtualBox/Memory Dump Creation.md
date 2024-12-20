# Memory Dump Creation

## Steps:

#### 1) Create the image using the VBoxManage CLI utility

    C:\Program Files\Oracle\VirtualBox\VBoxManage.exe debugvm {name of the vm} dumpvmcore --filename={output file name}

#### 2) Convert the core dump into a memory dump with volatility 2

    python vol.py -f {output file name} imagecopy -O {new output file name}

