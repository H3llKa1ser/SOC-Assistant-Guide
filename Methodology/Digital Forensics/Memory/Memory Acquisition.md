# Memory Acquisition

## Windows

### 1) Full Memory Capture

#### Capture Steps:

Start FTK Imager tool, then:

    Click File -> Capture Memory
    Enter destination path to save memory capture (external storage) -> Give the capture file a fitting name
    Choose whether to include the page file or not -> Click Capture Memory

#### Integrity assurance process:

Open Powershell as Administrator

Get MD5 file hash

    Get-FileHash -Path 'C:\Users\Administrator\Documents\Full Memory Capture\FS-ANALYSIS-07April2025.mem' -Algorithm MD5 

Note down the hash value.

### 2) Process Memory Dump

Tools: Sysinternals Suite

Dump content of the lsass.exe process (Example)

    .\procdump64.exe -ma lsass.exe C:\temp -accepteula

Ensure integrity

    Get-FileHash -Path 'C:\TMP\lsass.exe_250408_082640.dmp' -Algorithm MD5

### 3) Crash Dump

#### Steps:

Right-click the Winfows logo in the task bar, then click run.

Enter this to open the System Properties control panel

    sysdm.cpl
    Advanced Tab -> Settings (Under startup and recovery)

Configure the memory dump in the "System failure - Write debugging information" section.

Choose dump according to use case.

## Linux

### 1) Full Memory Capture

Tool: LiME

#### Capture Steps:

Install necessary dependencies

    sudo apt update
    sudo apt install -y git build-essential linux-headers-$(uname -r)

Clone the LiME repository and compile it for use in kernel

    git clone https://github.com/504ensicsLabs/LiME.git
    cd LiME/src
    make

Take full memory capture

    sudo insmod lime-6.8.0-1027-aws.ko "path=/tmp/HOSTNAME-HHMMSS-DDMMYYYY.lime format=lime"

Ensure integrity

    md5sum /tmp/HOSTNAME-HHMMSS-DDMMYYYY.lime

Unload LiME from the kernel

    sudo rmmod lime

### 2) Process Memory Dump

Find the PID of the bash process (Example)

    ps aux | grep bash

Dump the memory of the bash process

    sudo gcore -o /tmp/BASH-130000-10042025 PID

Esnure integrity

    md5sum /tmp/BASH-130000-10042025

### 3) Crash Dump

#### Kernel Crash Dump

Check status kernel crash dump utility

    cat /proc/cmdline

Install kdump

    sudo apt install kdump-tools -y

Reboot to enable kdump

    sudo -reboot

Verify if the tool is running

    sudo kdump-config show

#### Process Crash Dump

Configure the crash dump for systemd-managed processes

    sudo mkdir -p /etc/systemd/system.conf.d
    sudo nano /etc/systemd/system.conf.d/core-dumps.conf

Add the following lines to the conf file

    [Manager]
    DefaultLimitCORE=infinity

Reload the systemd service

    sudo systemctl daemon-reexec

Enable process dumps

    ulimit -c unlimited

Open the config file

    sudo nano /etc/sysctl.d/60-core-pattern.conf

Add the following

    kernel.core_pattern = /var/crash/core.%e.%p.%t
    fs.suid_dumpable = 1

Create the /var/crash folder and assign permissions (optional if it exists)

    sudo mkdir -p /var/crash
    sudo chmod 1777 /var/crash
    
## Hypervisors

### 1) Hyper-V

Get VM details

    get-vm | FT VMId, VMName

Take a checkpoint

    get-vm -Id VM_ID | Checkpoint-VM

Take a snapshot

    Get-VMSnapshot -VMName 'VM_NAME' | FT Id,Name,Path

Copy the .vmrs file, which contains the RAM content

    cp C:\ProgramData\Microsoft\Windows\Hyper-V\Snapshots\97DBBAE5-3F91-4E5E-B177-FBB970E8703E.VMRS C:\temp\hostname-17-04-2025.VMRS

Esnure integrity

    Get-FileHash -Algorithm MD5 C:\temp\hostname-17-04-2025.VMRS

### 2) vSphere

Take a snapshot of the VM

Navigate to the datastore where the VM is located and copy the .vmsn file

Calculate a hash to ensure integrity

### 3) KVM

List all VMs 

    virsh list

Dump memory of VM

    virsh dump vmname /path/to/dupm.raw --memory-only

Ensure integrity

    md5sum memdump.raw

### 4) VirtualBox

List VMs

    .\VBoxManage.exe list runningvms

Dump memory

    .\VBoxManage.exe debugvm "VM_NAME" dumpvmcore --filename C:\temp\VM_NAME_memdump.elf

Ensure integrity

    Get-FileHash -Algorithm MD5 -Path C:\temp\VM_NAME_memdump.elf
