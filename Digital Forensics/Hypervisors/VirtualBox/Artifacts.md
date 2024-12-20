# VirtualBox Hypervisor Artifacts

### 1) Snapshots directory

    C:\Users\USER\VirtualBox VMs\VM_NAME\Snapshots

### 2) Enable debug logs

    VBoxManage.exe debugvm {name of the vm} log --all

### 3) Information about the VirtualBox process

    C:\Users\{username}\.VirtualBox\selectorwindow.log

### 4) Information regarding the start/stop use of VirtualBox and also saves/deletes components

    C:\Users\{username}\.VirtualBox\VboxSVC

### 5) Configuration file used by VirtualBox

    C:\Users\{username}\.VirtualBox\VirtualBox.xml

### 6) Information about OS, architecture, installation dates (timestamps) VM plugins and implemented drivers, etc

    C:\Users\{username}\.VirtualBox\Vbox.log

### 7) Information about hardening performed on VirtualBox, security-related crashes, memory manipulation (escape VM attacks) can be found here

    C:\Users\{username}\.VirtualBox\VBoxHardening.log
