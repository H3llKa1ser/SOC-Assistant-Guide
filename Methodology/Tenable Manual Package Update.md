# Tenable Manual Package Update

Update packages to remediate vulnerabilities regarding the Nessus scanners.

### 1) Enable specific packages

    sudo yum-config-manager --enable ol8_baseos_latest && sudo yum-config-manager --enable ol8_appstream 

### 2) 

    sudo dnf autoremove

### 3) 

    sudo dnf clean all

### 4) 

    sudo dnf update

### 5) 

    sudo yum-config-manager --disable ol8_baseos_latest && sudo yum-config-manager --disable ol8_appstream

### 6) 

    exit
