# Package Managers

## Debian

### 1) Search for installed packages

    grep " install " /var/log/dpkg.log

### 2) View more details about a specific package installed

    dpkg -l | grep PACKAGE_NAME
