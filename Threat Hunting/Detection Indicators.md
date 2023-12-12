# DETECTION INDICATORS FOR POSSIBLE MALICIOUS ACTIVITY

## VULNERABILITY SCANS

#### 1) User-agent

#### 2) Many requests in a short period of time

#### 3) Many errors

#### 4) Weird words

#### 5) Unexpected requests

## BRUTE FORCE ATTACKS

#### 1) User-agent

#### 2) Many requests in a short period of time

#### 3) Login web pages

#### 4) Administrator/admin username

#### 5) Brute force attacks via POST requests (Hydra) can be identified in the payload and analyzed with packet sniffers (Wireshark) or IDS/IPS (Snort)

#### 6) Check for any successful login attempts

## SQL INJECTIONS

#### 1) SQL Commands

#### 2) Encoded commands

#### 3) User-agent

#### 4) OS commands (EXEC)

### Attack Types:

### 1) Blind (Out-of-band)

### 2) Classic (In-band

### 3) Union Based

### 4) Error Based

### 5) Time Based

### 6) Boolean

## FILE INCLUSION

### TARGETS

### LINUX:

#### /etc/issue

#### /proc/version

#### /etc/profile

#### /etc/passwd

#### /etc/shadow

#### /root/.bash_history

#### /var/log/dmessage

#### /var/mail/root

#### /var/spool/cron/crontabs/root

### OS X/Mac OS

#### /etc/fstab

#### /etc/master.passwd

#### /etc/resolv.conf

#### /etc/sudoers

#### /etc/sysctl.conf

### WINDOWS

#### %SYSTEMROOT%repairsystem

#### %SYSTEMROOT%repairSAM

#### %SYSTEMDRIVE%boot.ini

#### %WINDIR%win.ini

#### %WINDIR%Panthersysprep.ini

#### %WINDIR%system32configAppEvent.Evt
