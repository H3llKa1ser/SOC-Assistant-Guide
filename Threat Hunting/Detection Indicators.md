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

## LFI IDENTIFICATION

#### 1) Weird requests

#### 2) OS Commands/Files

#### 3) New Files Seen

#### 4) URL Encoded

#### 5) Increase in upload

#### 6) Answers with bigger sizes

#### 7) Many "/" or "%2F" on the request

## RFI IDENTIFICATION

#### 1) Requests for other/unknown servers - outside traffic

#### 2) Increase in webserver download traffic

#### 3) Encoded requests

#### 4) User agent

## CROSS-SITE SCRIPTING (XSS)

#### 1) Script tags in the request (<script></script>)

#### 2) Javascript code in the request

#### 3) Many encoded characters

#### 4) Unexpected user agents

## STORED XSS

### Same as reflected with 2 bonuses:

#### 1) Check the web page code and look for malicious commands

#### 2) IDPS logs because stored XSS payload is sent via POST request

## CROSS SITE REQUEST FORGERY (CSRF)

#### 1) Referer

#### 2) Different behavior from the user

#### 3) Same action with an uncommon interval

## FLOOD ATTACKS (DDoS)

#### 1) Many equal requests

#### 2) Small period of time

#### 3) High CPU/Bandwidth usage

#### 4) Half connected TCP connections

#### 5) Uncommon or random requests

#### 6) Web Application slow/notworking

#### 7) User agent
