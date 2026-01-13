# RDP Scenarios

## RDP Brute-force

### 1) Open Security logs and filter for 4625 event ID (Failed login attempts)

### 2) Look for events with Logon Type 3 and 10 (Network and RDP logins)

For most modern systems, the logon type will be 3 (since NLA is enabled by default)

For older or misconfigured systems, the logon type will be 10 (since NLA is not used)

### 3) Every event is now worth your attention, but the main red flags are:

Many attempted users like admin, helpdesk,  and cctv (Indicates password spraying)

Many login failures on a single account, usually Administrator (Indicates brute force)

Workstation Name does not match a corporate pattern (e.g. kali instead of WRK-PC-06)

Source IP is not expected (e.g. your printer trying to connect to your Windows Server)

## RDP Logons

### 1) Open Security logs and filter for 4624 event ID (Successful logins)

### 2) Look for events with Logon Type 10 (RDP logins)

If NLA is enabled, every RDP logon event is preceded by another 4624 with logon type 3

To get a real Workstation Name, you need to check the preceding logon type 3 event

### 3) Your red flags are either a preceding brute force or a suspicious source IP / hostname

### 4) If you assume that the login was indeed malicious, find out what happened next:

Windows assigns a Logon ID to every successful login (e.g. 0x5D6AC)

Logon ID is a unique session identifier. Save it for future analysis!
