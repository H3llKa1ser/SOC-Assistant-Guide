# LOCKHEED MARTIN'S CYBER KILL CHAIN FRAMEWORK

## KILL CHAIN TERMINOLOGY

### A military terminology, that explains the various stages of an attack.

### In cybersecurity, a kill chain is used to describe the methodology/path attackers such as hackers or APTs use to approach and intrude a target.

## Linear steps:

#### 1) Reconnaisance: OSINT, SOCMINT, etc.

#### 2) Weaponization: Purchase malware from the Dark Web, automation tools to generate malware, nation-sponsored APTs or more sophisticated actors develop their own unique malware.

#### 3) Delivery: Phishing email (Mass phishing/Spearphishing/Whaling), Infected USB Drive distribution, Watering hole attack (Website compromise)

#### 4) Exploitation: Zero-say exploits, phising email containing malicous link/harmful macros, server-based vulnerabilities, human vulnerabilities.

#### 5) Installation: Web shell persistence, meterpreter shell persistence, creation or modification of windows services, adding the entry to the "run keys" for the payload in the registry of the startup folder.

#### 6) Command and Control: C2 Channels ( HTTP port 80, HTTPS port 443, DNS Tunneling, IRC (Internet Relay Chat), Twitter account, etc.

#### 7) Action on Objectives: Credential collection, Overwrite or corruption of data, privilege escalation, internal reconnaisance, collection and exfiltration of sensitive/classified data, lateral movement, backup and shadow copy deletion.

## CYBER KILL CHAIN WEAKNESSES

#### 1) Insider Threats

#### 2) Passive steps hard to detect (Passive recon, weaponization)


# DEFENSE IN DEPTH

## Countermeasures against the Cyber Kill Chain steps:

#### 1) Detect

#### 2) Deny

#### 3) Disrupt

#### 4) Degrade

#### 5) Deceive

#### 6) Contain

#### Recon counters: Web analytics, NIDS, Firewall, Sharing Policy

#### Weaponize counters: Threat Intelligence

#### Delivery counters: Vigilant users, NIDS, NIPS, Proxy filtering, Email AV, Inline AV, Sandboxing

#### Exploitation counters: AV, HIDS, 2FA, Patching, Honeypots

#### Installation counters: Log monitoring, Privilege Access Management (PAM), AV

#### C2 counters: Log monitoring, NIDS, Firewall, NIPS, DNS redirect, Honeypot

#### Action on objectives counters: Audit logs, Data Loss Prevention (DLP), Honeypot
