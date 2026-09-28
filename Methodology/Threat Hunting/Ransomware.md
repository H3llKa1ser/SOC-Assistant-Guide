# Threat Hunting for Ransomware Attacks

Threat hunting for ransomware is really hunting for the intrusion that comes before it. By the time files are encrypted, hunting is over and incident response has started. Encryption is the last and loudest stage of an operation that usually runs for days, sometimes only hours. Before it comes initial access, tooling, discovery, credential theft, privilege escalation, disabling defences, lateral movement, exfiltration, and destroying your recovery options. Each of those stages leaves artefacts, and the hunter's job is to find them early enough to evict the operator before detonation.

## The 2026 landscape, and why it changes how you hunt

The ecosystem is fragmented. Tracking three big brands no longer covers most of the threat. Between April 2025 and March 2026, 61 new ransomware groups entered the market, and by June 2026 the number of active groups had reached 146, although the five largest groups still accounted for 43.6% of victims, with Qilin the largest by volume. In Q2 2026, Qilin, Akira, and The Gentlemen had the largest victim volumes. Groups also rebrand constantly and reuse code, so behavioral monitoring has to take priority over tracking actors by name. In practice, you hunt behaviours and tools, not group names.

Several trends should shape your hypotheses.

**Edge devices are the front door.** The Gentlemen's TTPs include mass exploitation of hardware common in large enterprises, such as FortiOS/FortiProxy, SonicWall VPN, and Cisco ASA. Mandiant reports that mean time to exploit has dropped to an estimated -7 days, so exploitation routinely happens before a patch exists. These devices often lack EDR, so your visibility there is logs only.

**Access is bought, not built.** Initial access brokers remain important, with increased focus on RDWeb access, and access sales surged 44% in Q1 2026. The account that logs in on day 1 may belong to a different actor than the one who detonates on day 6.

**EDR killers and encryptionless extortion.** Kaspersky highlights EDR killers on the rise, and some groups implementing extortion without encryption as ransom payments drop. If a group only exfiltrates, you never get the "encryption" signal at all. Exfiltration hunting becomes primary, not secondary.

**Recovery denial.** M-Trends 2026 identifies backups, identity services, and virtualization layers as key targets attackers disrupt to prevent recovery.

**Supply chain and MSPs.** Attackers are hijacking the trusted tools of MSPs and software distributors to hit many downstream victims at once. Your vendors' remote access is part of your attack surface.

## Hunting approach

There are three classic hunt types, and a mature programme uses all three. Hypothesis-driven hunts start from a statement like "an affiliate is using an unsanctioned RMM tool for persistence" and test it. Intel-driven hunts start from a fresh CISA #StopRansomware advisory or a DFIR Report write-up and sweep for its specific TTPs and IOCs. Analytics- or baseline-driven hunts look for rarity and deviation, such as a binary seen on only two hosts or an admin account authenticating somewhere it never has.

Splunk's PEAK framework (Prepare, Execute, Act with Knowledge) is a good structure. Every hunt should end in one of three outcomes: an incident, a new detection rule, or a documented negative result plus any visibility gaps you found. A hunt that produces nothing reusable was mostly wasted.

## Phase-by-phase: what to hunt and where

| Phase | What to look for | Primary telemetry |
|---|---|---|
| Initial access | VPN/firewall exploitation, anomalous VPN logins, RDP/RDWeb brute force, valid-account abuse, phishing/malvertising loaders, helpdesk social engineering | Edge device logs, VPN auth logs, IdP sign-in logs, email telemetry, web proxy |
| Execution & C2 | Unsanctioned RMM tools, C2 frameworks (Cobalt Strike, Sliver, Havoc, Brute Ratel), tunnelling (ngrok, Cloudflared, Chisel, plink) | EDR process/network, DNS, proxy, JA3/JA4 |
| Discovery | Bursts of AD recon (AdFind, nltest, net group, SharpHound), network scanners (Advanced IP Scanner, SoftPerfect, netscan) | EDR process, DC LDAP logs, 4662 |
| Credential access | LSASS dumping, NTDS.dit extraction, SAM/SECURITY hive saves, DCSync, Kerberoasting, Veeam credential extraction, browser credential theft | EDR, Sysmon 10, DC 4662/4769, backup server logs |
| Defense evasion | BYOVD driver loads, Defender tampering, security service stops, log clearing, Safe Mode boots | EDR tamper alerts, 7045, 1102/104, driver load events |
| Lateral movement | PsExec/PAExec, WMI, WinRM, RDP chains, SMB admin shares, GPO-based deployment, scheduled tasks on many hosts | 4624 type 3/10, 7045, 4698, 5145, EDR |
| Exfiltration | rclone, restic, WinSCP, MEGAsync, curl to file-sharing sites, large outbound transfers, archive creation (7z, WinRAR) | EDR, proxy, NetFlow, firewall, DNS |
| Impact prep | Shadow copy deletion, wbadmin/bcdedit changes, backup job deletion, ESXi VM shutdowns, cloud snapshot deletion | EDR, backup console, ESXi syslog, CloudTrail/Azure Activity |

The single best free reference for the tools affiliates actually use is BushidoToken's Ransomware Tool Matrix on GitHub. Pair it with LOLRMM (lolrmm.io) for remote access tools and LOLDrivers (loldrivers.io) for vulnerable drivers.

## Example hunt queries (KQL, Defender XDR)

These are starting points. Adapt field names for Sentinel, Splunk, or your EDR, and expect to tune against your baseline.

**Unsanctioned or rare RMM tools.** This is one of the highest-yield hunts. Anything not on your approved list, or present on only a handful of hosts, deserves a look.

```kql
let rmm = dynamic(["anydesk","screenconnect","atera","splashtop","meshagent","rustdesk",
                   "tacticalrmm","netsupport","client32","level","simplehelp","remoteutilities","teamviewer"]);
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName has_any (rmm) or ProcessVersionInfoProductName has_any (rmm)
| summarize Devices = dcount(DeviceName), FirstSeen = min(Timestamp),
            Hosts = make_set(DeviceName, 25), Parents = make_set(InitiatingProcessFileName, 10)
            by FileName, ProcessVersionInfoCompanyName
| order by Devices asc
```

**Discovery bursts.** A single `nltest` is noise. Six recon commands from one account on one host within ten minutes is a hands-on-keyboard operator.

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName in~ ("nltest.exe","net.exe","net1.exe","adfind.exe","whoami.exe","systeminfo.exe",
                      "quser.exe","nslookup.exe","ipconfig.exe","arp.exe","route.exe")
   or ProcessCommandLine has_any ("domain_trusts","dclist","domain admins","enterprise admins",
                                  "objectcategory=computer","trustdmp","-gcb")
| summarize DistinctCmds = dcount(ProcessCommandLine), Tools = make_set(FileName),
            Samples = make_set(ProcessCommandLine, 10)
            by DeviceName, AccountName, bin(Timestamp, 10m)
| where DistinctCmds >= 5
```

**Credential dumping patterns.**

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where (ProcessCommandLine has "ntdsutil" and ProcessCommandLine has_any ("ifm","create full"))
   or (FileName =~ "rundll32.exe" and ProcessCommandLine has_all ("comsvcs","MiniDump"))
   or (FileName =~ "reg.exe" and ProcessCommandLine has "save"
       and ProcessCommandLine has_any ("hklm\\sam","hklm\\security","hklm\\system"))
   or (ProcessCommandLine has_any ("vssadmin create shadow","\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy")
       and ProcessCommandLine has_any ("ntds.dit","\\config\\SAM"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessCommandLine
```

For DCSync, look on domain controllers for event 4662 with the replication GUIDs `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` and `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` coming from an account that isn't a DC machine account. For Kerberoasting, look for 4769 with RC4 encryption (`0x17`) requested by one account for many SPNs in a short window.

**Exfiltration tooling, including renamed binaries.** Affiliates rename rclone constantly. `OriginalFileName` and command-line flags catch that.

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where ProcessVersionInfoOriginalFileName in~ ("rclone.exe","restic.exe","winscp.exe","megasync.exe")
   or ProcessCommandLine has_any ("--multi-thread-streams","--transfers","--no-check-certificate",
                                  " mega:"," sftp:","--config","copy \\\\")
   or (FileName in~ ("7z.exe","7za.exe","rar.exe","winrar.exe") and ProcessCommandLine has_any ("-hp","-p","-v"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessVersionInfoOriginalFileName, ProcessCommandLine
```

On the network side, look for sustained high-volume outbound flows from servers that don't normally talk to the internet. Also look for DNS resolutions of file-sharing services (mega.nz, temp.sh, file.io, gofile, bashupload) and odd-hour upload spikes.

**Recovery inhibition.** Treat this as a detection, not a hunt. If you're seeing it, you're very late, but it's worth sweeping historically for "test runs".

```kql
DeviceProcessEvents
| where Timestamp > ago(90d)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete","shadows"))
   or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy","delete"))
   or (FileName =~ "wbadmin.exe" and ProcessCommandLine has_any ("delete catalog","delete systemstatebackup"))
   or (FileName =~ "bcdedit.exe" and ProcessCommandLine has_any ("recoveryenabled no","ignoreallfailures","safeboot"))
   or (FileName in~ ("powershell.exe","pwsh.exe") and ProcessCommandLine has "Win32_ShadowCopy")
```

**BYOVD / EDR killers.** Match driver load events (Sysmon EID 6, or your EDR's driver-load telemetry) against the LOLDrivers hash list. Also hunt service creations with a kernel driver service type (7045) from unusual paths such as user temp directories or `C:\ProgramData`. Signs of sensor tampering include a host going silent in EDR while still sending firewall or DNS traffic. Build a "sensor heartbeat gap" hunt and review it weekly. EDR killers exist precisely to create that gap.

## Hypervisors: the blind spot that ends businesses

ESXi encryption is how ransomware takes out hundreds of servers in minutes, and ESXi has no EDR. Forward ESXi syslog (hostd, shell, auth, vobd) to your SIEM and hunt for the following:

- SSH or the ESXi Shell being enabled outside change windows.
- Interactive use of `esxcli vm process list/kill` or `vim-cmd vmsvc/getallvms` and `power.off`.
- `esxcli system settings advanced set -o /User/execInstalledOnly -i 0`, which disables the execute-installed-only protection.
- Unsigned VIB installs.
- New local accounts.
- Firewall rule changes.

On the AD side, watch for creation of or membership changes to an "ESX Admins" group. That was the CVE-2024-37085 abuse path on domain-joined hosts. Check vCenter for new admin roles and mass snapshot deletions.

## Identity and cloud

Many recent intrusions are identity-first, not malware-first. In your IdP (Entra ID, Okta), hunt for the following:

- Helpdesk-driven password or MFA resets followed quickly by new MFA method registration.
- Sign-ins from residential proxy or VPS ASNs.
- New federated domains or trust changes.
- Consent grants to unfamiliar OAuth apps.
- Privileged role activations outside normal patterns.

In AWS, hunt for:

- Mass `DeleteObject` and snapshot deletion.
- Changes to or deletion of `DeleteBackupVault` and lifecycle policies.
- S3 objects rewritten with SSE-C, meaning customer-provided keys. This was the "Codefinger" technique from early 2025: the attacker encrypts your data with a key only they hold.

In Azure, watch for storage account key listing, immutability policy changes, and Recovery Services vault soft-delete being disabled.

## Backups are a hunting target in their own right

Attackers go after backup servers specifically: Veeam, Commvault, Rubrik consoles, and NAS devices. Hunt for these signs:

- Logins to backup consoles from new sources.
- Deleted or modified jobs and retention policies.
- Encryption-password changes.
- Known Veeam credential-extraction scripts and exploitation of Veeam CVEs.
- Backup servers joined to the production domain with shared admin credentials. This is a finding, even if nothing is wrong yet.

## Deception: cheap, high-signal tripwires

Deception gives you near-zero false positives. Useful tripwires include:

- A honey account with an SPN and an attractive name. Any 4769 request for it means Kerberoasting.
- A fake "svc_backup" credential planted in a script on a file share. Any authentication with it is an alert.
- Canary files at the top of share directories, named so they sort first alphabetically. Many encryptors walk directories in order, so these trip early.
- Canary AWS keys (Thinkst Canarytokens are free).
- A decoy RDWeb or VPN portal, if you want to go further.

## Timing and operator behaviour

Operators prefer to detonate on Friday nights, weekends, and holidays, when staffing is thinnest. Exfiltration usually happens in the days before encryption. Test runs against a few hosts sometimes precede the mass run. Tuning your hunts and on-call escalation around those windows matters as much as the queries themselves. Assume you have hours from domain admin compromise to detonation, not weeks.

## Operationalising it

A realistic cadence has three parts. Run a weekly sweep of your high-yield hunts: RMM rarity, discovery bursts, exfil tools, sensor gaps, and new admin-group memberships. Do an intel-driven sweep within 24–48 hours of any relevant CISA #StopRansomware advisory or DFIR Report publication. Run a deeper quarterly hypothesis hunt tied to an emulation exercise. For emulation, Atomic Red Team, MITRE Caldera, and the Center for Threat-Informed Defense's adversary emulation plans let you run the actual TTPs in a controlled way. That tells you whether your telemetry and detections would have caught them. Every visibility gap you find, such as "we have no ESXi logs" or "VPN logs retain only 7 days", is a real deliverable.

When a hunt finds something real, avoid tipping off the operator. Don't reset the compromised account or kill the beacon before you've scoped how many hosts and accounts are involved. Partial eviction triggers early detonation. This is where the hunt hands off to your IR process: scope quietly, then contain everything at once.

## Key resources

- CISA #StopRansomware advisories, which include per-group TTP and IOC write-ups.
- The DFIR Report, for detailed intrusion timelines from access to detonation.
- BushidoToken's Ransomware Tool Matrix.
- LOLRMM and LOLDrivers.
- ransomware.live, for leak-site tracking by group and sector.
- The SigmaHQ rules repository, for detections you can convert to KQL or SPL.
- Mandiant M-Trends, Sophos Active Adversary, and Kaspersky's annual ransomware reports, for trend data.
- MITRE ATT&CK, particularly T1486 (Data Encrypted for Impact), T1490 (Inhibit System Recovery), T1567 (Exfiltration Over Web Service), and T1219 (Remote Access Software).

If it's useful, I can turn this into a hunt playbook doc with hypotheses, queries, and owners that your team can keep editing.
