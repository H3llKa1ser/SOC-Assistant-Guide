# Threat Hunting and IR with XDR/EDR


---

## 1. The landscape: what these tools actually are

**EDR (Endpoint Detection and Response)** is an agent on each endpoint (Windows, macOS, Linux, sometimes mobile) that records detailed telemetry: process creation and command lines, file writes, registry changes, network connections, module loads, and cross-process activity such as handle opens and remote thread injection. It streams this to a backend that applies detection logic and lets analysts search and act. EDR grew out of the realization that signature antivirus was losing, and that defenders needed a record of *what happened* rather than just a verdict on a file.

**XDR (Extended Detection and Response)** widens that lens by correlating endpoint telemetry with identity (Active Directory, Entra ID, Okta), email, cloud workloads and SaaS, network (firewall, NDR, DNS, proxy), and sometimes OT. The important word is *correlation*. A good XDR stitches a phishing email, the user's click, the resulting process chain, the credential theft, and the anomalous cloud sign-in into one incident instead of five unrelated alerts. "Native" XDR is one vendor's stack (Microsoft Defender XDR, CrowdStrike Falcon, SentinelOne Singularity, Palo Alto Cortex XDR, Trend Vision One). "Open" or "hybrid" XDR ingests third-party sources.

Related acronyms get blurred in marketing. A **SIEM** is the broad log aggregation and correlation platform (Splunk, Sentinel, QRadar, Elastic). It has more breadth and retention but usually less endpoint depth and no native response. **SOAR** is orchestration and automation that runs playbooks across tools. **NDR** is network detection from traffic analysis. **ITDR** is identity threat detection. **MDR** is a managed service where someone else's analysts run the EDR/XDR for you. In practice, mature SOCs run EDR/XDR for depth and fast response, plus a SIEM for long retention and sources the XDR doesn't cover.

## 2. How EDR works under the hood

Understanding the sensor's view matters, because it tells you what you can hunt and what attackers try to blind.

On Windows, sensors rely on several mechanisms. **Kernel callbacks** (PsSetCreateProcessNotifyRoutine, image-load, thread-creation, object callbacks, registry callbacks) notify the driver of process, thread, image and registry events. A **minifilter driver** watches file system I/O. **Event Tracing for Windows (ETW)** supplies many events, including the Microsoft-Windows-Threat-Intelligence provider, which exposes things like remote memory allocation and APC injection to protected (PPL/ELAM) security processes. **AMSI** gives visibility into script content (PowerShell, VBScript, JScript, Office VBA, .NET) after deobfuscation at runtime. Some products also use **userland API hooks** in ntdll, although attackers bypass these easily, so the industry has shifted toward kernel and ETW-TI telemetry. Network visibility comes from WFP callouts. On Linux, modern sensors use **eBPF** (older ones used auditd or kernel modules). On macOS, they use Apple's **Endpoint Security Framework** and Network Extensions.

Detection happens in layers. There is static ML on files, behavioral rules on sequences of events (for example, an Office application spawning a script interpreter that makes a network connection), memory scanning, reputation and threat intel, and cloud-side analytics that correlate across hosts and tenants. Response capabilities typically include killing processes, quarantining files, **network isolation** (cutting the host off except for the EDR channel), **live response** shells, remediation of persistence, and on some platforms rollback (for example SentinelOne's VSS-based rollback).

The key practical point is that **EDR telemetry is not a full log**. Vendors filter and sample to control volume. Some events are only recorded when they look interesting, and retention is finite. Defender's Advanced Hunting, for example, retains about 30 days by default. Know your platform's schema, what it drops, and how long it keeps it before an incident forces you to find out.

## 3. Threat hunting: what it is and isn't

Threat hunting is the **proactive, human-driven search for adversary activity that your automated detections missed**. It starts from the assumption that you are already compromised. Triaging alerts is not hunting, and neither is IOC sweeping on its own, although IOC sweeps are a useful part of intel-driven work.

The **Pyramid of Pain** (David Bianco) is the guiding idea. Hash values, IP addresses and domains are trivial for attackers to change. Network and host artifacts, tools, and ultimately **TTPs** (tactics, techniques and procedures) are progressively harder to change. Good hunting targets behavior near the top of the pyramid, because that is where you impose real cost on the adversary.

**MITRE ATT&CK** is the shared vocabulary. Hunts are commonly scoped to techniques such as T1003.001 (LSASS memory dumping) or T1053.005 (scheduled tasks), and coverage is tracked on the ATT&CK matrix. **MITRE D3FEND** maps the defensive side. The **Sqrrl Hunting Maturity Model** (HMM0 to HMM4) describes progress from relying purely on alerts to automating successful hunts into detections.

### Types of hunts

**Hypothesis-driven (TTP) hunts** start from a statement like "an adversary may be using WMI event subscriptions for persistence on our servers." You pick the technique, determine what telemetry would reveal it, query, and investigate the results. **Intel-driven hunts** start from a threat report about a specific actor or campaign and look for its behaviors and indicators in your environment. **Anomaly or baseline-driven hunts** have no specific hypothesis. You look for statistical outliers such as rare binaries, unusual parent-child pairs, new services, or odd logon patterns. **Situational or crown-jewel hunts** focus on what matters most to your business: domain controllers, payment systems, CI/CD pipelines, backup infrastructure, and privileged identities.

Frameworks worth knowing include **PEAK** (Prepare, Execute, Act with Knowledge, from Splunk's SURGe team), which formalizes hypothesis, baseline and model-assisted hunts, and **TaHiTI**, from the Dutch financial sector. Both emphasize documentation and turning hunts into lasting detections.

### The hunting loop

A disciplined hunt goes like this:

1. **Form a hypothesis** that is specific and testable.
2. **Identify the data** you need and confirm you actually collect it. Surprisingly often you don't, which is itself a valuable finding.
3. **Query and analyze.**
4. **Investigate the leads** that come back.
5. **Decide the outcome:** malicious (escalate to IR), benign but noteworthy (document or tune), or nothing found (still valuable, because it validates coverage).
6. **Operationalize it** by turning a good hunt into a scheduled detection, so you never have to hunt for that exact thing manually again.

### Core analysis techniques

**Stacking (frequency analysis)** is the workhorse. You count occurrences of something across the fleet, such as process names by path, services by binary, or scheduled tasks by command, and study the long tail. Malicious items tend to be rare, but rarity alone isn't malice, so context matters. **Baselining** means learning what normal looks like for a host, user or role (which admins log into which servers, which service accounts talk to what) and flagging deviations. **Process tree analysis** asks whether the lineage makes sense. `w3wp.exe` spawning `cmd.exe` on a web server suggests a webshell. `winword.exe` spawning `powershell.exe` suggests a malicious macro. `services.exe` spawning something from `C:\Users\Public` is suspicious. **Temporal analysis** looks at beaconing periodicity, activity at 3 a.m. local time, and clusters of events within seconds of each other. **Graph and relationship analysis** examines authentication paths and lateral movement chains (BloodHound thinking applied to telemetry). **Command-line analysis** covers encoding, obfuscation (caret insertion, string concatenation, environment variable substrings), unusual flags, and high entropy.

## 4. High-value hunting targets by tactic

This is where most of the practical knowledge lives. The examples are Windows-heavy because that is where most enterprise intrusions play out, but the same thinking applies elsewhere.

**Initial access and execution.** Look for Office applications, PDF readers, or browsers spawning script hosts or LOLBins. Watch for script execution from user-writable paths (`%TEMP%`, `%APPDATA%`, Downloads, `C:\Users\Public`, `C:\ProgramData`). Other signals include ISO, IMG and VHD mounts followed by execution (used to bypass Mark-of-the-Web), `.lnk` files launching PowerShell, HTML smuggling, and OneNote attachments. Recently, "ClickFix" or fake-CAPTCHA lures, which trick users into pasting commands into the Run dialog, have become widespread. A useful hunt for these is `explorer.exe` spawning `powershell.exe` or `mshta.exe` with a long command line, alongside RunMRU registry entries.

**LOLBins (living off the land).** The LOLBAS project catalogs these. Classic ones include `mshta`, `rundll32` with unusual exports or no DLL, `regsvr32 /i:http` (Squiblydoo), `certutil -urlcache` or `-decode`, `bitsadmin`, `msiexec` loading from a URL, `wmic process call create`, `installutil`, `msbuild` running inline tasks, `cmstp`, and `forfiles`. Hunt for them making network connections, running from unusual parents, or taking unusual arguments.

**PowerShell.** Look for `-EncodedCommand` or `-enc`, `-nop -w hidden`, `IEX` with `DownloadString` or `Invoke-WebRequest`, reflection and `Add-Type`, and AMSI bypass strings (such as `amsiInitFailed` or patching `AmsiScanBuffer`). Downgrade attempts to PowerShell v2 are another signal. Script Block Logging (Event ID 4104) and AMSI telemetry are gold here.

**Persistence.** Check Run and RunOnce keys, the Startup folder, scheduled tasks (especially ones created by non-admin tooling, running from odd paths, or with hidden flags), new services (Event 7045), WMI event subscriptions (`__EventFilter`, `CommandLineEventConsumer`), COM hijacking, IFEO debugger keys, accessibility feature replacement (`sethc.exe`, `utilman.exe`), Winlogon Userinit and Shell values, BITS jobs, Office add-ins, and DLL search-order hijacking. In the cloud, look for new OAuth apps, service principals with added credentials, and mailbox forwarding rules. On Linux, check cron, systemd units, `.bashrc`, `authorized_keys`, and `LD_PRELOAD`. On macOS, check LaunchAgents and LaunchDaemons and login items.

**Privilege escalation and credential access.** Watch for **LSASS access**, meaning any process opening a handle to `lsass.exe` with memory-read rights that isn't a known security or system tool. Common methods include `procdump`, `comsvcs.dll MiniDump` via rundll32, Mimikatz, Task Manager dumps, and `nanodump`. Other credential access signals include SAM, SYSTEM and SECURITY hive exports (`reg save`), NTDS.dit access via `ntdsutil` or volume shadow copies, and **DCSync**, which appears as replication requests (Event 4662 with the replication GUIDs) from non-DC accounts. Also look for Kerberoasting (unusual volumes of TGS requests using RC4 encryption type 0x17), AS-REP roasting, browser credential store access, and DPAPI abuse. Token theft and adversary-in-the-middle phishing (Evilginx-style) show up in identity logs as session cookie replay from a new IP or ASN without a matching fresh MFA.

**Discovery.** Bursts of `whoami`, `net group "domain admins"`, `nltest /dclist`, `ipconfig /all`, `systeminfo`, `quser`, and AdFind or SharpHound executions are typical. LDAP query spikes also show up. Discovery commands are individually benign, so hunt for **clusters** of them from one parent process within a short window.

**Lateral movement.** Look for PsExec (the `PSEXESVC` service, or renamed variants), WMI remote execution (`WmiPrvSE.exe` spawning a shell), WinRM (`wsmprovhost.exe` children), RDP from unusual sources, SMB admin share writes followed by service creation, DCOM (MMC20, ShellWindows), and remote scheduled tasks. Pass-the-hash and pass-the-ticket show up as logon type 3 with NTLM where Kerberos is expected, or as ticket anomalies. Remote Monitoring and Management tools (AnyDesk, ScreenConnect, Atera, Splashtop and similar) are now a top lateral movement and persistence vector, so hunt for any RMM tool that isn't your sanctioned one.

**Command and control.** Look for beaconing, meaning regular intervals with jitter. You can surface it by analyzing connection timing per process and destination. Other signals are rare destinations contacted by few hosts, newly registered domains, long or high-entropy DNS queries (DNS tunneling), non-browser processes making HTTPS connections, named pipes matching known C2 defaults (for example Cobalt Strike's `\MSSE-*`, `\postex_*`), and traffic to legitimate services abused for C2 (Telegram, Discord, cloud storage, dev tunnels, ngrok, Cloudflare tunnels).

**Defense evasion.** Watch for attempts to stop, uninstall, or tamper with the EDR, Defender exclusion changes (`Add-MpPreference -ExclusionPath`), event log clearing (1102, 104), `wevtutil cl`, and timestomping. **BYOVD** (bring your own vulnerable driver) loads a signed but vulnerable driver to kill EDR processes from the kernel, so hunt for driver loads not on your baseline and cross-check against loldrivers.io. Other evasion techniques include process injection and hollowing, parent PID spoofing, direct or indirect syscalls, ETW patching, and EDR "silencing" via WFP filters that block the sensor's cloud traffic (EDRSilencer). A host that suddenly goes quiet is itself a signal.

**Impact and ransomware precursors.** These are among the most valuable hunts because they give you a last chance to act. Look for `vssadmin delete shadows`, `wmic shadowcopy delete`, `bcdedit /set recoveryenabled no`, `wbadmin delete catalog`, mass service stops (backup, SQL, AV), GPO modifications pushing scheduled tasks domain-wide, and mass file renames or high-entropy writes. Before any of that, look for **exfiltration staging**: `rclone`, `WinSCP`, `MEGAsync`, large archives created with 7-Zip or WinRAR, and big outbound transfers.

## 5. Query examples

Every platform has its own language. Microsoft Defender XDR and Sentinel use **KQL**. CrowdStrike uses **Falcon Query Language (FQL)** for filtering and **LogScale (CQL)** in Advanced Event Search, where you'll work with event types like `ProcessRollup2`. SentinelOne uses **S1QL / PowerQuery** in Deep Visibility. Cortex XDR uses **XQL**. Elastic uses **EQL/ES|QL**. The logic transfers, so here are some illustrative KQL hunts for Defender's Advanced Hunting schema.

Office spawning suspicious children:
```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

Stacking rare processes by path (long-tail analysis):
```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| summarize DeviceCount = dcount(DeviceId), Executions = count(), SampleCmd = any(ProcessCommandLine) by FileName, FolderPath, SHA256
| where DeviceCount <= 2
| order by DeviceCount asc
```

Non-standard processes touching LSASS (the exact fields depend on what your tenant logs, and many sensors surface this as an `OpenProcessApiCall` action in `DeviceEvents`):
```kql
DeviceEvents
| where Timestamp > ago(7d)
| where ActionType == "OpenProcessApiCall"
| where FileName =~ "lsass.exe"
| where InitiatingProcessFileName !in~ ("MsMpEng.exe","svchost.exe","wininit.exe","csrss.exe")
| project Timestamp, DeviceName, InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
```

Shadow copy deletion and recovery tampering:
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where (FileName =~ "vssadmin.exe" and ProcessCommandLine has_all ("delete","shadows"))
    or (FileName =~ "wmic.exe" and ProcessCommandLine has_all ("shadowcopy","delete"))
    or (FileName =~ "bcdedit.exe" and ProcessCommandLine has "recoveryenabled")
    or (FileName =~ "wbadmin.exe" and ProcessCommandLine has "delete")
```

Clusters of discovery commands from one parent:
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("whoami.exe","net.exe","net1.exe","nltest.exe","ipconfig.exe","systeminfo.exe","quser.exe","tasklist.exe","arp.exe","route.exe")
| summarize Commands = make_set(ProcessCommandLine), Distinct = dcount(FileName) by DeviceName, InitiatingProcessId, InitiatingProcessFileName, bin(Timestamp, 10m)
| where Distinct >= 4
```

Other key Defender tables are `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceImageLoadEvents`, `IdentityLogonEvents`, `IdentityDirectoryEvents`, `EmailEvents`, `EmailUrlInfo`, `UrlClickEvents`, `CloudAppEvents`, `AADSignInEventsBeta` (being superseded by `EntraIdSignInEvents`), and `AlertInfo`/`AlertEvidence`. Always **write portable logic in Sigma** where you can, so your detections survive a vendor switch and can be shared.

## 6. Incident response with EDR/XDR

The reference lifecycles are **NIST SP 800-61**, whose Revision 3 (April 2025) reorganized IR around the NIST CSF 2.0 functions, and the **SANS PICERL** model: Preparation, Identification, Containment, Eradication, Recovery, Lessons Learned. EDR/XDR touches every phase.

**Preparation** is where most IR battles are won or lost. It means full sensor coverage, which you should verify continuously, since the unmanaged box is where attackers live. It also means tamper protection on, sensible retention, tested isolation and live response permissions, playbooks for common scenarios (ransomware, BEC, compromised identity, insider, webshell), break-glass accounts, out-of-band communications for when email or Teams may be compromised, legal and insurance contacts, and pre-approved containment authority so analysts don't wait hours for sign-off to isolate a host.

**Identification and triage.** When an alert fires, validate it first. Read the process tree top to bottom and ask whether this lineage, user, host and time make sense. Check the file's prevalence (seen on one host or ten thousand), signer, and reputation. Look at what happened *before* the alert, since the alert is rarely the start, and what happened after (network connections, child processes, files dropped). XDR incident views help by pre-correlating alerts, but don't trust the grouping blindly: sometimes it merges unrelated events or misses linked ones.

**Scoping** is the step people rush and regret. Before you contain, understand the breadth. Pivot on everything you learned: the hash, the filename, the C2 domain or IP, the compromised account, the parent technique, the persistence mechanism. Search the entire fleet for each. Build a **timeline** starting from patient zero. Identify every compromised account and every host touched. The reason is that containing one host alerts a capable adversary, who may then burn their other footholds or accelerate to impact. For hands-on-keyboard intrusions, the ideal is often coordinated containment of everything at once.

**Containment.** EDR provides the fast levers: network isolation, process kill, file quarantine, and blocking hashes or indicators fleet-wide. Identity containment is just as important and often forgotten. Disable accounts, **revoke sessions and refresh tokens** (resetting a password alone does not kill existing cloud sessions), reset credentials, and remove attacker-registered MFA methods. If the domain is compromised, reset the **krbtgt password twice**, with appropriate spacing, to invalidate golden tickets. Block C2 at the firewall and DNS. For ransomware in progress, isolation beats everything; consider disconnecting segments and protecting backups immediately.

**Evidence collection.** Collect evidence before or alongside eradication, because EDR telemetry alone may not stand up to legal scrutiny or answer every question. Use live response or tools like **Velociraptor**, **KAPE**, or vendor collectors to pull forensic artifacts. Capture memory (for example with WinPmem or Magnet RAM Capture) when you suspect in-memory implants, since that evidence disappears on reboot. Preserve chain of custody if litigation, regulators or law enforcement may be involved.

**Eradication.** Remove every persistence mechanism you found, rebuild compromised systems rather than trusting cleanup where the compromise was deep, patch the initial access vector, and remove attacker tools, accounts and cloud apps. Then **hunt again** to confirm eradication. A common failure is removing the obvious implant while a second backdoor or RMM tool quietly remains.

**Recovery.** Restore systems from known-good backups, validate them, and return them to service in stages under heightened monitoring. Watch closely for re-entry attempts for weeks afterward, because adversaries often retry through access they sold or stashed.

**Lessons learned.** Ask where you detected them versus where you *could* have, and how long the dwell time was. Every incident should produce new detections, closed telemetry gaps, and updated playbooks.

## 7. Forensic artifacts to complement EDR

EDR gives you the recent, filtered view. Classic Windows forensic artifacts give you history and ground truth, especially for activity that predates the sensor or occurred while it was blinded.

For execution evidence, key sources are **Prefetch**, **Amcache.hve**, **Shimcache (AppCompatCache)**, **BAM/DAM**, **SRUM** (which also records per-app network usage, useful for exfiltration estimates), UserAssist, and RunMRU. For file system activity, use the **$MFT**, **$UsnJrnl**, $LogFile, LNK files, and Jump Lists. ShellBags show folder access.

Windows event IDs worth memorizing include 4624 and 4625 (logons, where logon type matters: 2 interactive, 3 network, 10 RDP), 4648 (explicit credentials), 4672 (special privileges), 4688 (process creation, with command-line auditing enabled), 4698 and 4702 (scheduled tasks), 4720 and 4732 (account creation and group changes), 4768, 4769 and 4771 (Kerberos), 4662 (directory object access, used to spot DCSync), 7045 (service installed), 1102 (Security log cleared), 4104 (PowerShell script blocks), and the RDP-specific logs such as TerminalServices-LocalSessionManager and RDP-CoreTS. **Sysmon**, if deployed, adds rich events (1 process create, 3 network, 7 image load, 8 CreateRemoteThread, 10 process access, 11 file create, 13 registry, 22 DNS) and is an excellent supplement where your EDR is thin.

For memory analysis, **Volatility 3** and **MemProcFS** let you find injected code, hidden processes, and implant configurations. Timeline everything together with **Plaso/log2timeline** or Eric Zimmerman's tools and Timeline Explorer.

## 8. Limitations, blind spots, and attacker evasion

Be clear-eyed about what EDR/XDR cannot see. **Coverage gaps** are the biggest issue. Unmanaged endpoints, legacy OS versions, network appliances (VPNs, firewalls, load balancers), hypervisors (ESXi is a favorite ransomware target precisely because it usually runs no EDR), IoT and OT, and contractor devices all fall outside the sensor's view. Many recent major intrusions began at an edge device exploit, where no agent runs.

**Telemetry limitations** include retention windows, sampling and filtering, and events recorded only above certain thresholds. **Legitimate-tool abuse** is hard to distinguish from administration, whether it's RMM tools, PowerShell, or cloud consoles. **Identity-only attacks** such as token theft, consent phishing, and MFA fatigue may never touch an endpoint. **Deliberate evasion** includes BYOVD, unhooking, syscalls, sensor tampering, and operating from compromised hosts that lack sensors.

Compensate with defense in depth. Monitor sensor health and treat an agent going silent as an alert. Feed edge device logs into your SIEM. Pay special attention to identity telemetry. Deploy canaries and honeytokens (fake credentials, fake AWS keys, decoy shares), which have a near-zero false positive rate.

## 9. Operationalizing: making it a program, not heroics

**Detection engineering** turns hunting output into durable coverage. Treat detections as code: store them in version control, peer review them, test them, and document the intent, known false positives, and response steps for each. **Validate continuously** with purple team exercises and emulation tools such as **Atomic Red Team**, **MITRE Caldera**, or commercial breach-and-attack-simulation platforms. A detection you've never seen fire may not work at all.

**Tuning** matters because alert fatigue kills SOCs. Suppress known-benign patterns narrowly (a specific hash, path and parent combination rather than a whole process name), and review suppressions regularly, because attackers love hiding inside exclusions.

**Automation** via SOAR or native XDR automation handles enrichment, low-risk containment (isolating a host when high-confidence ransomware behavior appears), and ticket creation. Keep humans in the loop for high-impact actions like disabling executive accounts or isolating production servers.

**Metrics** worth tracking include mean time to detect and respond, dwell time, ATT&CK coverage (being honest about quality over quantity), the number of hunts converted into detections, sensor coverage percentage, and false positive rate per detection. Avoid vanity metrics like raw alert counts.

**Threat intel integration** means mapping reports to ATT&CK and your telemetry and prioritizing hunts by the adversaries actually targeting your sector. Useful sources include CISA advisories, vendor threat reports, the DFIR Report (excellent detailed intrusion write-ups), and ISACs for your industry.

## 10. Practical wisdom from the field

A few things experienced hunters and responders tend to learn the hard way. Know your environment's normal better than the attacker does; the best detection engine is an analyst who knows which admin runs PsExec on Tuesdays. Document every hunt, including the ones that found nothing, since null results prove coverage and prevent duplicated effort. Don't tip your hand during scoping, and resist the urge to isolate the first host before you know how big the problem is, unless impact is imminent. Assume credentials are compromised in any hands-on-keyboard intrusion and plan resets accordingly. Remember that cloud sessions survive password resets. Keep out-of-band communication ready. Practice with tabletop exercises and live-fire drills so that the first time you isolate fifty hosts isn't during a real crisis. And stay humble about your tooling: EDR/XDR is a powerful lens, but it is only one lens, and the intrusions that hurt most are usually the ones happening where it isn't looking.

---

