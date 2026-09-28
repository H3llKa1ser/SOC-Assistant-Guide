# Threat Hunting with EDR

# Threat Hunting with EDR

## What threat hunting actually is

Threat hunting is the proactive, human-led search for adversary activity that your existing automated detections have missed. The core assumption is "assume breach": somewhere in your environment, an attacker may already be operating quietly, and your alerts haven't fired because the attacker is using legitimate tools, novel techniques, or behavior that falls below alert thresholds.

Hunting is distinct from two neighboring activities. Alert triage is reactive: a detection fires and an analyst investigates it. Incident response starts once you know something bad happened. Hunting starts with no alert at all, only a question: "If an attacker were doing X here, what would it look like, and is it happening?"

EDR (Endpoint Detection and Response) is the most valuable data source for hunting because endpoints are where attackers must eventually act. They have to execute code, touch credentials, persist, and move laterally. An EDR records those actions as rich, queryable telemetry across your whole fleet, often with months of history. Firewalls and proxies see traffic. EDR sees which process, run by which user, with which command line, made that traffic.

## What EDR telemetry gives you

Hunting depends on knowing exactly what your EDR records, because you can only find what you collect. Most mature platforms (Microsoft Defender for Endpoint, CrowdStrike Falcon, SentinelOne, Carbon Black, Elastic Defend, Cortex XDR, and others) capture roughly these event families:

**Process events.** These are the backbone of hunting. They include process creation and termination, full command lines, parent and grandparent processes, user context, integrity level, file hashes, signer information, and the image path. The parent-child relationship matters most here, since legitimate software has predictable lineages and malicious activity often breaks them.

**File events.** Creation, modification, deletion, and renaming, with the responsible process. These are useful for spotting dropped payloads, staging directories, and ransomware encryption patterns.

**Registry events (Windows).** Key and value creation or modification. This is essential for persistence hunting (Run keys, services, COM hijacking, IFEO debuggers).

**Network events.** Outbound and inbound connections with local and remote IPs, ports, protocol, and the initiating process. Many EDRs also log DNS queries and, sometimes, URLs or TLS SNI.

**Module and image loads.** DLLs loaded by each process. This helps with DLL side-loading, unusual loads such as `clr.dll` inside a process that shouldn't run .NET, and credential-theft tooling loading `dbghelp.dll` or `dbgcore.dll`.

**Cross-process activity.** Handle opens to other processes (especially LSASS), remote thread creation, and memory writes. These are key signals for injection and credential dumping.

**Logon and identity events.** Local and remote logons, logon types, and privilege use. These matter for lateral movement.

**Script and AMSI content.** Some platforms capture deobfuscated PowerShell, VBScript, or JScript content via AMSI or script block logging, which is enormously valuable against obfuscated attacks.

**Other sources.** Depending on vendor, you may also get WMI activity, named pipe creation, scheduled task and service creation, driver loads, USB activity, and ETW-derived events.

Before hunting, learn the exact schema of your platform, the retention period for raw telemetry (often 30 days for hot data, sometimes longer), and whether any events are sampled, filtered, or deduplicated. Some EDRs don't record every network connection or every file write, and not knowing this leads to false negatives.

## Frameworks and mental models

**MITRE ATT&CK** is the lingua franca. It catalogs adversary tactics (the "why": initial access, execution, persistence, privilege escalation, defense evasion, credential access, discovery, lateral movement, collection, command and control, exfiltration, impact) and techniques (the "how"). Hunters use it to pick hypotheses, measure coverage, and communicate findings. A common program goal is to map which techniques you have detections for, which you've hunted, and which you have no visibility into.

**The Pyramid of Pain** (David Bianco) ranks indicators by how painful they are for an attacker to change. Hashes, IPs, and domains sit at the bottom and are trivial to rotate. Artifacts and tools are in the middle. TTPs (tactics, techniques, and procedures) sit at the top because behavior is hard to change. Good EDR hunting focuses on behavior, because hunting for a hash only finds that exact file.

**The Hunting Maturity Model** (HMM0 to HMM4) describes progression from relying entirely on automated alerts (HMM0), through IOC searching (HMM1), following published hunt procedures (HMM2), creating your own hypothesis-driven hunts (HMM3), to automating successful hunts into detections at scale (HMM4).

**Hunting loops and methodologies.** The classic Sqrrl hunting loop is: create a hypothesis, investigate with tools and techniques, uncover new patterns and TTPs, then inform and enrich analytics. Newer frameworks refine this. PEAK (from Splunk's SURGe team) divides hunts into hypothesis-driven, baseline (anomaly) hunts, and model-assisted hunts, each with Prepare, Execute, and Act phases. TaHiTI, from Dutch financial institutions, emphasizes threat intelligence as the driver.

## Types of hunts

**Hypothesis-driven or TTP-based hunts** start from a specific adversary behavior. For example: "Attackers commonly dump LSASS memory for credentials. Let's find any non-standard process opening a handle to LSASS with read-memory access." This is the most common and repeatable type.

**Intelligence-driven hunts** start from a threat report. A new campaign is reported targeting your industry, and you extract its behaviors (not just its IOCs) and look for them. For a gaming or lottery operator, that might mean tracking groups known to target financial or gaming sectors, or ransomware affiliates active in your region.

**Baseline or anomaly hunts** don't start with a specific attack in mind. You establish what "normal" looks like and hunt for outliers: the process that runs on only two machines out of 5,000, the service account that suddenly logs on interactively, the workstation that talks to 200 internal hosts on SMB.

**Situational or crown-jewel hunts** focus on what matters most to the business: domain controllers, payment systems, source code repositories, jackpot or gaming systems, executives' laptops. You hunt deeply on a small, high-value scope.

**IOC sweeps** (searching for known-bad hashes, domains, IPs) are the entry-level form. They're worth doing when intel arrives, but they're not really hunting in the mature sense because they only find what someone else already found.

## Core analytical techniques

**Searching** is the simplest technique: looking for a specific value or pattern. It's precise, but only as good as your query.

**Stacking (frequency analysis or long-tail analysis)** is the hunter's most powerful EDR technique. You count occurrences of something across the fleet and look at the rare end. Legitimate software tends to be common and consistent, while attacker tooling is often rare. Stack by process name plus path, by hash, by parent-child pair, by scheduled task name, by service binary path, or by autorun entry. Things that appear on one or two hosts deserve a look.

**Grouping and clustering** looks for things occurring together: several discovery commands (`whoami`, `net group`, `nltest`, `ipconfig`) executed by the same process tree within minutes is far more suspicious than any single one.

**Baselining and time-series analysis** compares current behavior to historical behavior for a host, user, or process. Beaconing detection is a classic example: C2 implants often call home at regular intervals, which creates a statistical signature even when the traffic itself is encrypted.

**Pivoting** means following threads. You find a suspicious process, pivot to its parent, its children, its network connections, the files it wrote, other hosts with the same hash, and the user's other logons. EDR process trees make this fast.

## Hunting in practice: common hunts with example queries

The examples below use KQL for Microsoft Defender for Endpoint / Sentinel advanced hunting, because it's widely used and readable, plus a couple in Splunk SPL. The logic translates to CrowdStrike's LogScale/CQL, SentinelOne's Deep Visibility or PowerQuery, Elastic EQL/ES|QL, Carbon Black, and others. Treat these as starting points to tune, not finished detections.

### Office applications spawning shells or script hosts

Macro-based and document-based initial access often shows Word, Excel, or Outlook launching something they have no business launching.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe","onenote.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","wscript.exe","cscript.exe",
                      "mshta.exe","rundll32.exe","regsvr32.exe","certutil.exe","bitsadmin.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

### Encoded or obfuscated PowerShell

Base64-encoded commands, download cradles, and hidden windows are classic tradecraft, though some admin tools use them legitimately, so expect to build an allowlist.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ ("powershell.exe","pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)\s-e[a-z]*\s+[A-Za-z0-9+/=]{40,}"
    or ProcessCommandLine has_any ("DownloadString","DownloadFile","IEX","Invoke-Expression",
                                   "FromBase64String","-w hidden","-windowstyle hidden","Net.WebClient")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

You can decode the Base64 in KQL with `base64_decode_tostring()` (PowerShell encodes as UTF-16LE, so you may need to strip null bytes) to read the payloads at scale.

### Living-off-the-land binaries (LOLBins)

Attackers abuse signed Windows binaries to download, execute, or proxy code: `certutil -urlcache`, `mshta http://...`, `regsvr32 /i:http... scrobj.dll`, `rundll32` calling JavaScript, `bitsadmin /transfer`, `msbuild` compiling inline tasks, `installutil`, and many more. The LOLBAS project catalogs them. Hunt for these binaries making network connections, running from unusual parents, or with unusual arguments.

```kql
DeviceNetworkEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("certutil.exe","mshta.exe","regsvr32.exe","rundll32.exe",
                                       "msbuild.exe","installutil.exe","bitsadmin.exe","wmic.exe")
| where RemoteIPType == "Public"
| summarize Connections=count(), Hosts=dcount(DeviceName), SampleCmd=any(InitiatingProcessCommandLine)
    by InitiatingProcessFileName, RemoteUrl, RemoteIP
| order by Hosts asc
```

A related classic: `rundll32.exe` running with no command-line arguments is a common artifact of Cobalt Strike and other frameworks' default spawn-to process.

### Rare binaries in user-writable locations (stacking)

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FolderPath has_any (@"\AppData\", @"\Temp\", @"\ProgramData\", @"\Users\Public\", @"\PerfLogs\")
| summarize DeviceCount=dcount(DeviceName), Executions=count(),
            SampleCmd=any(ProcessCommandLine), Signer=any(ProcessVersionInfoCompanyName)
    by FileName, SHA256
| where DeviceCount <= 3
| order by DeviceCount asc
```

Enrich the results with hash reputation, signature status, and first-seen date. A binary that first appeared yesterday on two machines, is unsigned, and lives in `ProgramData` deserves attention.

### Credential access: LSASS

Credential dumping via Mimikatz, `procdump -ma lsass.exe`, `comsvcs.dll MiniDump` (run through rundll32), Task Manager dumps, or custom tools is almost universal in intrusions. Hunt for command lines referencing LSASS dumps, and for unusual processes opening LSASS with memory-read access (in Sysmon this is Event ID 10 with suspicious `GrantedAccess` masks such as `0x1010` or `0x1410`; EDRs expose equivalents in their own schemas).

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where ProcessCommandLine has_any ("lsass", "MiniDump", "sekurlsa", "comsvcs")
    and (ProcessCommandLine has "comsvcs" or FileName in~ ("procdump.exe","procdump64.exe","rundll32.exe"))
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
```

Also look for SAM, SYSTEM, and SECURITY hive exports (`reg save hklm\sam`), `ntds.dit` access on domain controllers, `ntdsutil "ac i ntds" ifm`, and shadow-copy-based NTDS extraction.

### Persistence

Attackers need to survive reboots. Stack and review new scheduled tasks, new services, Run/RunOnce keys, startup folder items, WMI event subscriptions, IFEO debugger keys, and COM hijacks.

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where FileName =~ "schtasks.exe" and ProcessCommandLine has "/create"
| summarize Count=count(), Hosts=make_set(DeviceName, 20) by ProcessCommandLine, InitiatingProcessFileName
| order by Count asc
```

```kql
DeviceRegistryEvents
| where Timestamp > ago(14d)
| where RegistryKey has_any (@"\CurrentVersion\Run", @"\CurrentVersion\RunOnce",
                             @"\Image File Execution Options", @"\Winlogon")
| where ActionType == "RegistryValueSet"
| summarize Hosts=dcount(DeviceName), Sample=any(RegistryValueData)
    by RegistryKey, RegistryValueName, InitiatingProcessFileName
| order by Hosts asc
```

Service creation pointing at binaries in temp paths, or services whose command line contains `cmd /c` or `powershell`, is especially suspicious because this is how PsExec-style and Impacket-style tools behave.

### Lateral movement

Look at the destination side of remote execution. Signals include `services.exe` spawning unusual children (PsExec and SMB exec), `wmiprvse.exe` spawning shells (WMI exec), `wsmprovhost.exe` spawning processes (PowerShell remoting and WinRM), `mmc.exe` or `excel.exe` via DCOM, and RDP logons from workstations to other workstations. Also stack which accounts log on to which hosts. Admin accounts appearing on machines they've never touched, or one host fanning out to dozens of peers over SMB (445) or RPC (135) in a short window, are strong indicators.

```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("wmiprvse.exe","wsmprovhost.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","rundll32.exe","mshta.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

### Discovery bursts

Individually, `whoami`, `net user /domain`, `nltest /dclist`, `ipconfig /all`, `systeminfo`, `quser`, and AD enumeration tools like AdFind or SharpHound are benign. Clustered together under one parent in a few minutes, they're a hallmark of hands-on-keyboard activity.

```kql
let discovery = dynamic(["whoami.exe","net.exe","net1.exe","nltest.exe","ipconfig.exe","systeminfo.exe",
                         "quser.exe","tasklist.exe","arp.exe","route.exe","netstat.exe","adfind.exe"]);
DeviceProcessEvents
| where Timestamp > ago(7d)
| where FileName in~ (discovery)
| summarize Commands=dcount(FileName), CmdList=make_set(ProcessCommandLine, 20)
    by DeviceName, AccountName, InitiatingProcessId, InitiatingProcessFileName, bin(Timestamp, 10m)
| where Commands >= 4
```

### Command-and-control beaconing

Implants check in periodically. Even with jitter, their connection intervals are more regular than human-driven traffic. This query computes the time between connections for each process-destination pair and flags low-variance patterns.

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteIPType == "Public"
| sort by DeviceName asc, InitiatingProcessFileName asc, RemoteIP asc, Timestamp asc
| extend Delta = iff(DeviceName == prev(DeviceName) and RemoteIP == prev(RemoteIP)
                     and InitiatingProcessFileName == prev(InitiatingProcessFileName),
                     datetime_diff('second', Timestamp, prev(Timestamp)), long(null))
| where isnotnull(Delta) and Delta > 0
| summarize Count=count(), AvgDelta=avg(Delta), StdDelta=stdev(Delta)
    by DeviceName, InitiatingProcessFileName, RemoteIP, RemoteUrl
| where Count > 30 and StdDelta < AvgDelta * 0.2
| order by StdDelta asc
```

Expect a lot of legitimate noise (update agents, telemetry, chat apps), so allowlist by process and destination. Also hunt for rare destinations contacted by very few hosts, newly registered domains, direct-to-IP connections by non-browser processes, and connections to known tunneling and remote-access services (ngrok, Cloudflare tunnels, AnyDesk, ScreenConnect, and similar). Abuse of legitimate RMM tools is extremely common in current ransomware operations.

### Defense evasion

Hunt for attempts to blind you: clearing event logs (`wevtutil cl`), disabling Defender (`Set-MpPreference -DisableRealtimeMonitoring`, exclusion additions), stopping or tampering with security services, deleting the EDR agent, loading vulnerable signed drivers (BYOVD attacks used to kill EDR processes), timestomping, and masquerading (for example `svchost.exe` running from anywhere other than `System32`, or with the wrong parent).

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName in~ ("svchost.exe","lsass.exe","services.exe","csrss.exe","winlogon.exe","smss.exe")
| where not(FolderPath startswith @"C:\Windows\System32\") and not(FolderPath startswith @"C:\Windows\SysWOW64\")
| project Timestamp, DeviceName, FileName, FolderPath, InitiatingProcessFileName, SHA256
```

### Ransomware precursors and impact

Shadow copy deletion, backup catalog deletion, disabling recovery, and mass file renames often occur minutes before encryption. By then you're late, but finding the precursors on even one host can save the rest. Here it is in Splunk SPL (field names vary with your EDR data model):

```spl
index=edr
  ( (process_name="vssadmin.exe" process="*delete*shadows*")
 OR (process_name="wmic.exe" process="*shadowcopy*delete*")
 OR (process_name="bcdedit.exe" process="*recoveryenabled*no*")
 OR (process_name="wbadmin.exe" process="*delete*catalog*") )
| stats count min(_time) as first_seen by host, user, parent_process_name, process
```

Also hunt for data staging (large archives created with 7-Zip, WinRAR, or `tar` in odd directories) and exfiltration tools such as rclone, MEGAsync, WinSCP, and restic running on servers.

## Sigma: portable hunting logic

Sigma is an open, vendor-neutral format for describing detections in YAML, which can be converted into KQL, SPL, CQL, EQL, and other languages. The public Sigma repository contains thousands of community rules mapped to ATT&CK, and it's one of the best sources of ready-made hunt ideas. A minimal example looks like this:

```yaml
title: Office Application Spawning Script Interpreter
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith: ['\winword.exe', '\excel.exe', '\powerpnt.exe']
    Image|endswith: ['\powershell.exe', '\cmd.exe', '\wscript.exe', '\mshta.exe']
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1204.002
```

## Running a hunt, start to finish

A well-run hunt usually follows this arc. First, pick a hypothesis grounded in threat intel, an ATT&CK technique you lack coverage for, a recent incident, or a business-critical asset. Write it down in one sentence, for example: "An attacker with a foothold would use WMI to execute commands on remote hosts."

Then scope it. Decide which hosts, which time window, which data sources, and what "found it" would look like. Confirm your EDR actually collects the data you need, since hunting for something you can't see yields a meaningless "nothing found."

Next, research what the technique looks like in telemetry. Emulating it in a lab with Atomic Red Team, or reading how others detect it, is extremely helpful. Knowing the benign version of the behavior is equally important.

Execute the queries, starting broad, then stacking, filtering, and pivoting. Expect most of your time to go into separating legitimate activity (admin scripts, deployment tools, backup agents, vulnerability scanners) from the suspicious remainder.

Investigate what remains. For anything suspicious, walk the process tree, look at surrounding activity on the host, check the user's behavior, search for the same artifacts fleet-wide, and use EDR response features (live response shells, file retrieval, memory acquisition) if needed. If you find a real intrusion, the hunt becomes an incident, and you hand off or escalate according to your IR process, with host isolation available through the EDR.

Finally, act on the outcome, which is where hunting pays for itself even when nothing malicious is found. Convert reliable queries into scheduled detections or custom EDR rules. Document the allowlists you built. Record visibility gaps you discovered (missing logs, unmonitored hosts, telemetry your EDR doesn't collect) and push to close them. Report hygiene problems you noticed, like admins using plaintext credentials in scripts or unmanaged remote access tools. Log the hunt in a hunt library so it can be repeated periodically.

## Limitations and blind spots

EDR is powerful but not omniscient, and a good hunter knows where it's blind.

Coverage gaps are the first problem. Unmanaged devices, servers the agent was never deployed to, legacy systems, network appliances, OT or gaming-floor devices, and hypervisors (ESXi is a favorite ransomware target precisely because it usually has no EDR) produce no telemetry. An attacker who lives on an unmonitored host is invisible to endpoint hunting. Asset inventory reconciliation against EDR enrollment is a surprisingly high-value exercise.

Telemetry fidelity varies. Some EDRs sample or summarize high-volume events like network connections or file writes. Linux and macOS agents often collect less than Windows agents. Retention windows limit how far back you can look, which matters because median attacker dwell time is measured in days to weeks.

Attackers actively evade EDR. Techniques include unhooking user-mode API hooks, direct and indirect syscalls, BYOVD attacks to kill agents from the kernel, abusing trusted signed tools and RMM software, operating purely in memory, using cloud and identity planes where there's no endpoint at all, and timing activity to blend with normal working hours. Hunting for the side effects of evasion (agent health drops, sensor tampering events, unusual driver loads, hosts that suddenly stop reporting) is a hunt in itself.

Identity and cloud activity sit largely outside endpoint telemetry. Token theft, OAuth consent abuse, MFA fatigue, and SaaS data theft may never touch an endpoint the EDR watches. Mature programs combine EDR with identity logs (Entra ID or Active Directory), cloud audit logs, email telemetry, and network data (NDR, DNS, proxy) in a SIEM or XDR platform.

## Building a hunting program

A sustainable program needs a few things beyond queries. It needs a hunt backlog prioritized by threat relevance and visibility gaps, not by whatever looks interesting. It needs documentation: each hunt's hypothesis, queries, data sources, findings, and follow-ups. It needs a feedback loop into detection engineering, so the same thing never has to be manually hunted twice. It needs time protected from the alert queue, since hunters who are constantly pulled into triage never hunt.

Measure the right things. "Number of intrusions found" is a poor primary metric, because a well-defended environment should produce few. Better measures include ATT&CK techniques hunted, detections created or improved from hunts, visibility gaps identified and closed, reduction in dwell time, and hygiene issues remediated.

## Skills a good EDR hunter develops

The best hunters combine deep knowledge of how operating systems work normally (Windows internals, process lineage, authentication, services, the registry, Active Directory) with knowledge of attacker tradecraft, fluency in at least one query language, basic statistics for stacking and baselining, and enough familiarity with the business to know what's normal for your environment. Curiosity and skepticism matter more than any tool, and so does the discipline to document.

## Great resources

For hunt ideas and detection logic, the most useful resources include MITRE ATT&CK and MITRE's Cyber Analytics Repository (CAR), the SigmaHQ rule repository, the Threat Hunter Playbook (Roberto Rodriguez), Elastic's open detection rules, Microsoft's public Defender hunting query repositories, and Splunk's Security Content library. For understanding attacker behavior in practice, The DFIR Report publishes detailed real intrusion timelines that are ideal hunt fuel, and the LOLBAS and LOLDrivers projects catalog abused binaries and drivers. For testing your visibility, Atomic Red Team and similar adversary emulation tools let you safely generate the behavior you're hunting for. For methodology, the PEAK framework and SANS threat hunting materials (such as FOR508 and the SANS Threat Hunting Summit talks) are strong references. Sysmon, osquery, and Velociraptor are also worth knowing as free complements or alternatives for endpoint visibility and hunting.

---

