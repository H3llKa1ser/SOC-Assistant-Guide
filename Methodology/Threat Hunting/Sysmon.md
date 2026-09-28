# Threat Hunting with Sysmon

# Threat Hunting with Sysmon

## What Sysmon is

Sysmon (System Monitor) is a free Sysinternals tool by Mark Russinovich and Thomas Garnier. It installs a Windows service and a kernel driver that record detailed system activity to the event log `Microsoft-Windows-Sysmon/Operational`. The default Windows Security log tells you little about what processes actually did. Sysmon fills that gap with full command lines, parent-child relationships, file hashes, network connections tied to specific processes, registry changes, DNS queries, process memory access, and more.

It is not an EDR. It doesn't block much (with a couple of exceptions covered below), doesn't respond, and doesn't analyze. It is a high-quality telemetry source that you ship to a SIEM or data lake, where the hunting happens.

**Native Sysmon in Windows (2026).** Sysmon has traditionally been a standalone download. Microsoft announced it will integrate Sysmon directly into Windows 11 and Windows Server 2025 in 2026, an announcement made by Russinovich himself. The functionality first landed in Windows Insider builds 26300.7733 (Dev channel) and 26220.7752 (Beta channel). It is disabled by default, can be enabled through Windows Settings, PowerShell, or DISM, and still has to be initialized before it starts logging. The big operational win is that it gets updated through Windows Update instead of needing its own patch cycle. Check how this is rolling out in your Windows builds before choosing between native and standalone deployment.

## Architecture: why it's useful and where it's fragile

The driver (`SysmonDrv`) hooks kernel callbacks for process, thread, image load, and registry events, uses a minifilter for file events, and consumes ETW for things like DNS. The service applies your XML configuration filters and writes the surviving events to the event log.

Key design features:

- **ProcessGuid.** Every process gets a globally unique ID, which avoids the problem of Windows reusing PIDs. It lets you reliably chain events: process creation (1), then its network connections (3), files written (11), and child processes, all via ProcessGuid and ParentProcessGuid. Correlation by ProcessGuid is the single most important technique in Sysmon hunting.
- **LogonGuid and LogonId.** These link process activity back to a logon session, which you can join against Security Event 4624.
- **Hashes.** MD5, SHA1, SHA256, and IMPHASH are all configurable. IMPHASH is especially useful for clustering malware families that recompile often.
- **OriginalFileName.** Pulled from the PE header, this is how you catch renamed binaries (for example, `svch0st.exe` whose original name is `procdump`, or a renamed `rclone`).

## The event IDs

| ID | Event | Primary hunting value |
|---|---|---|
| 1 | Process Create | Command lines, parent-child anomalies, LOLBins, renamed tools |
| 2 | File creation time changed | Timestomping |
| 3 | Network Connection | C2, beaconing, lateral movement, processes that shouldn't talk to the network |
| 4 | Sysmon service state changed | Tampering with Sysmon |
| 5 | Process Terminated | Process lifetimes, short-lived processes |
| 6 | Driver Loaded | BYOVD (bring your own vulnerable driver), rootkits, unsigned drivers |
| 7 | Image Loaded (DLL) | DLL sideloading, unusual modules (e.g. `dbghelp.dll`, `clr.dll` in odd processes) |
| 8 | CreateRemoteThread | Process injection |
| 9 | RawAccessRead | Direct disk reads (NTDS.dit or SAM theft bypassing file locks) |
| 10 | ProcessAccess | LSASS credential dumping, injection prep |
| 11 | FileCreate | Payload drops, staging, startup folder persistence, ransomware |
| 12/13/14 | Registry create/delete, value set, rename | Persistence, defense evasion, configuration changes |
| 15 | FileCreateStreamHash | Alternate data streams, Mark-of-the-Web (`Zone.Identifier`) downloads |
| 16 | Sysmon config change | Tampering |
| 17/18 | Pipe Created / Connected | Cobalt Strike and other C2 named pipes, PsExec |
| 19/20/21 | WMI Filter / Consumer / Binding | WMI event subscription persistence |
| 22 | DNS Query | C2 domains, DGA, tunneling, first-seen domains per process |
| 23 | FileDelete (archived) | Deleted file recovery (saved to an archive directory) |
| 24 | ClipboardChange | Clipboard theft (use sparingly because of privacy) |
| 25 | ProcessTampering | Process hollowing, herpaderping |
| 26 | FileDeleteDetected | Logs deletions without archiving (cheaper than 23) |
| 27 | FileBlockExecutable | Blocks executable drops in specified locations |
| 28 | FileBlockShredding | Blocks tools like SDelete from wiping files |
| 29 | FileExecutableDetected | Logs creation of new PE files |
| 255 | Error | Sysmon internal errors (can also indicate tampering) |

Events 27 and 28 are the only real preventive controls Sysmon has. They are useful but narrow.

## Configuration: where most of the value is won or lost

Sysmon with no configuration logs very little of value. Sysmon with an "include everything" configuration will flood your SIEM, especially with Event IDs 3, 7, 10, 11, and 13. The configuration is essentially a detection-engineering artifact.

### Common starting points

- **SwiftOnSecurity/sysmon-config** is the classic, heavily commented, conservative baseline. It's good for learning.
- **Olaf Hartong's sysmon-modular** is modular, maps rules to MITRE ATT&CK, and offers pre-built variants (default, verbose, super-verbose, "MDE augment" for use alongside Defender for Endpoint). It is generally considered the most maintained and hunting-oriented option.
- **Florian Roth's fork** builds on SwiftOnSecurity with extra detection coverage.

### Syntax essentials

```xml
<Sysmon schemaversion="4.90">
  <HashAlgorithms>SHA256,IMPHASH</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <ProcessCreate onmatch="exclude">
        <Image condition="is">C:\Windows\System32\backgroundTaskHost.exe</Image>
      </ProcessCreate>
    </RuleGroup>
    <RuleGroup name="" groupRelation="or">
      <ProcessAccess onmatch="include">
        <Rule groupRelation="and" name="technique_id=T1003.001,technique_name=LSASS Memory">
          <TargetImage condition="end with">\lsass.exe</TargetImage>
          <GrantedAccess condition="is any">0x1010;0x1410;0x1438;0x143a;0x1fffff</GrantedAccess>
        </Rule>
      </ProcessAccess>
    </RuleGroup>
  </EventFiltering>
</Sysmon>
```

Things to understand about configs:

- `onmatch="include"` logs only what matches; `onmatch="exclude"` logs everything except what matches. If both exist for the same event type, include is evaluated and then exclude filters it down (exclude wins).
- An event type with an empty `include` block logs nothing. An empty `exclude` block logs everything.
- Conditions include `is`, `is not`, `contains`, `contains any`, `contains all`, `begin with`, `end with`, `excludes`, `image`, `less than`, and `more than`.
- The `name` attribute on a rule populates the `RuleName` field in the event. Tagging rules with ATT&CK technique IDs means every event arrives pre-labeled, which makes hunting and dashboards dramatically easier.
- Use `sysmon64 -s` to print the schema for your version, so you know which fields and events are supported.

### Deployment commands

```
sysmon64.exe -accepteula -i config.xml   # install with a config
sysmon64.exe -c config.xml               # update the config live
sysmon64.exe -c                          # show the current config
sysmon64.exe -u                          # uninstall
```

At scale, people deploy through GPO startup scripts, SCCM/Intune, or scheduled tasks that pull a config from a share and compare hashes. Native Sysmon will make this simpler. You can also rename the service and driver at install time to make them slightly harder to find, which is security by obscurity but raises the bar a little.

### Configuration tuning tips

- Exclude your own EDR, AV, backup agents, and management tools from Event 10 (ProcessAccess) and Event 7 (ImageLoad). They are the biggest noise generators.
- For Event 7, include only interesting DLLs (`dbghelp.dll`, `dbgcore.dll`, `samlib.dll`, `vaultcli.dll`, `clr.dll`/`clrjit.dll` for in-memory .NET, `System.Management.Automation.dll` for unmanaged PowerShell, `wmiutils.dll`) rather than logging every load.
- For Event 3, exclude well-known, high-volume, trusted processes by full path (not just name), and consider logging only outbound, non-RFC1918 traffic or specific suspicious processes.
- For Event 22, exclude your internal domains and the huge Microsoft/CDN noise, but be careful not to exclude domains attackers abuse (for example, blanket-excluding `*.azurewebsites.net` or `*.cloudfront.net` hides a lot of C2).
- Always exclude by full path. Excluding `chrome.exe` by name lets any attacker's `chrome.exe` in `%TEMP%` go dark.
- Raise the Sysmon event log's max size well above the default and forward events off-box quickly.

## Getting the data somewhere useful

Hunting on individual endpoints doesn't scale. Typical pipelines:

- **Windows Event Forwarding (WEF/WEC)**: native, agentless, free. Forward to a collector, then to a SIEM.
- **Splunk Universal Forwarder** with the Splunk Add-on for Sysmon (field extraction and CIM mapping).
- **Elastic Agent / Winlogbeat** with the Sysmon integration (ECS-normalized).
- **Microsoft Sentinel** through the Azure Monitor Agent collecting from the Sysmon channel, parsed with ASIM parsers.
- **Wazuh, Graylog, Security Onion, Velociraptor**: all have Sysmon support.
- **Offline or IR work**: pull `.evtx` files and use Chainsaw or Hayabusa (both apply Sigma rules to raw EVTX), DeepBlueCLI, EvtxECmd (Eric Zimmerman) with Timeline Explorer, or Sysmon View / SysmonTools for visual process-tree reconstruction.

## Hunting methodology

Sysmon hunting works best when it's structured rather than a random scroll through logs.

**Hypothesis-driven hunting.** Start from a specific idea ("An attacker with initial access via phishing would spawn a script interpreter from an Office process") and look for evidence. Frame hypotheses around MITRE ATT&CK techniques and threat intelligence about the actors relevant to your industry.

**Stacking (frequency analysis / long-tail analysis).** Count occurrences of a value across the environment and look at the rare ones: rare parent-child pairs, rare command lines, rare DLLs loaded by `lsass.exe`, rare processes making outbound connections, rare named pipes, hashes seen on only one or two hosts. Attackers are usually the long tail.

**Baselining.** Know what normal looks like in your environment: which admin tools run, which service accounts do what, which software updates itself over the network. Hunting without a baseline produces endless false positives.

**Pivoting through ProcessGuid.** Once you find one suspicious event, expand it into the full story: parent chain upward, children downward, network connections, files, registry changes, DNS queries, and logon session.

**Convert hunts into detections.** A successful hunt query that produces a manageable number of results should become a scheduled detection (ideally a Sigma rule), freeing you to hunt for the next thing.

## Hunts by tactic

Queries below are shown in Splunk SPL-style or KQL-style pseudocode. Field names vary slightly by pipeline (Elastic uses ECS names like `process.parent.executable`), so adapt them.

### Initial access and execution

**Office apps spawning interpreters or LOLBins.** One of the highest-signal hunts there is.

```
index=sysmon EventCode=1
ParentImage IN ("*\\WINWORD.EXE","*\\EXCEL.EXE","*\\POWERPNT.EXE","*\\OUTLOOK.EXE","*\\MSPUB.EXE","*\\ONENOTE.EXE")
Image IN ("*\\powershell.exe","*\\pwsh.exe","*\\cmd.exe","*\\wscript.exe","*\\cscript.exe","*\\mshta.exe","*\\rundll32.exe","*\\regsvr32.exe","*\\certutil.exe","*\\bitsadmin.exe")
```

Also look at browsers or archive tools (`7zFM.exe`, `WinRAR.exe`, `explorer.exe` opening ISO/LNK/HTA files) spawning script engines, as phishing moved to container files after Microsoft blocked macros from the internet.

**PowerShell abuse.** Look for `-enc`/`-EncodedCommand` (and truncated variants like `-e`, `-ec`), `-nop`, `-w hidden`, `IEX`, `DownloadString`, `FromBase64String`, `Net.WebClient`, `Invoke-WebRequest`, `-ExecutionPolicy Bypass`. Stack by parent: PowerShell spawned by `services.exe`, `wmiprvse.exe`, or `w3wp.exe` is almost always interesting. Pair Sysmon with PowerShell Script Block Logging (Event 4104) for the decoded content.

**LOLBins (living-off-the-land binaries).** The LOLBAS project catalogs them. Classic hunts:
- `certutil.exe` with `-urlcache`, `-split`, `-decode`
- `mshta.exe` with an `http` argument or `javascript:`
- `regsvr32.exe` with `/i:http` or `scrobj.dll` (Squiblydoo)
- `rundll32.exe` with no arguments, with `javascript:`, or loading DLLs from user-writable paths
- `msbuild.exe`, `installutil.exe`, `regasm.exe`, `regsvcs.exe` running outside developer machines
- `bitsadmin.exe /transfer`
- `wmic.exe` with `process call create` or `/format:` pointing to remote XSL

**Execution from suspicious paths.** Processes running from `%TEMP%`, `%APPDATA%`, `C:\Users\Public`, `C:\ProgramData`, `C:\PerfLogs`, `$Recycle.Bin`, or `C:\Windows\Temp`, especially unsigned ones.

**Renamed binaries.** Look for `OriginalFileName` not matching the `Image` filename, such as `OriginalFileName=PowerShell.EXE` while `Image` ends in something else.

**Masquerading.** System binaries running from the wrong location (`svchost.exe` outside `System32`/`SysWOW64`), wrong parents (`svchost.exe` whose parent isn't `services.exe`, `lsass.exe` whose parent isn't `wininit.exe`), and typosquatted names (`scvhost.exe`, `lsasss.exe`). SANS's "Hunt Evil" poster documents the normal parent-child relationships of core Windows processes.

### Persistence

**Registry Run keys and friends (Events 12/13):** `...\CurrentVersion\Run`, `RunOnce`, `Winlogon\Userinit`, `Winlogon\Shell`, `Image File Execution Options\*\Debugger`, `SilentProcessExit`, `AppInit_DLLs`, `Services\*\ImagePath`, `COM` hijacks under `HKCU\Software\Classes\CLSID`, `Environment\UserInitMprLogonScript`. Hunt for values pointing to user-writable paths or containing script interpreters.

**Startup folder (Event 11):** files created in `\Start Menu\Programs\Startup\`.

**Scheduled tasks:** `schtasks.exe /create` in Event 1, and files created in `C:\Windows\System32\Tasks\` in Event 11. Pair with Security Event 4698.

**Services:** `sc.exe create`, or registry writes under `HKLM\SYSTEM\CurrentControlSet\Services\`, especially where `ImagePath` contains `cmd.exe`, `powershell`, or a user path.

**WMI event subscriptions (Events 19/20/21):** these are rare in legitimate use in most environments, so nearly every hit is worth reviewing. `CommandLineEventConsumer` and `ActiveScriptEventConsumer` are the dangerous ones.

### Privilege escalation and defense evasion

**Process injection (Event 8):** `CreateRemoteThread` into processes like `explorer.exe`, `svchost.exe`, `lsass.exe`, `rundll32.exe`, from a source that isn't a known legitimate tool. Filter out known noise, and whatever remains deserves attention.

**Process tampering (Event 25):** image replacement in memory, which indicates hollowing or herpaderping. Low volume, high value.

**Suspicious DLL loads (Event 7):** `clr.dll` loaded into processes that don't normally run .NET (indicating execute-assembly style tradecraft), `System.Management.Automation.dll` loaded outside `powershell.exe` (unmanaged PowerShell), unsigned DLLs loaded by signed Microsoft binaries from their own directory (DLL sideloading).

**Vulnerable or malicious drivers (Event 6):** stack drivers by hash and signer. Compare hashes to the LOLDrivers project list. Unsigned or revoked-signature drivers are high priority. BYOVD is heavily used by ransomware crews to kill EDR.

**Timestomping (Event 2):** file creation times changed by processes other than installers, archive tools, and cloud sync clients.

**Security tool tampering:** `sc stop`/`sc delete` on security services, `Set-MpPreference -DisableRealtimeMonitoring`, Defender exclusion paths added via registry (`...\Windows Defender\Exclusions\Paths`), `wevtutil cl` (clearing logs), `auditpol /clear`, `fltmc unload`.

### Credential access

**LSASS access (Event 10):** the flagship Sysmon hunt. Look at `TargetImage` ending in `lsass.exe` with `GrantedAccess` values like `0x1010`, `0x1410`, `0x1438`, `0x143a`, `0x1fffff`. Stack by `SourceImage`: you'll see AV/EDR, `svchost`, `wininit`, `MsMpEng`, and similar. Anything else (especially `rundll32.exe`, `powershell.exe`, `taskmgr.exe` from an interactive session, or anything from a user path) needs explaining. A `CallTrace` containing `UNKNOWN` means the calling code isn't backed by a module on disk, which strongly suggests shellcode or reflective loading.

**Command-line indicators:** `comsvcs.dll` with `MiniDump`, `procdump` with `-ma lsass`, `rundll32` with `comsvcs`, `reg save HKLM\SAM` / `HKLM\SYSTEM` / `HKLM\SECURITY`, `ntdsutil` with `ifm`, `vssadmin create shadow`, `esentutl` copying `ntds.dit`.

**Raw disk reads (Event 9):** processes reading the volume directly, often to copy locked files like `NTDS.dit` or the SAM hive.

**Dump files created (Event 11):** `.dmp` files written by unexpected processes, or files named like `lsass*.dmp`.

### Discovery

Individually benign commands become interesting in clusters. Look for bursts of `whoami`, `net user`, `net group "domain admins"`, `nltest /domain_trusts`, `ipconfig /all`, `systeminfo`, `tasklist`, `quser`, `arp -a`, `route print`, `netstat -ano`, `dsquery`, `AdFind.exe`, or `SharpHound`-style LDAP enumeration, especially many of them from one parent in a short window. A time-windowed count of distinct discovery commands per host or parent is a good hunt.

### Lateral movement

**PsExec and clones:** a `PSEXESVC` service or binary; named pipes (Events 17/18) like `\PSEXESVC`, `\RemCom_communication`, and the patterns used by Impacket.

**Impacket-style remote execution:** `cmd.exe /Q /c ... 1> \\127.0.0.1\ADMIN$\__<timestamp>` (wmiexec) is extremely distinctive, as is `wmiprvse.exe` spawning `cmd.exe`/`powershell.exe`.

**WinRM:** `wsmprovhost.exe` spawning processes, and network connections to 5985/5986.

**RDP:** outbound 3389 from workstations to workstations, and `mstsc.exe` launched with unusual arguments.

**SMB from odd processes:** Event 3 connections to port 445 from processes other than `System` (PID 4) are worth stacking.

**DCOM:** `mmc.exe`, `excel.exe`, or `explorer.exe` spawned by `svchost.exe -k DcomLaunch` in unusual patterns.

### Command and control

**Named pipes:** some C2 frameworks use default pipe names. Cobalt Strike's defaults such as `\MSSE-*-server`, `\msagent_*`, `\postex_*`, and `\status_*` are well documented. Sophisticated operators change them, but many don't.

**Beaconing (Event 3 and 22):** connections from one process to one destination at regular intervals. Compute the time delta between connections per `(host, image, destination)` and look for low variance (jitter reduces this but rarely eliminates it). RITA is a tool built for this kind of analysis on network data.

**Processes that shouldn't be networking:** `rundll32.exe`, `regsvr32.exe`, `mshta.exe`, `notepad.exe`, `calc.exe`, `dllhost.exe` with no arguments, `werfault.exe`, or anything in `%TEMP%` making outbound connections.

**DNS hunts (Event 22):** first-seen domains per environment, high-entropy or DGA-like names, very long subdomains (tunneling), domains with newly registered TLDs, queries from unusual processes, and abuse of dynamic DNS providers. The `QueryResults` field ties the domain to resolved IPs you can join against Event 3.

**Remote access tools:** AnyDesk, ScreenConnect, Atera, TeamViewer, Splashtop, and similar tools appearing where your organization doesn't use them. Ransomware affiliates rely on these heavily.

### Collection, exfiltration, and impact

**Exfiltration tools:** `rclone.exe` (often renamed, so use `OriginalFileName` or its command-line flags like `--config`, `copy`, `mega:`), `WinSCP`, `curl.exe` with `-T`/`--upload-file` or `-F`, MEGAsync, and large archive creation with `7z.exe`/`rar.exe` using a password flag (`-p`).

**Ransomware precursors:**
- `vssadmin delete shadows`, `wmic shadowcopy delete`, `wbadmin delete catalog`, `bcdedit /set {default} recoveryenabled no`
- Mass file creation or renaming with a new extension (Event 11 counts per process per minute)
- Ransom-note filenames appearing across many directories
- Services stopped in bulk (`net stop` loops against SQL, backup, and AV services)

**Deleted evidence (Event 23/26):** attacker tools deleting themselves after running. Event 23 with archiving can actually give you the deleted file back, which is great for forensics but consumes disk, so scope it tightly to high-value extensions and paths.

## Sigma: the lingua franca

Sigma is a generic, YAML-based detection format that converts to SPL, KQL, Lucene/EQL, and more. The SigmaHQ repository contains thousands of rules, a large fraction written against Sysmon fields. Chainsaw and Hayabusa apply these rules directly against EVTX files. A minimal example:

```yaml
title: Office Application Spawning Script Interpreter
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
    Image|endswith:
      - '\powershell.exe'
      - '\wscript.exe'
      - '\mshta.exe'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1204.002
```

Learning to read and tune Sigma rules is one of the fastest ways to build Sysmon hunting skill.

## Sysmon's weaknesses and how attackers evade it

Knowing these tells you both what to monitor and where not to trust Sysmon blindly.

**Configuration blind spots.** The config is readable by admins (`sysmon -c`, or from the registry under the driver's parameters key), so an attacker with admin rights can read your exclusions and operate inside them. Exclusions by process name alone are the classic gap.

**Tampering.** Attackers with admin rights can stop the service, unload the driver (`fltmc unload SysmonDrv`), change the config, clear the log, or patch ETW in-process. Hunt for Event 4 (service state), Event 16 (config change), Event 255 (errors), Security Event 1102 (log cleared), and System Event 7036/7040 (service changes). Most importantly, monitor for **silence**: a host that stops sending Sysmon events while still sending other telemetry is a strong signal. Heartbeat-gap alerting is one of the most valuable things you can build.

**Driver altitude conflicts.** Minifilter altitude manipulation can prevent Sysmon's file driver from seeing events.

**Direct syscalls and in-memory tradecraft.** Some techniques bypass the user-mode or callback paths Sysmon relies on, or simply produce less telemetry (for example, running everything inside one already-running process). Sysmon sees process creation very reliably but only sees in-memory behavior indirectly (Events 8, 10, 25, and module loads).

**Short windows.** Event log rollover on busy hosts can destroy evidence if forwarding lags.

**No inherent prevention.** Apart from Events 27/28, Sysmon observes and never stops anything.

**Command-line obfuscation.** Caret insertion (`p^o^w^e^r^s^h^e^l^l`), environment variable substitution, and quote tricks can evade naive string matching. Normalize command lines before matching or rely on `Image` and `OriginalFileName` plus behavioral context.

## Sysmon for Linux

Sysmon for Linux (open source, built on eBPF) logs to syslog in the same XML event schema, supporting a subset of events: process create and terminate, network connections, file create and delete, and a few others. It's useful for consistency in mixed environments. Hunts translate naturally: reverse shells (`bash -i` with `/dev/tcp`), `curl | sh` patterns, cron and systemd persistence file writes, processes running from `/tmp` or `/dev/shm`, and web server processes (`nginx`, `apache2`, `java`) spawning shells.

## Sysmon alongside EDR

Many organizations run Sysmon alongside Defender for Endpoint, CrowdStrike, SentinelOne, and others. EDR telemetry is often sampled, summarized, or retained for a limited time, while Sysmon gives you full, configurable, raw events in your own SIEM with your own retention. Sysmon-modular's "MDE augment" config is designed to fill specific gaps without duplicating what MDE already collects. Sysmon is also valuable in environments where you can't afford an EDR, or as an independent telemetry source if the EDR gets killed.

## Practical tips from the field

1. Start with a well-maintained community config, deploy to a pilot group, measure volume per event ID, then tune. Event IDs 3, 7, 10, 11, and 13 are where volume explodes.
2. Tag rules with ATT&CK IDs so `RuleName` does classification work for you.
3. Keep your config in version control and deploy changes like code.
4. Monitor Sysmon's health (versions, config hash, heartbeat) across the fleet. A fleet running five different config versions is a fleet with unknown blind spots.
5. Build a process-tree view in your SIEM keyed on ProcessGuid; it makes investigation many times faster.
6. Enrich events at ingest: hash reputation, domain age, internal asset criticality, user role.
7. Practice with Atomic Red Team or similar emulation frameworks to confirm your config and detections actually fire for the techniques you care about. Many teams discover their config silently excludes the exact thing they wanted to detect.
8. The Mordor/Security-Datasets project (OTRF) and the EVTX-ATTACK-SAMPLES repository provide pre-recorded attack telemetry for practicing hunts without running attacks yourself.
9. Read the Sysmon event documentation for your version; fields get added over time (for example, `ParentUser` was a later addition).

## Useful resources

The Sysinternals Sysmon documentation page, SwiftOnSecurity/sysmon-config, olafhartong/sysmon-modular, TrustedSec's Sysmon Community Guide (an excellent deep reference on every event type), SigmaHQ, the LOLBAS and LOLDrivers projects, the SANS "Hunt Evil" poster, Roberto Rodriguez's OTRF projects (Security-Datasets, ThreatHunter-Playbook), Chainsaw and Hayabusa for EVTX analysis, and the MITRE ATT&CK data sources pages (which map techniques to the telemetry needed to see them).

