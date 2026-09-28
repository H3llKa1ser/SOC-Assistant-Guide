# Advanced Windows Forensics

## Windows Event Log Analysis

**What event logs are:** Windows stores audit and system activity in `.evtx` files (XML-based binary format, introduced with Vista/2008, replacing the older `.evt` format). Default location:
```
C:\Windows\System32\winevt\Logs\
```

**The three classic channels plus modern ones:**
- **Security.evtx** — authentication, privilege use, object access, policy changes (the crown jewel for intrusion investigations)
- **System.evtx** — driver, service, and OS component events
- **Application.evtx** — application-generated events
- Plus hundreds of **Applications and Services Logs** channels (PowerShell, TaskScheduler, TerminalServices, WMI-Activity, Windows Defender, etc.)

**High-value Security Event IDs:**

| Event ID | Meaning |
|----------|---------|
| 4624 | Successful logon (check Logon Type) |
| 4625 | Failed logon |
| 4634 / 4647 | Logoff / user-initiated logoff |
| 4648 | Logon with explicit credentials (lateral movement indicator) |
| 4672 | Special privileges assigned (admin logon) |
| 4720 | User account created |
| 4726 | User account deleted |
| 4728 / 4732 / 4756 | User added to security-enabled group |
| 4688 | Process creation (enable command-line auditing!) |
| 4698 | Scheduled task created (persistence) |
| 4697 | Service installed (persistence) |
| 4776 | NTLM credential validation |
| 1102 | **Security log cleared** (anti-forensics red flag) |

**Logon Types (field in 4624/4625) — critical to interpret:**
- **2** — Interactive (physical/keyboard)
- **3** — Network (SMB, file shares — most lateral movement)
- **4** — Batch (scheduled tasks)
- **5** — Service
- **7** — Unlock
- **8** — NetworkCleartext (often IIS basic auth)
- **9** — NewCredentials (runas /netonly — seen with `Pass-the-Hash`-style tooling)
- **10** — RemoteInteractive (RDP)
- **11** — CachedInteractive (cached domain creds)

**Other essential channels for IR:**
- **PowerShell Operational** (`Microsoft-Windows-PowerShell/Operational`) — Event **4104** captures script block logging (deobfuscated PowerShell), **4103** module logging
- **TaskScheduler/Operational** — 106 (registered), 140/141, 200/201 (task executed)
- **TerminalServices-LocalSessionManager & RemoteConnectionManager** — RDP session tracking (21, 22, 25, 1149)
- **WMI-Activity/Operational** — WMI persistence and lateral movement
- **Windows Defender/Operational** — 1116/1117 detections

**Analysis methodology:**
1. **Build a timeline** — correlate across logs by timestamp (watch UTC vs. local, and clock skew)
2. **Establish the baseline** — what's normal for this host/environment?
3. **Pivot on anomalies** — off-hours logons, service accounts logging on interactively, Type 3/10 from unusual sources
4. **Watch for anti-forensics** — 1102 (log cleared), gaps in sequential record numbers, the log service being stopped

**Key gotchas:**
- Event logs **roll over** — default sizes are small; attackers exploit this
- Command-line auditing (4688) and PowerShell logging are **off by default** — their presence tells you about the environment's maturity
- Timestamps are stored in **UTC** internally
- Record numbers are sequential — gaps suggest tampering

**Command-line / free tooling** worth knowing alongside GUI tools:
- **`wevtutil`** (built-in) — query/export logs
- **`Get-WinEvent`** (PowerShell) — powerful filtering with FilterHashtable/XPath
- **Chainsaw** and **Hayabusa** — fast Sigma-rule-based `.evtx` hunting
- **EvtxECmd** (Eric Zimmerman) — parses evtx to CSV/JSON with maps
- **DeepBlueCLI** — PowerShell threat-hunting on evtx

---

## Event Log Analysis with Event Log Explorer

**Event Log Explorer** (by FSPro Labs) is a popular commercial GUI (free for personal use) that goes well beyond the native Windows Event Viewer.

**Why analysts like it over Event Viewer:**
- Opens `.evtx` files **offline** from acquired images without importing
- **Much faster** filtering and searching across large logs
- **Consolidated views** — merge multiple logs into one chronological timeline
- **Persistent workspaces** — save your log set and filters between sessions
- Color-coding, bookmarks, and better export (Excel, HTML, CSV, tab-delimited)

**Core workflow:**
1. **Load logs** — either connect to a live machine or `File → Open Log File` to load `.evtx` extracted from an image (point it at the `winevt\Logs` folder from your evidence)
2. **Apply filters** — filter by Event ID, level, source, time range, user, computer, or keyword in the description
3. **Use the description/XML view** — inspect the full event data, including the fields not shown in the summary column
4. **Consolidate** — merge Security + System + PowerShell logs to see cross-log sequences (e.g., a logon followed by a service install followed by a process creation)
5. **Bookmark** notable events and export the filtered set for your report

**Practical tips:**
- Build a **filter library** for your common IR Event IDs (4624/4625/4688/4720/1102, etc.)
- Use the **"Event Log by Time" consolidation** to reconstruct an attacker's session
- When working from an image, copy out the whole `Logs` directory so cross-referencing channels works
- Watch for the log-tampering tells the tool surfaces (cleared logs show as a 1102 with the account that did it)

For fully scripted/repeatable work, analysts often pair the GUI (for interactive triage) with EvtxECmd or Chainsaw (for bulk automation) — GUI for depth, CLI for breadth.

---

## Windows Registry Forensics

**What the registry is:** A hierarchical database of configuration and state. Forensically it's a goldmine because it records program execution, device connections, user activity, and persistence.

**The five root keys (HKEYs):**
- **HKLM** (HKEY_LOCAL_MACHINE) — system-wide settings
- **HKU** (HKEY_USERS) — all loaded user profiles
- **HKCU** — current user (a link into HKU)
- **HKCR** — file associations (merge of HKLM/HKCU Classes)
- **HKCC** — current hardware profile

**Where the hives actually live on disk (this matters for acquisition):**

System hives — `C:\Windows\System32\config\`:
- **SYSTEM** — services, drivers, mounted devices, current control set
- **SOFTWARE** — installed software, OS config, autoruns
- **SECURITY** — security policy
- **SAM** — local account info (hashes; sensitive)
- **DEFAULT**

Per-user hives:
- **NTUSER.DAT** — `C:\Users\<user>\` (user's HKCU)
- **UsrClass.dat** — `C:\Users\<user>\AppData\Local\Microsoft\Windows\` (holds the very useful **Shellbags** and modern MRU data)

**Also critical — the Amcache hive:**
- `C:\Windows\AppCompat\Programs\Amcache.hve` — program execution artifact (SHA1 hashes, paths, timestamps of executed binaries)

**Registry transaction logs** (`.LOG1`/`.LOG2`) contain unwritten changes — for thorough work you replay these into the hive (RegRipper/Registry Explorer handle "dirty" hives).

**High-value forensic artifacts by category:**

**Program execution:**
- **UserAssist** (`NTUSER.DAT\...\Explorer\UserAssist`) — GUI programs run, run count, last run (ROT13-encoded names)
- **ShimCache / AppCompatCache** (`SYSTEM\...\AppCompatCache`) — evidence of execution/presence, path + timestamps
- **Amcache.hve** — executed binaries with SHA1
- **BAM/DAM** (`SYSTEM\...\bam\State\UserSettings`) — Background Activity Moderator, records last execution time per user
- **MUICache**

**File/folder access & user activity:**
- **RecentDocs** — recently opened files by extension
- **OpenSavePidlMRU / LastVisitedPidlMRU** — file open/save dialog history
- **RunMRU** — commands typed into Run box
- **TypedPaths** — Explorer address bar
- **Shellbags** (UsrClass.dat + NTUSER.DAT) — folders the user browsed, including now-deleted and removable/network folders (proves knowledge/access)

**USB / device history:**
- **USBSTOR** (`SYSTEM\...\Enum\USBSTOR`) — connected USB storage devices (vendor, product, serial)
- **USB** key, **MountedDevices**, and correlate with `Microsoft-Windows-Partition/Diagnostic` and setupapi logs for first/last insertion times

**Persistence (autoruns):**
- **Run / RunOnce** (both HKLM and HKCU)
- **Services** (`SYSTEM\CurrentControlSet\Services`)
- **Winlogon** (Shell, Userinit)
- **Scheduled Tasks** references, **AppInit_DLLs**, **Image File Execution Options** (debugger hijack)

**System configuration:**
- **CurrentControlSet** — note the `Select` key tells you which ControlSet is current; images have ControlSet001/002
- **ComputerName**, **TimeZoneInformation** (essential for timeline normalization!)
- **NetworkList** — networks the machine connected to, with timestamps
- Last shutdown time

**Key concepts:**
- **LastWrite time** — every registry key has a timestamp (like a file's mtime) — the backbone of registry timelining
- **ControlSets** — always confirm which is "current" via `SYSTEM\Select`
- Values can be hidden/null-embedded to evade naive tools

---

## Registry Forensics with Registry Explorer

**Registry Explorer** (Eric Zimmerman, free) is the modern standard for manual registry analysis.

**Why it's superior to regedit for forensics:**
- Loads **offline hive files** (never touch the live registry of your evidence)
- **Automatically detects and replays dirty transaction logs** (`.LOG1/.LOG2`) — reconstructing the true, latest state
- **Bookmarks** — hundreds of built-in bookmarks pointing you straight to known forensic artifacts, so you don't have to memorize every path
- Shows **all timestamps**, including nanosecond LastWrite times
- Recovers **deleted keys/values** (unallocated within the hive)
- Displays **raw hex + multiple data interpretations** simultaneously
- Powerful search and value-type decoding; export to Excel

**Typical workflow:**
1. **Load hives** — File → Load hive; add SYSTEM, SOFTWARE, NTUSER.DAT, UsrClass.dat, Amcache.hve, SAM as needed
2. **Accept the dirty-log replay prompt** — let it apply the transaction logs (choose to replay for accuracy)
3. **Use the Bookmarks pane** — jump directly to UserAssist, ShimCache, USBSTOR, Run keys, Shellbags, etc. Bookmarks show a count so you immediately see if data exists
4. **Inspect values** — use the type viewers (the tool decodes ROT13 for UserAssist, binary structures for Shellbags, etc.)
5. **Check deleted records** — the "Available Bookmarks" and deleted key recovery surface anti-forensic deletions
6. **Export** findings for the report

**The Zimmerman companion CLI tools** (for automation/timelines):
- **RECmd** — command-line registry parsing with batch "plugin" files (`RECmd\BatchExamples\`), great for processing many hives consistently
- **AppCompatCacheParser** — ShimCache
- **AmcacheParser** — Amcache.hve
- **AppCompatCache**, **SBECmd** (Shellbags Explorer CLI), **ShellBags Explorer** (GUI companion)
- Output everything to CSV → load into **Timeline Explorer** for pivoting

**RegRipper** (Harlan Carvey, free/open source) is the other classic — a plugin-based tool that dumps known artifacts from a hive automatically (`rip.exe`/`rr.exe`). Many analysts run RegRipper for a fast automated first pass, then use Registry Explorer for deep manual inspection.

---

## Windows Evidence Acquisition Tools & Techniques

**The foundational principles:**
- **Order of Volatility (RFC 3227)** — collect most-volatile first: CPU registers/cache → RAM → network state/ARP/routing → running processes → disk → remote logs → archival media
- **Forensic soundness** — preserve integrity, minimize alteration, document everything
- **Chain of custody** — who, what, when, where for every piece of evidence
- **Hashing** — MD5/SHA-256 the acquisition; verify the copy matches the source
- **Write-blocking** — hardware or software write blockers when imaging disks so you never alter the source

**Two big categories: live (volatile) vs. dead (disk) acquisition.**

### Memory (RAM) acquisition
Volatile — captures running processes, network connections, injected code, encryption keys, unsaved data, malware that never touches disk.

Tools:
- **WinPmem** (open source) — reliable, outputs raw/AFF4
- **Magnet RAM Capture** (free)
- **FTK Imager** (also does memory)
- **Belkasoft Live RAM Capturer**
- **DumpIt** (Comae)

Then analyze with **Volatility 3** or **MemProcFS** (pslist, netscan, malfind, cmdline, etc.).

Note: acquiring the **pagefile.sys / swapfile.sys** and **hiberfil.sys** (hibernation file — a compressed RAM image) complements live memory capture.

### Disk (dead) acquisition — imaging
Create a bit-for-bit forensic image.

Image formats:
- **Raw / dd** — exact bytes, large
- **E01 (EnCase Expert Witness)** — compressed, with embedded metadata and hashes (most common)
- **AFF4** — modern open format

Tools:
- **FTK Imager** (free, industry staple — imaging, hashing, preview, memory capture, protected-file export)
- **Guymager** (Linux, fast)
- **dd / dcfldd / dc3dd** (Linux CLI; dcfldd/dc3dd add hashing + progress)
- **EnCase**, **X-Ways**, **Magnet AXIOM** (commercial suites)
- **Guymager**/Linux boot media (Paladin, CAINE, Tsurugi) for dead-box imaging

**Live vs. dead disk imaging:** dead-box (powered off, boot to forensic Linux, write-block) is cleanest. Live imaging is needed when you can't power down (servers) or when disk encryption (BitLocker) means powering off loses access — in that case capture RAM (for keys) and image while the volume is unlocked.

### Triage / targeted collection
Full images are huge; often you collect just the high-value artifacts fast:
- **KAPE** (Kroll Artifact Parser and Extractor) — the dominant triage tool. **Targets** define what to collect (event logs, registry hives, $MFT, prefetch, browser data, etc.); **Modules** run parsers (often the Zimmerman tools) against them. Collect + process in minutes.
- **Velociraptor** — endpoint hunting & remote collection at scale
- **CyLR**, **FastIR**, **Magnet RESPONSE** (free)
- **Autopsy / The Sleuth Kit** — free full analysis platform

### Locked/live system files
The registry hives and event logs are **locked** while Windows runs. To grab them from a live box:
- **FTK Imager** "Export files" / **KAPE** use raw NTFS/volume access to copy locked files
- **Volume Shadow Copies (VSS)** — snapshots that let you access locked files and recover previous versions of files/registry; mount and pull historical hives (great for showing state over time)

### Cloud / modern considerations
- **BitLocker** — capture recovery keys, image while unlocked, or pull keys from memory
- **VSS** for point-in-time recovery
- Increasingly, **EDR telemetry** and **cloud/M365 audit logs** supplement host artifacts

**Documentation discipline throughout:** photograph the scene/screen, record system time vs. real time (clock skew), note whether the system was on/off, log every tool and command with timestamps and hashes. If it isn't documented, it didn't happen — and it won't survive court or a serious IR review.

---

## How these fit together in a real investigation

A typical flow: **acquire** (RAM first if live, then triage with KAPE or full image) → **parse registry** (Registry Explorer/RegRipper for execution, USB, persistence, user activity) → **analyze event logs** (Event Log Explorer/Chainsaw for logons, process creation, persistence, log clearing) → **build one master timeline** (Timeline Explorer, plaso/log2timeline) correlating registry LastWrite times, evtx timestamps, $MFT, and prefetch → **report** with chain of custody intact.

---

