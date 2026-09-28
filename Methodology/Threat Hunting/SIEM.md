# Threat Hunting with SIEM

# Threat Hunting with a SIEM

## What threat hunting actually is

Threat hunting is the proactive, human-led search for adversary activity that your existing detections missed. It starts from the **assume breach** mindset: instead of waiting for an alert, you form a theory about how an attacker could be operating in your environment and go looking for evidence.

It helps to separate three related activities:

- **Detection engineering** is automated, rule-based, and runs continuously.
- **Incident response** is reactive and starts from a known event.
- **Hunting** sits between them. It is exploratory, starts from a question rather than an alert, and its most valuable output is often a new detection rule that turns a one-off hunt into permanent coverage.

The SIEM is the natural hunting ground because it centralizes and normalizes telemetry from many sources and lets you query across time and systems. You can correlate an Entra ID sign-in with an endpoint process launch and a firewall connection in a single query.

## Foundational models

**The Pyramid of Pain** (David Bianco) ranks indicators by how much it hurts an attacker when you detect them. From bottom to top: hash values, IP addresses, domain names, network/host artifacts, tools, and TTPs (tactics, techniques, and procedures). Hashes and IPs are trivial for an attacker to change. Behaviours are expensive to change. Mature hunting aims at the top of the pyramid.

**The Hunting Maturity Model** (Sqrrl) describes five levels:

| Level | Name | What it looks like |
|---|---|---|
| HMM0 | Initial | Relies entirely on automated alerting |
| HMM1 | Minimal | Searches for threat-intel IOCs |
| HMM2 | Procedural | Follows hunting procedures written by others |
| HMM3 | Innovative | Creates its own procedures and hypotheses |
| HMM4 | Leading | Automates successful hunts into detections at scale |

**MITRE ATT&CK** is the common language for hunting. Hypotheses, data-source requirements, coverage maps, and findings are almost always expressed in ATT&CK technique IDs (for example, T1003.001 for LSASS memory dumping).

## Hunting methodologies

**Hypothesis-driven hunting** is the core approach. A good hypothesis is specific and testable, for example: "An adversary with a foothold is using Kerberoasting to obtain service account credentials." Hypotheses come from three places: threat intelligence (what groups targeting your sector are doing), situational awareness (your crown jewels, recent changes, known weak spots), and domain expertise (how you know attacks work).

**IOC-driven hunting** sweeps historical data for known-bad indicators from intel feeds or reports. It is fast and useful after a new advisory is published, but low on the Pyramid of Pain.

**TTP/analytics-driven hunting** looks for behaviour patterns regardless of specific indicators, such as any process reading LSASS memory, whatever the tool.

**Baseline/anomaly hunting** establishes what normal looks like and hunts for deviations. This is where stacking and statistics shine.

**Formal frameworks** give these approaches structure:

- **Sqrrl Hunting Loop:** create hypothesis → investigate with tools → uncover new patterns and TTPs → inform and enrich analytics.
- **PEAK (Splunk):** Prepare, Execute, Act with Knowledge. It covers hypothesis-driven, baseline, and model-assisted hunts.
- **TaHiTI:** a Dutch financial-sector methodology that emphasizes threat intel integration.

## Data: the thing that makes or breaks hunting

You can only hunt in data you collect. Most failed hunting programs fail here, not on analyst skill.

### Windows endpoint telemetry

This is the richest source for most hunts. Sysmon or EDR telemetry dramatically outperforms native logging alone.

| Source | Event ID | Why it matters |
|---|---|---|
| Security | 4624 / 4625 | Successful / failed logon. Logon type matters: 3 = network, 10 = RDP |
| Security | 4648 | Logon with explicit credentials (runas, lateral movement) |
| Security | 4672 | Special privileges assigned |
| Security | 4688 | Process creation (enable command-line auditing!) |
| Security | 4697 / System 7045 | Service installed (persistence, PsExec) |
| Security | 4698 | Scheduled task created |
| Security | 4720 / 4732 / 4728 | Account created / added to groups |
| Security | 4768 / 4769 / 4771 | Kerberos TGT, service tickets, pre-auth failures |
| Security | 1102 | Audit log cleared |
| Sysmon | 1 | Process create with hashes and parent |
| Sysmon | 3 | Network connection by process |
| Sysmon | 7 | Image (DLL) loaded |
| Sysmon | 8 | CreateRemoteThread (injection) |
| Sysmon | 10 | Process access (credential dumping) |
| Sysmon | 11 | File created |
| Sysmon | 12/13/14 | Registry events (Run keys, persistence) |
| Sysmon | 22 | DNS query by process |
| PowerShell | 4103 / 4104 | Module and script block logging (de-obfuscated content) |

### Other key sources

- **Network:** DNS logs, web proxy, firewall, NetFlow, Zeek (conn, dns, http, ssl, x509), and IDS alerts.
- **Identity:** Active Directory, Entra ID sign-in and audit logs, Okta, VPN.
- **Cloud:** AWS CloudTrail, Azure Activity, GCP audit logs, and the Microsoft 365 Unified Audit Log.
- **Other:** email gateway logs and application or database logs for the crown jewels.

### Data quality concerns

**Normalization** lets one query work across vendors. The main schemas are Splunk CIM, Elastic ECS, Sentinel ASIM, and OCSF.

**Time synchronization** is essential. Without NTP everywhere, timeline reconstruction lies to you.

**Retention** needs to exceed typical dwell time, which is often weeks to months. A cheap tier for older data, such as Sentinel Basic/Auxiliary logs or frozen Splunk buckets, is common.

**Coverage mapping** tells you where your blind spots are. Tools like DeTT&CT or the ATT&CK Navigator map which techniques your data can actually see.

## Core analytic techniques

**Searching** is the simplest technique: look for a specific artifact. It is precise, but you have to know what to look for.

**Stacking (least frequency of occurrence)** counts occurrences of a value across the environment and examines the rare tail. Malware usually runs on few machines, while legitimate software runs on many. You can stack parent-child process pairs, service names, scheduled tasks, autoruns, user agents, and DLL load paths.

**Grouping and clustering** finds entities that share unusual combinations of attributes, such as the same rare binary plus the same outbound destination.

**Time-series and beaconing analysis** looks for C2 implants. They call home at regular intervals, so low jitter in connection timing between a host and a destination is a strong signal.

**Statistical outlier detection** flags anything well above an entity's own baseline or its peer group, using z-scores, IQR, or percentiles. Examples include data volume, logon counts, and failed authentications.

**Entropy and string analysis** catches machine-generated artifacts. High-entropy domain names suggest DGAs. Long, random-looking subdomains suggest DNS tunneling.

**UEBA** is built into many SIEMs. It automates peer-group and baseline comparisons and is useful as a lead generator, but its output is not a verdict.

## Worked hunts with queries

These examples use Splunk SPL and Microsoft KQL, the two most common hunting languages. Field names vary with your parsing, so treat them as templates.

### Encoded PowerShell (T1059.001)

```kql
DeviceProcessEvents
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine matches regex @"(?i)\s-(e|en|enc|enco|encod|encodedcommand)\s"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```

The initiating process is the gold. PowerShell spawned by `winword.exe` or `excel.exe` is a classic phishing chain. Decode the base64 and pair this hunt with 4104 script block logs.

### Rare parent-child process pairs (stacking)

```spl
index=sysmon EventCode=1
| stats count dc(host) AS hosts values(host) AS host_list BY ParentImage Image
| where hosts <= 2
| sort count
```

Pay attention to Office apps, browsers, or `w3wp.exe` (IIS) spawning shells or LOLBins such as `certutil`, `mshta`, `regsvr32`, `rundll32`, and `bitsadmin`.

### LSASS credential access (T1003.001)

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
| search GrantedAccess IN ("0x1010","0x1410","0x1438","0x143a","0x1fffff")
| stats count values(GrantedAccess) BY SourceImage host
| sort count
```

Expect noise from AV, EDR, and backup agents. Build an allowlist, then everything left is interesting, especially `rundll32.exe` loading `comsvcs.dll` or any unsigned binary.

### Kerberoasting (T1558.003)

```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17 Service_Name!="*$"
| stats dc(Service_Name) AS spn_count values(Service_Name) BY Account_Name Client_Address
| where spn_count > 5
```

Here 0x17 is RC4 encryption. One account requesting RC4 tickets for many SPNs in a short window is a strong signal. For AS-REP roasting, look at 4768 with pre-auth type 0.

### C2 beaconing (T1071)

```kql
CommonSecurityLog
| where TimeGenerated > ago(1d)
| project TimeGenerated, SourceIP, DestinationIP, DestinationPort
| sort by SourceIP asc, DestinationIP asc, TimeGenerated asc
| extend delta = iff(SourceIP == prev(SourceIP) and DestinationIP == prev(DestinationIP),
                     datetime_diff('second', TimeGenerated, prev(TimeGenerated)), long(null))
| where isnotnull(delta)
| summarize conns = count(), avgDelta = avg(delta), sdDelta = stdev(delta)
    by SourceIP, DestinationIP, DestinationPort
| where conns > 50
| extend jitterRatio = sdDelta / avgDelta
| where jitterRatio < 0.2
| order by jitterRatio asc
```

Legitimate software beacons too: update checkers, telemetry, NTP. Filter out known destinations and enrich the rest with domain age and reputation. RITA is a good dedicated tool for Zeek data.

### DNS tunneling and DGA (T1071.004, T1568.002)

```spl
index=dns
| eval qlen=len(query)
| rex field=query "(?<domain>[^.]+\.[^.]+)$"
| stats count dc(query) AS unique_subdomains avg(qlen) AS avg_len BY src domain
| where unique_subdomains > 100 AND avg_len > 40
```

Also hunt for high volumes of TXT or NULL record queries and NXDOMAIN spikes from a single host, which indicate DGA malware cycling through domains.

### MFA fatigue and identity attacks (T1621)

```kql
SigninLogs
| where ResultType == "500121"
| summarize failures = count(), apps = make_set(AppDisplayName)
    by UserPrincipalName, bin(TimeGenerated, 1h)
| where failures > 5
```

Follow up by checking whether a successful sign-in from a new country, ASN, or device followed the failures. Related identity hunts include impossible travel, new MFA method registration, inbox rule creation (the `New-InboxRule` operation in the UAL), and OAuth consent grants.

### Other high-value hunts to build

- **Lateral movement:** workstation-to-workstation 4624 type 3 or 10 logons, 7045 services with random names (PsExec-style), WMI process creation via `wmiprvse.exe`, and admin share (`ADMIN$`, `C$`) access.
- **Persistence:** stack Run keys, services, scheduled tasks, WMI event subscriptions (Sysmon 19–21), and new local admins.
- **Defense evasion:** 1102 or 104 log clears, Sysmon or EDR service stops, and hosts that suddenly go silent. Missing data is itself a signal.
- **Cloud:** CloudTrail `ConsoleLogin` without MFA, `CreateAccessKey` for other users, `StopLogging`, unusual regions, and `GetSecretValue` spikes.
- **Exfiltration:** outbound byte-count outliers per host against its own 30-day baseline, and uploads to personal cloud storage.

## Sigma: vendor-agnostic hunting logic

Sigma is to logs what YARA is to files. It is a YAML format for detection logic that converts into SPL, KQL, EQL, and other SIEM query languages using `sigma-cli` (pySigma). The public SigmaHQ repository has thousands of community rules and is an excellent source of hunt ideas.

```yaml
title: Encoded PowerShell Command Line
status: experimental
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains:
      - ' -enc '
      - ' -EncodedCommand '
  condition: selection
level: medium
tags:
  - attack.execution
  - attack.t1059.001
```

## The hunt lifecycle in practice

**1. Prepare.** Pick a topic by weighing threat relevance against your data availability. Write the hypothesis, map it to ATT&CK, identify the data sources, and confirm they are actually being ingested and parsed correctly. Scope the time range and assets.

**2. Execute.** Start broad, then pivot. Every finding raises a new question: what else did this host do, what else did this user touch, where else does this hash appear? Use SIEM bookmarks (Sentinel) or notable events and notes (Splunk) to capture evidence as you go.

**3. Act.** Every hunt should produce something, even when you find nothing malicious:

- **Escalations to incident response** for confirmed malicious activity.
- **New or tuned detection rules**, which is the most important output.
- **Visibility gaps** discovered, which feed a data onboarding backlog.
- **Hardening recommendations**, such as disabling RC4 or restricting PowerShell.
- **Documented baselines** of normal behaviour for future hunts.

**4. Document.** Use a standard template covering hypothesis, ATT&CK mapping, data sources, queries, findings, false positives encountered, and outputs. A shared hunt library prevents repeated work and lets junior analysts re-run proven hunts, which is how you move from HMM2 to HMM3.

## Measuring a hunting program

Measuring "threats found" alone is a trap. A good program in a well-defended environment often finds nothing malicious, and that is a legitimate result. Better metrics include:

- hunts completed per period
- detections created or improved
- ATT&CK techniques newly covered
- visibility gaps identified and closed
- mean time to detect and dwell time trends
- the percentage of incidents first discovered by hunting versus alerts versus third parties

## Tooling landscape

**Splunk** uses SPL. Enterprise Security adds risk-based alerting, and the Splunk Security Content (ESCU) library ships ready-made analytic stories. Its `tstats` command against accelerated data models is the key to fast hunting at scale.

**Microsoft Sentinel and Defender XDR** use KQL. They provide built-in hunting queries, bookmarks, livestream, Jupyter notebooks with the msticpy library, and UEBA. Advanced Hunting in Defender gives you 30 days of raw endpoint telemetry.

**Elastic Security** supports KQL/Lucene, EQL, and ES|QL. EQL's `sequence` syntax is excellent for ordered behaviour chains like "process A, then network connection, then file write."

**Google SecOps (Chronicle)** uses the UDM schema and YARA-L rules. It is known for long, cheap retention.

**Other platforms** include QRadar (AQL), Sumo Logic, Exabeam, LogRhythm, and open-source stacks like Wazuh, Security Onion, and HELK.

**Complementary tools:**

- **Velociraptor** for endpoint-level hunting when SIEM data isn't enough.
- **Zeek** for network metadata and **RITA** for beaconing analysis.
- **MISP and OpenCTI** for threat intelligence, delivered via STIX/TAXII.
- **Atomic Red Team and MITRE CALDERA** to simulate techniques and verify your hunts actually catch them. This is purple teaming.

## Common pitfalls

- **Assuming absence of evidence is evidence of absence.** Always confirm the data you need is present before concluding "nothing found."
- **Drowning in noise** because there is no baseline. Invest in allowlists and known-good inventories.
- **Hunting only IOCs.** Attackers rotate them within hours.
- **Not operationalizing.** A brilliant hunt that never becomes a detection has to be repeated manually forever.
- **Confirmation bias.** Analysts can fall in love with a hypothesis and interpret ambiguous data as proof. Actively look for the benign explanation.
- **Cost-driven data cuts.** Teams drop high-volume logs like DNS, proxy, or process creation to save money, and these are exactly what hunters need most.
- **Living-off-the-land attacks.** These abuse legitimate admin tools, so context (who, from where, when, how unusual) matters more than the tool itself.

## Building skills

**Practice datasets:** Splunk's Boss of the SOC (BOTS) datasets, the OTRF Security Datasets project (formerly Mordor), and the Threat Hunter Playbook by Roberto Rodriguez.

**Test environments:** Splunk Attack Range and DetectionLab-style home labs let you generate your own attack telemetry.

**Training:** SANS courses such as FOR508 (endpoint forensics and hunting), FOR572 (network forensics), and SEC555 (SIEM with tactical analytics) are the industry's standard formal routes.

**Staying current:** follow The DFIR Report, which publishes detailed real-intrusion timelines with hunt queries, as well as vendor threat intel blogs and the MITRE ATT&CK updates. Each new intrusion report is a ready-made source of hypotheses.

