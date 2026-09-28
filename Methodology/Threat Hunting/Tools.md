# Threat Hunting Tools

## What threat hunting is (and why the tools look the way they do)

Threat hunting is the proactive, human-led search for adversaries who have already evaded your automated defenses. Alert triage waits for a detection to fire. Hunting starts from the assumption that something is already inside and goes looking for it. Almost every tool in this space serves one of four jobs:

1. **Collect** telemetry from endpoints, networks, identity systems, and cloud.
2. **Store and query** that telemetry at scale.
3. **Enrich** findings with threat intelligence and context.
4. **Analyze, validate, and operationalize** results, turning successful hunts into automated detections.

Hunts generally come in three flavors. **Hypothesis-driven** hunts start from a question like "An attacker is using scheduled tasks for persistence." **Intel-driven** hunts start from a new report or IOC about a threat actor. **Analytics-driven** hunts start from anomalies, outliers, or ML baselines. The PEAK framework (Prepare, Execute, Act with Knowledge), published by Splunk's SURGe team in 2023, formalizes these three types. Older models you'll still see referenced include the Sqrrl Hunting Maturity Model (HMM0–HMM4) and the TaHiTI methodology from the Dutch financial sector.

---

## 1. SIEM and security data platforms

These are the central places where hunters write queries across huge volumes of logs.

| Platform | Query language | Notes |
|---|---|---|
| **Splunk Enterprise Security** (now part of Cisco) | SPL | The long-time hunting standard, with a massive community and app ecosystem. Can get expensive at volume. |
| **Microsoft Sentinel** | KQL | Cloud-native on Azure. Tight integration with Defender XDR, and the same KQL works across both. Many free community hunting queries on GitHub. |
| **Elastic Security** | KQL (Kibana), EQL, ES\|QL, Lucene | EQL is excellent for sequence hunting ("process A followed by network connection B within 5 minutes"). A self-hosted free tier makes it popular for labs. |
| **Google Security Operations** (formerly Chronicle) | UDM search, YARA-L | Fixed-price, long-retention model that suits hunting over months or years of data. |
| **CrowdStrike Falcon Next-Gen SIEM / LogScale** (formerly Humio) | LogScale Query Language | Very fast index-free search. |
| **Palo Alto Cortex XSIAM** | XQL | Palo Alto's SIEM/SOC platform. It absorbed the QRadar SaaS customer base after the 2024 IBM deal. |
| **Others** | Various | Sumo Logic, Exabeam (merged with LogRhythm), Securonix, Rapid7 InsightIDR, Panther (detection-as-code, Python), Datadog Cloud SIEM. |

**Security data lakes** are a growing trend, driven by SIEM cost. Teams send raw logs to Snowflake, Databricks, Amazon Security Lake (which uses the OCSF schema), or Azure Data Explorer and hunt there with SQL or KQL. Pipeline tools like Cribl route and reduce data before it lands anywhere.

---

## 2. EDR / XDR platforms (endpoint hunting)

Endpoint telemetry is where most hunts pay off: process trees, command lines, file writes, registry changes, network connections, and module loads.

- **Microsoft Defender for Endpoint / Defender XDR** has an "Advanced Hunting" feature using KQL, with tables like `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceRegistryEvents`, `IdentityLogonEvents`, and `EmailEvents`. It is arguably the most hunter-friendly schema available.
- **CrowdStrike Falcon** offers Event Search / Advanced Event Search. Falcon OverWatch is its managed hunting service, and Falcon Adversary Intelligence is built in.
- **SentinelOne Singularity** offers Deep Visibility and the PowerQuery language, with storyline-based process correlation.
- **Palo Alto Cortex XDR** uses XQL and has strong network and endpoint correlation.
- **Others** include VMware/Broadcom Carbon Black, Trellix, Sophos XDR (which exposes osquery-style SQL for live hunting), Cybereason, Elastic Defend, and Huntress (SMB-focused, with a human-led hunting service).

The AI assistant layer across these platforms is now widespread: Microsoft Security Copilot, CrowdStrike Charlotte AI, SentinelOne Purple AI, and Gemini in Google SecOps. These translate natural language into queries and summarize findings. They speed up hunting, but you still need to verify the queries they write.

---

## 3. Open-source endpoint visibility and hunting

- **Sysmon (System Monitor)** is Microsoft's free Sysinternals driver that logs rich Windows telemetry. Key event IDs:
  - 1 = process creation with command line and hashes
  - 3 = network connection
  - 7 = image/DLL load
  - 8 = CreateRemoteThread
  - 10 = process access (catches LSASS access)
  - 11 = file create
  - 12/13 = registry
  - 22 = DNS query
  - 25 = process tampering

  Popular configs are SwiftOnSecurity's sysmon-config and Olaf Hartong's sysmon-modular. Sysmon for Linux also exists.
- **osquery** exposes the operating system as a SQL database (`SELECT * FROM processes WHERE on_disk = 0;` finds processes running from deleted binaries). Fleet and Kolide manage it at scale.
- **Velociraptor** is arguably the most powerful free hunting and DFIR tool. It uses VQL to query thousands of endpoints simultaneously for artifacts: prefetch, amcache, shimcache, scheduled tasks, WMI subscriptions, and memory. It has a large artifact exchange and is now maintained under Rapid7.
- **Wazuh** is an open-source XDR/SIEM (an OSSEC fork) with file integrity monitoring, rules, and a dashboard.
- **GRR Rapid Response** is Google's remote live-forensics framework. It is less active today than Velociraptor.

### Windows event log hunting tools
These are great when you have raw EVTX files but no SIEM:
- **Hayabusa** by Yamato Security is a fast, Sigma-based timeline generator for EVTX.
- **Chainsaw** by WithSecure hunts through EVTX with Sigma rules and built-in detections.
- **DeepBlueCLI** by Eric Conrad (SANS) is a PowerShell-based EVTX hunter.
- **APT-Hunter** and **Zircolite** are both Sigma-over-EVTX tools, Zircolite using SQLite.

### Key Windows event IDs worth knowing
- **Logons:** 4624 (successful logon) and 4625 (failed logon). Logon type 3 is network and type 10 is RDP.
- **Process creation:** 4688, which needs command-line auditing enabled to be useful.
- **Persistence:** 4698 (scheduled task created) and 7045 (service installed).
- **Kerberos:** 4769 (service ticket request, used to hunt Kerberoasting when the encryption type is 0x17/RC4) and 4768 (TGT request).
- **Log tampering:** 1102 (security log cleared).
- **PowerShell:** 4104 (script block logging), which is essential.

---

## 4. Network hunting tools

- **Zeek** (formerly Bro) turns packets into rich, structured logs such as `conn.log`, `dns.log`, `http.log`, `ssl.log`, `x509.log`, and `files.log`. It is the gold standard for network hunting. Corelight is its commercial version.
- **Suricata** and **Snort** are signature-based IDS/IPS engines. Suricata also produces EVE JSON metadata that is useful for hunting.
- **Arkime** (formerly Moloch) provides full packet capture with indexed search.
- **Security Onion** is a free Linux distro bundling Zeek, Suricata, Elastic, Arkime-style PCAP, and case management. It is the best "hunting lab in a box."
- **RITA** (Real Intelligence Threat Analytics) by Active Countermeasures analyzes Zeek logs for C2 beaconing, long connections, and DNS tunneling. AC-Hunter is the commercial version.
- **Wireshark, tcpdump, TShark, NetworkMiner, Brim/Zui** are packet-level analysis tools.
- **JA3/JA3S and JA4+ fingerprints** identify TLS clients and servers regardless of IP or domain, which makes them good for finding malware families and C2 frameworks. JA4+ from FoxIO is the modern successor.
- **NDR vendors** include Vectra AI, Darktrace, ExtraHop Reveal(x), and Corelight.

Classic network hunts include beaconing detection (regular intervals, consistent byte sizes), long-duration connections, DNS with high-entropy or long subdomains, rare user agents, self-signed or newly issued certificates, and internal hosts talking to newly registered domains.

---

## 5. Detection-as-code and rule formats

- **Sigma** is the generic, vendor-neutral rule format for log-based detections, often called "YARA for logs." One rule can be converted via **pySigma / sigma-cli** into SPL, KQL, EQL, and others. The SigmaHQ repository has thousands of community rules. It is essential for sharing hunts.
- **YARA** is a pattern-matching language for files and memory, used to hunt malware across disks and samples. YARA-X is the newer Rust rewrite from VirusTotal.
- **Suricata/Snort rules** cover network signatures.
- **KQL / SPL query libraries** include the Azure Sentinel GitHub repository, Splunk Security Content (ESCU), Elastic's detection-rules repository, and Bert-Jan Pals' KQL hunting queries.
- **THOR / LOKI** from Nextron Systems are IOC and YARA scanners for compromise assessment. LOKI is free, THOR is commercial.

---

## 6. Threat intelligence and enrichment

**Platforms**
- MISP (open source, sharing-focused)
- OpenCTI (open source, STIX 2.1-native knowledge graph)
- ThreatConnect, Anomali, EclecticIQ, ThreatQuotient

**Commercial intel**
- Recorded Future
- Google Threat Intelligence (Mandiant + VirusTotal)
- CrowdStrike, Intel 471, Flashpoint

**Free and community sources**
- VirusTotal
- AlienVault OTX
- abuse.ch projects: URLhaus, MalwareBazaar, ThreatFox, Feodo Tracker, SSLBL
- GreyNoise (tells you whether an IP is just internet background noise)
- Shodan, Censys, and FOFA (for hunting attacker infrastructure outward)
- urlscan.io, Hybrid Analysis, ANY.RUN, Joe Sandbox

**Utilities**
- CyberChef for decoding and deobfuscation
- DomainTools and WHOIS/passive DNS services for infrastructure pivoting

Keep David Bianco's **Pyramid of Pain** in mind here. Hashes and IPs are trivial for attackers to change. Hunting at the TTP level (behaviors) is what actually costs them.

---

## 7. Identity and Active Directory hunting

Identity is now the primary battleground, since most modern intrusions involve credential abuse.

- **BloodHound** (Community Edition / Enterprise from SpecterOps) maps AD and Entra ID attack paths. Defenders use it to find the same paths attackers would. SharpHound and AzureHound are its collectors.
- **PingCastle** and **Purple Knight** are AD security assessment tools.
- **ROADtools** is for Entra ID (Azure AD) reconnaissance and analysis.
- **Microsoft Defender for Identity** and **Entra ID Protection** cover sign-in logs and risky users.

Hunts to run: Kerberoasting, AS-REP roasting, DCSync (replication requests from non-DCs), golden/silver ticket anomalies, impossible travel, MFA fatigue patterns, OAuth consent grants to suspicious apps, and new federation trusts.

---

## 8. Cloud and SaaS hunting

**Log sources**
- AWS CloudTrail, VPC Flow Logs, and GuardDuty
- Azure Activity and Entra sign-in and audit logs
- GCP Cloud Audit Logs
- The Microsoft 365 Unified Audit Log
- Okta System Log
- Google Workspace audit logs

**Tools**
- **Microsoft-Extractor-Suite** by Invictus IR and **CISA's Untitled Goose Tool** collect M365 and Entra evidence.
- **Prowler**, **ScoutSuite**, and **Steampipe** (SQL over cloud APIs) cover posture and hunting.
- **CloudQuery** and **Cloud Custodian** handle inventory and policy.
- **CNAPP vendors** such as Wiz, Orca, Lacework, and Sysdig include runtime threat detection. **Falco** is the open-source runtime threat detection tool for containers and Kubernetes.

Hunts to run: new access keys created for long-lived IAM users, `ConsoleLogin` without MFA, disabled CloudTrail, unusual `AssumeRole` chains, mass S3 `GetObject` activity, inbox forwarding rules in M365, and new service principal credentials.

---

## 9. Forensics and triage (for when a hunt finds something)

- **KAPE** by Kroll does fast targeted artifact collection and processing.
- **Eric Zimmerman's tools** include PECmd (prefetch), MFTECmd, RECmd (registry), EvtxECmd, AmcacheParser, and Timeline Explorer.
- **Volatility 3** and **MemProcFS** are for memory analysis, useful for finding injected code, hidden processes, and fileless malware.
- **Plaso (log2timeline)** and **Timesketch** build super-timelines and support collaborative timeline analysis.
- **Autopsy / The Sleuth Kit** handle disk forensics.
- **UAC (Unix-like Artifacts Collector)** covers Linux and macOS triage. **DFIR-ORC** is ANSSI's Windows collector.

---

## 10. Analysis, notebooks, and data science

- **Jupyter notebooks** with **MSTICPy** (Microsoft's open-source hunting library) support querying Sentinel, Defender, Splunk, and others, plus enrichment, visualization, and anomaly detection.
- **Pandas, Polars, and DuckDB** handle ad-hoc analysis of exported logs. DuckDB is excellent for querying large CSV or Parquet files locally.
- **Graph tools** like Neo4j (under BloodHound) and Maltego support link analysis.
- **Practice datasets** include the OTRF Security Datasets (formerly Mordor), Splunk's Boss of the SOC (BOTS v1–v3), EVTX-ATTACK-SAMPLES, and the Threat Hunter Playbook.

---

## 11. Adversary emulation (for validating hunts)

You can't be confident a hunt works until you've seen it catch the behavior.

- **Atomic Red Team** from Red Canary is a library of small, ATT&CK-mapped tests. Run them with Invoke-AtomicRedTeam.
- **MITRE Caldera** is an automated adversary emulation platform.
- **Stratus Red Team** from Datadog provides cloud-focused attack emulation.
- **Commercial breach and attack simulation** vendors include AttackIQ, SafeBreach, Picus, and Cymulate.

---

## 12. Deception

- **Thinkst Canary** provides hardware and virtual honeypots.
- **Canarytokens** are free tripwires: fake AWS keys, documents, and DNS tokens that alert when touched.
- **Honey accounts** in AD, such as a fake admin with a Service Principal Name (SPN), catch Kerberoasting with near-zero false positives.

Deception flips hunting around. Instead of searching for attackers, you make them reveal themselves.

---

## 13. Case management and automation

- **TheHive + Cortex** (StrangeBee) is an open-source case management and analyzer platform.
- **SOAR tools** include Shuffle (open source), Tines, Splunk SOAR, Microsoft Sentinel playbooks (Logic Apps), and Torq.
- **Jira and Confluence** are commonly used simply to document hunt hypotheses, queries, and outcomes.

---

## 14. Frameworks and reference knowledge

- **MITRE ATT&CK** is the shared language for adversary TTPs. Most hunts map to a technique ID, such as T1053.005 for scheduled tasks.
- **ATT&CK Navigator** and **DeTT&CT** visualize your data-source and detection coverage.
- **MITRE D3FEND** is the defensive countermeasure knowledge graph.
- **LOLBAS, GTFOBins, LOLDrivers, and LOLRMM** catalog legitimate binaries, drivers, and remote-access tools that attackers abuse. They are goldmines for hypotheses.
- **The DFIR Report** publishes detailed real intrusion write-ups with timelines. It is excellent hunting inspiration.

---

## 15. Core hunting techniques

These are independent of any tool.

- **Searching:** looking for a specific known bad pattern.
- **Stacking (frequency analysis):** count occurrences of something across all hosts, such as every scheduled task name or every service binary path, and look at the rare ones. "Long-tail analysis" is the single most productive hunting technique.
- **Grouping and clustering:** find sets of events that co-occur, like the same process, parent, and user combination across hosts.
- **Baselining:** know what normal admin activity, normal outbound destinations, and normal logon hours look like, so deviations stand out.
- **Visualization:** timelines, process trees, and connection graphs.
- **Sequence hunting:** look for chains of events, for example Office spawning a script host that makes a network connection.

### Example queries

**KQL (Defender XDR):** Office apps spawning script interpreters, a classic phishing-execution hunt.
```kql
DeviceProcessEvents
| where Timestamp > ago(7d)
| where InitiatingProcessFileName in~ ("winword.exe","excel.exe","powerpnt.exe","outlook.exe")
| where FileName in~ ("powershell.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe")
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, FileName, ProcessCommandLine
```

**SPL (Splunk + Sysmon):** stacking rare parent/child process pairs.
```spl
index=sysmon EventCode=1
| stats count dc(host) as hosts by ParentImage, Image
| where count < 5
| sort count
```

**KQL:** potential Kerberoasting, where RC4 service tickets are requested for many SPNs by one account.
```kql
SecurityEvent
| where EventID == 4769 and TicketEncryptionType == "0x17"
| summarize SPNs = dcount(ServiceName) by TargetUserName, IpAddress, bin(TimeGenerated, 1h)
| where SPNs > 10
```

### High-value hunt ideas
- Persistence: Run keys, scheduled tasks, services, WMI event subscriptions, startup folders, and new local admins.
- LSASS access by unusual processes.
- LOLBins with network activity, such as certutil, bitsadmin, mshta, and regsvr32.
- Encoded PowerShell.
- RMM tools that aren't part of your approved stack, such as AnyDesk, ScreenConnect, or Atera. This is a very common ransomware precursor.
- Lateral movement via PsExec, WMI, WinRM, or RDP from workstations.
- Beaconing and rare external domains.
- Shadow copy deletion, which is a ransomware tell.
- Cloud privilege escalation.

---

## 16. Building a stack at different budgets

- **Free / lab:** Sysmon + Velociraptor + Security Onion (Zeek, Suricata, Elastic) + Sigma + Hayabusa/Chainsaw + MISP or OpenCTI + Atomic Red Team + Jupyter/MSTICPy. This is entirely capable of real hunting.
- **Mid-market:** Microsoft Defender XDR + Sentinel is a common and cost-effective choice if you're already on M365 E5. Add Velociraptor for deep forensics and Canarytokens for cheap deception.
- **Enterprise:** A major EDR (CrowdStrike, SentinelOne, or Defender), a SIEM or data lake (Splunk, Sentinel, Google SecOps, or XSIAM), NDR (Corelight or Vectra), commercial intel, BAS for validation, and a dedicated hunt team using PEAK or a similar methodology.

---

## 17. Common pitfalls

- **Hunting without the right data.** Command-line logging, PowerShell script block logging, and DNS logs are often missing. Map your data sources to ATT&CK before hunting.
- **Short retention.** Dwell times can be weeks to months, so 30 days of logs limits you badly.
- **Chasing IOCs instead of behaviors.** This is the Pyramid of Pain problem.
- **Not documenting.** A hunt that finds nothing still has value: it proves coverage and can become a detection. Record the hypothesis, the query, the data used, and the outcome.
- **Not operationalizing.** The end goal of a good hunt is usually an automated detection, so humans can move on to the next question.
- **Over-trusting AI-generated queries.** Validate the logic and field names against your actual schema.

---

## 18. Learning paths and certifications

- **SANS courses:** FOR508 (Advanced IR & Threat Hunting, GCFA), FOR572 (Network Forensics, GNFA), FOR578 (Cyber Threat Intelligence, GCTI), and SEC555 / SEC511 for SIEM and continuous monitoring.
- **Other certifications:** eLearnSecurity/INE eCTHP, Certified Threat Hunting Professional options, and vendor certs such as Microsoft SC-200 and Splunk certifications.
- **Hands-on practice:** Splunk BOTS, CyberDefenders, Blue Team Labs Online, TryHackMe (SOC and hunting paths), LetsDefend, and HackTheBox Sherlocks.
- **Reading:** *The Threat Hunter Playbook* (OTRF), *Practical Threat Intelligence and Data-Driven Threat Hunting* by Valentina Costa-Gazcón, *Intelligence-Driven Incident Response* by Roberts and Brown, the PEAK framework papers, and The DFIR Report.

---

The vendor landscape here shifts constantly through acquisitions, renames, and new AI features, so it's worth double-checking product specifics before a purchasing decision.

