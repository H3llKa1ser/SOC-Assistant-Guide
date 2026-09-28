# Threat Hunting with Cyber Threat Intelligence (CTI)

## The core idea

**Threat hunting** is the proactive, human-led search for adversary activity that has gotten past your automated defenses. It starts from the assumption of compromise: something is already inside and your alerts haven't caught it. **Cyber threat intelligence** is analyzed knowledge about adversaries: who they are, what they want, how they operate, and what traces they leave.

The two fit together naturally. Hunting without intelligence tends to become aimless poking through logs. Intelligence without hunting stays as reports nobody acts on. CTI tells hunters *where to look and what to look for*. Hunting tells CTI teams *what is actually happening in this environment*, which feeds back into better intelligence. The goal is not just to find badness today but to turn every hunt into lasting improvements: new detections, closed visibility gaps, and sharper intelligence requirements.

A useful distinction is that searching your logs for a list of known-bad IPs and hashes is **IOC sweeping**, not hunting. It's worth doing, but it's retrospective matching. Real hunting looks for *behaviors*, which is where intelligence about adversary techniques becomes essential.

## Levels of intelligence and how hunters use each

CTI is usually split into four levels, and each feeds hunting differently.

**Strategic intelligence** covers long-term trends, geopolitics, and which actor types target your sector. It helps leadership decide what to prioritize, so it shapes which threats the hunt program focuses on at all.

**Operational intelligence** covers specific campaigns and actors: their motivations, timing, and targeting. It tells hunters which adversaries are most relevant right now, perhaps because a group has started going after your industry or region.

**Tactical intelligence** is about TTPs (tactics, techniques, and procedures), meaning how adversaries actually operate. This is the most valuable level for hunting because behaviors are hard for attackers to change and generalize across campaigns.

**Technical intelligence** is atomic indicators such as hashes, IPs, domains, URLs, and certificate fingerprints. They're useful for quick sweeps and scoping, but they're brittle and expire fast.

## The Pyramid of Pain

David Bianco's Pyramid of Pain is the key mental model for why TTP-based hunting matters. It ranks indicators by how much pain it causes an adversary when you detect and deny them. From bottom to top the levels are hash values, IP addresses, domain names, network and host artifacts, tools, and TTPs. Changing a hash takes an attacker seconds, and changing an IP takes minutes. Changing their tooling or fundamental techniques takes real effort and money. So the higher up the pyramid your hunt hypotheses sit, the more durable and valuable the resulting detections are. A mature CTI-driven program deliberately pushes its work toward the top.

## The intelligence lifecycle meets the hunting loop

The classic **intelligence lifecycle** runs through six stages: direction (defining requirements), collection, processing, analysis, dissemination, and feedback. The crucial step for hunting is direction. Good programs define **Priority Intelligence Requirements (PIRs)**, which are specific questions the organization needs answered. Examples include "Which ransomware affiliates are targeting organizations like ours, and what initial access methods are they using this quarter?" or "Are any actors abusing the remote-management tools we use?" PIRs keep both CTI collection and hunting focused on what actually matters to the business.

On the hunting side, the well-known **Sqrrl hunting loop** has four stages: create a hypothesis, investigate using tools and techniques, uncover new patterns and TTPs, and inform and enrich analytics. CTI plugs in most heavily at hypothesis creation, and the outputs of the final stage flow back to the CTI team.

## Frameworks built for intelligence-driven hunting

**TaHiTI** (Targeted Hunting integrating Threat Intelligence) was developed by the Dutch financial sector specifically to formalize the link between CTI and hunting. It has three phases. First you *initiate*, where a trigger such as a new intel report, a PIR, or an incident becomes an abstract hunt idea stored in a backlog. Then you *hunt*: define and refine the hypothesis, enrich it with CTI, and investigate. Finally you *finalize*, which means documenting findings and handing off outputs, including new detection use cases, incident response escalations, and intelligence feedback. TaHiTI treats CTI as a first-class input at every stage.

**PEAK** (Prepare, Execute, Act with Knowledge) was published by Splunk's SURGe team. It defines three hunt types. *Hypothesis-driven hunts* test a specific suspicion, often derived from CTI. *Baseline hunts* profile "normal" in your environment so you can spot deviations. *Model-assisted hunts* (M-ATH) use machine learning or statistical models to surface anomalies. CTI mostly powers the first type, but it also tells you which baselines are worth building.

The **Hunting Maturity Model (HMM)** describes five levels from HMM0 to HMM4. At HMM0 an organization relies entirely on automated alerting. At HMM1 it does minimal hunting, mostly IOC searches from threat feeds. At HMM2 it follows procedures written by others. At HMM3 it creates its own new procedures. At HMM4 it systematically automates successful hunts into detections. Moving up the scale largely depends on how well CTI is consumed: HMM1 organizations consume indicators, while HMM3 and above consume TTPs and produce their own intelligence.

**F3EAD** (Find, Fix, Finish, Exploit, Analyze, Disseminate) comes from military targeting. It is sometimes used to describe the tight coupling of operations and intelligence, where every operation generates intelligence that drives the next.

## Analytical models for structuring CTI

**MITRE ATT&CK** is the common language of TTP-based hunting. It organizes adversary behavior into tactics (the "why," such as Persistence or Lateral Movement), techniques and sub-techniques (the "how," such as T1053.005 Scheduled Task), and procedures (specific implementations by specific groups). CTI reports mapped to ATT&CK can be converted almost directly into hunt hypotheses. ATT&CK also documents groups, software, data sources, and detection guidance for each technique. The ATT&CK Navigator lets you layer an actor's known techniques over your detection coverage, which shows where you're blind to the threats that matter most. Companion projects include **D3FEND** for defensive countermeasures and the Center for Threat-Informed Defense's work on mapping and prioritization.

The **Diamond Model** describes every intrusion event through four connected features: adversary, capability, infrastructure, and victim. It's powerful for *pivoting*. If you find one piece of infrastructure, you can pivot to other infrastructure sharing the same registrant, certificate, or hosting pattern, or to other victims hit with the same capability. Hunters use it to expand from a single finding to a full picture of a campaign.

The **Lockheed Martin Cyber Kill Chain** breaks an intrusion into seven stages from reconnaissance to actions on objectives. The **Unified Kill Chain** extends it to 18 phases that better cover post-compromise activity. These help hunters think about where in an attack sequence to look, and they suggest that finding one stage should prompt a search for the adjacent ones.

## Handling intelligence properly

Not all intelligence is equally trustworthy, and hunters should know how much weight to give a source. The **Admiralty Code** (NATO system) rates source reliability from A (completely reliable) to F (cannot be judged), and information credibility from 1 (confirmed) to 6 (cannot be judged). A report rated "B2" comes from a usually reliable source and is probably true.

The **Traffic Light Protocol (TLP 2.0)** governs sharing: TLP:RED (named recipients only), TLP:AMBER and AMBER+STRICT (organization only, with or without clients), TLP:GREEN (community), and TLP:CLEAR (public). Respecting TLP matters for staying in trusted sharing communities.

Analysts should also be aware of cognitive biases. Confirmation bias is the big one in hunting: once you believe an actor is present, you start seeing their fingerprints everywhere. **Analysis of Competing Hypotheses (ACH)**, from Richards Heuer's work at the CIA, is a structured method that forces you to evaluate evidence against multiple explanations rather than just your favorite one.

## Where CTI comes from

Sources include open-source reporting from vendor blogs (Mandiant, Microsoft, CrowdStrike, Palo Alto Unit 42, Cisco Talos, Kaspersky, ESET, Recorded Future, The DFIR Report), government advisories (CISA, NCSC, ENISA, national CERTs such as CERT-EU and MT-CERT), sector ISACs (FS-ISAC and others), commercial intel platforms, malware repositories and sandboxes (VirusTotal, MalwareBazaar, ANY.RUN, Hybrid Analysis), infrastructure datasets (passive DNS, certificate transparency logs, Shodan, Censys), dark web and underground forum monitoring, and, very importantly, **your own internal intelligence** from past incidents and hunts. Internal intelligence is often the most relevant of all because it reflects what actually targets you.

The DFIR Report deserves special mention for hunters. It publishes detailed intrusion timelines with the exact commands, tools, and timings attackers used, which translate directly into hunt queries.

## The tooling ecosystem

For managing intelligence, **Threat Intelligence Platforms (TIPs)** such as MISP (open source), OpenCTI (open source), ThreatConnect, Anomali, and others store, correlate, and share intel. **STIX 2.1** is the standard format for representing threat intelligence objects and their relationships, and **TAXII** is the protocol for exchanging it.

For turning intel into hunt logic, there are several shareable rule formats. **Sigma** is a generic, SIEM-agnostic format for log-based detection rules that converts into Splunk SPL, Microsoft KQL, Elastic, and many other query languages; the SigmaHQ repository holds thousands of community rules. **YARA** matches patterns in files and memory. **Suricata and Snort** rules cover network traffic.

For querying and investigating, hunters work in SIEMs (Splunk, Microsoft Sentinel, Elastic, Google SecOps/Chronicle), EDR/XDR consoles (Microsoft Defender, CrowdStrike, SentinelOne) using their hunting query languages, **Velociraptor** and **osquery** for querying endpoints at scale, and **Zeek** for rich network metadata. Jupyter notebooks with Python (pandas, MSTICPy) are popular for more analytical hunts.

For testing your hunts and detections, **Atomic Red Team**, MITRE **Caldera**, and purple teaming exercises let you emulate the exact techniques in a CTI report and confirm you can see them. This step is often skipped and is enormously valuable.

## Data sources that make hunting possible

Intelligence is useless if you lack the telemetry to test it. Key endpoint sources include EDR process, file, registry, and network events; **Sysmon** (Event ID 1 process creation, 3 network connection, 7 image load, 10 process access, 11 file create, 13 registry, 22 DNS query); and Windows Security logs (4624/4625 logons, 4688 process creation with command line, 4698 scheduled task creation, 4769 Kerberos service tickets, 7045 service installs). PowerShell Script Block Logging (Event ID 4104) is essential given how often attackers use PowerShell.

Network sources include DNS logs, web proxy logs, firewall logs, NetFlow, and TLS metadata such as JA3/JA3S and the newer JA4+ fingerprints. Identity and cloud sources are increasingly central: Entra ID sign-in and audit logs, Microsoft 365 Unified Audit Log, Okta logs, AWS CloudTrail, GCP and Azure activity logs, and SaaS audit logs.

A practical early exercise is mapping your available data sources against ATT&CK data components for the techniques your priority actors use. That shows where you can hunt and where you're blind.

## Core hunting techniques

Several analytical techniques recur constantly. **Searching** means querying for specific artifacts or behaviors. **Stacking** (frequency analysis) counts occurrences of a value across the environment and examines the rare ones in the "long tail." A binary running from an unusual path on only two of 5,000 hosts is interesting. **Clustering and grouping** find sets of events that share characteristics or happen together, such as reconnaissance commands executed in quick succession by the same user. **Baselining** establishes what's normal so deviations stand out.

For command-and-control, **beaconing detection** looks for connections at regular intervals, allowing for the jitter that attackers add to evade simple checks. Hunters also look at connection duration, bytes transferred, and rare destinations. For living-off-the-land activity, the **LOLBAS** project catalogs legitimate Windows binaries that attackers abuse (rundll32, regsvr32, mshta, certutil, and many more), and **GTFOBins** does the same for Linux. **LOLDrivers** catalogs vulnerable drivers used in "bring your own vulnerable driver" attacks, and **LOLRMM** covers abused remote monitoring and management tools.

## A worked example

Suppose your CTI team shares a report on a ransomware affiliate targeting your sector. The report says the group gains access through phishing emails with ISO attachments containing an LNK file. The LNK runs rundll32 to load a DLL from the user's profile directory. The loader then establishes Cobalt Strike beaconing over HTTPS. The operators run AdFind and net commands for Active Directory reconnaissance, move laterally using PsExec and RDP, and exfiltrate data with rclone to a cloud storage service before deploying ransomware.

The first step is to extract and map TTPs: T1566.001 (Spearphishing Attachment), T1553.005 (Mark-of-the-Web bypass via container files), T1204.002 (Malicious File), T1218.011 (Rundll32), T1071.001 (Web Protocols C2), T1087.002 and T1482 (domain account and trust discovery), T1021.002 and T1021.001 (SMB and RDP lateral movement), and T1567.002 (Exfiltration to Cloud Storage).

The next step is to form testable hypotheses rather than just searching for the report's hashes. One might be: "If this actor has compromised us, we will see rundll32 loading DLLs from user-writable directories shortly after an ISO file was mounted." Another: "We will see rclone or renamed copies of it making large outbound transfers." A third: "We will see a single account running multiple AD discovery commands within a short window."

Then check that you have the data to test each hypothesis. Do you log process command lines? Can you see ISO mount events? Do you capture file metadata that would reveal a renamed rclone binary?

Then investigate. A Microsoft Defender KQL query for the first hypothesis might look like this:

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "rundll32.exe"
| where ProcessCommandLine matches regex @"(?i)\\Users\\[^\\]+\\(AppData|Downloads|Desktop)\\.*\.dll"
| where InitiatingProcessFileName in~ ("explorer.exe", "cmd.exe")
| summarize Count=count(), Hosts=dcount(DeviceName), SampleCmd=any(ProcessCommandLine) by InitiatingProcessFileName, AccountName
| order by Hosts asc
```

For the rclone hypothesis, you'd search for rclone's distinctive command-line arguments (such as "copy", "--config", or cloud provider names) regardless of the binary name, and check the original filename metadata recorded in PE headers, since attackers frequently rename it.

When you find something, you validate it by distinguishing legitimate activity from malicious (IT admins do run AdFind occasionally) and pivot using the Diamond Model: from a suspicious host to its network connections, from a C2 domain to other hosts contacting it, from a compromised account to everywhere it logged in.

Finally, you act. Confirmed malicious activity goes to incident response. Regardless of findings, successful hunt logic becomes a scheduled detection rule, gaps you discovered (for example, missing command-line logging on some servers) become engineering tickets, and what you learned goes back to the CTI team. That could be "this technique is present in our environment and was benign," "our variant of this behavior looks different from the report," or new indicators from anything you found.

## Outputs and measuring success

A common mistake is measuring hunts only by whether they found an active compromise. Most hunts won't, and that's fine; a well-run hunt that finds nothing still confirms coverage and produces value. Better outputs to track include new or improved detections created, visibility gaps identified and closed, ATT&CK technique coverage improvement for priority actors, incidents discovered and the dwell time reduction they represent, intelligence produced for the CTI team and shared with partners, and hunts converted to automation.

Documentation is essential. Each hunt should record the hypothesis, the intelligence that drove it, the data and queries used, the findings, and the follow-up actions. This creates an institutional memory and a repeatable library of hunts.

## Common pitfalls

The most frequent failure is treating IOC sweeps as a hunting program, which keeps you at the bottom of the Pyramid of Pain. Others include hunting without adequate data (an elegant hypothesis you can't test), consuming vendor feeds without relevance filtering so hunters drown in noise, chasing whatever made headlines rather than following PIRs, confirmation bias during investigation, the "ATT&CK heatmap fallacy" of treating technique coverage as binary when detection quality varies enormously, failing to validate hunts with adversary emulation, and failing to close the loop so hunts never become detections and findings never reach the CTI team.

## Current trends

Identity and cloud have become central hunting grounds, since many modern intrusions involve token theft, MFA fatigue, help desk social engineering, OAuth app abuse, and adversary-in-the-middle phishing kits rather than traditional malware. Groups like Scattered Spider demonstrated how much damage can be done with almost no malware at all.

**Detection-as-code** treats hunt queries and detection rules like software, with version control, testing, and CI/CD pipelines. **LLMs and AI assistants** are increasingly used to parse CTI reports, extract TTPs and map them to ATT&CK, draft hunt queries, and summarize findings, though their output needs expert validation because they can confidently invent technique mappings or produce queries with subtle logic errors. **Threat-informed defense** as a broader philosophy, championed by MITRE's Center for Threat-Informed Defense, uses CTI to drive not just hunting but also detection engineering, control selection, and red team planning.

## Recommended further reading

Worth exploring are the SANS whitepapers on threat hunting and the SANS FOR578 (CTI) and FOR508 courses, the TaHiTI methodology paper, the PEAK framework from Splunk SURGe, David Bianco's writing on the Pyramid of Pain and hunting maturity, the book *Practical Threat Intelligence and Data-Driven Threat Hunting* by Valentina Costa-Gazcón, *Intelligence-Driven Incident Response* by Scott Roberts and Rebekah Brown, *Psychology of Intelligence Analysis* by Richards Heuer (free from the CIA), the ThreatHunter-Playbook project, and MITRE ATT&CK's own training material.

