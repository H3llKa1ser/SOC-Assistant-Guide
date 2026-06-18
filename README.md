# 🛡️ Blue Team Operations

> A comprehensive defensive security knowledge base — detection, forensics, threat hunting, and incident response.

A curated encyclopedia of **blue team** tradecraft covering the full defensive lifecycle: **Detect → Investigate → Respond → Hunt.** Spanning **Digital Forensics (DFIR), SIEM detection engineering, threat hunting, malware analysis, and incident response**, with practical playbooks, SIEM queries, and tool references.

> 💡 **Purple Team Note:** This repo is the defensive counterpart to offensive techniques — many sections map directly to real-world attacks, making it ideal for detection engineering and purple team exercises.

<p align="center">
  <img src="https://img.shields.io/badge/Focus-Defensive%20Security-blue" alt="Focus">
  <img src="https://img.shields.io/badge/Files-260%2B-blue" alt="Files">
  <img src="https://img.shields.io/badge/Topics-DFIR%20%7C%20SIEM%20%7C%20Threat%20Hunting%20%7C%20IR-navy" alt="Topics">
  <img src="https://img.shields.io/badge/PRs-Welcome-brightgreen" alt="PRs">
</p>

---

## 🧭 How to Use This Repo

- **Building detections?** Head to [`Methodology/SIEM Search Queries`](./Methodology/SIEM%20Search%20Queries) (Splunk & Elastic) and [`Threat Hunting`](./Threat%20Hunting) (Sigma, YARA, Sysmon).
- **Running an investigation?** Start with [`Methodology/Digital Forensics`](./Methodology/Digital%20Forensics) for OS-specific artifact guides.
- **Responding to an incident?** See [`Incident Response`](./Incident%20Response) for lifecycle, frameworks, and playbooks.
- **Learning the fundamentals?** Begin with [`Cyber Security Frameworks`](./Cyber%20Security%20Frameworks) and [`Theory`](./Theory).
- **Analyzing AD attacks?** [`Methodology/Active Directory/Attack Scenarios`](./Methodology/Active%20Directory/Attack%20Scenarios) covers detection for common AD attacks.

---

## 📚 Table of Contents

| Section | What's Inside |
|---|---|
| 🧱 [Frameworks](#-cyber-security-frameworks) | Kill chains, MITRE ATT&CK, Diamond Model, Pyramid of Pain |
| 🕵️ [Threat Intelligence](#️-cyber-threat-intelligence-cti) | CTI methodology, IOC & file analysis |
| 🔬 [Digital Forensics](#-digital-forensics) | DFIR theory + per-platform artifact extraction |
| 🚨 [Incident Response](#-incident-response) | Lifecycle, frameworks, and playbooks |
| 🦠 [Malware Analysis](#-malware-analysis) | Analysis stages and Windows API behavior |
| 🗺️ [Methodology](#️-methodology) | The core detection & investigation playbooks |
| 🎯 [Threat Hunting](#-threat-hunting) | Sigma, YARA, Sysmon, detection indicators |
| 📖 [Theory](#-theory) | SIEM concepts, threat modelling, rootkits |
| 🛠️ [Tools](#️-tools) | Forensics, SIEM, and detection tooling |

---

## 🧱 Cyber Security Frameworks

Foundational [models that underpin defensive operations](./Cyber%20Security%20Frameworks):

- [Cyber Kill Chain](./Cyber%20Security%20Frameworks/Cyber%20Kill%20Chain.md) · [Unified Kill Chain](./Cyber%20Security%20Frameworks/Unified%20Kill%20Chain.md)
- [MITRE ATT&CK](./Cyber%20Security%20Frameworks/MITRE.md) · [Diamond Model](./Cyber%20Security%20Frameworks/Diamond%20Model.md) · [The Pyramid of Pain](./Cyber%20Security%20Frameworks/The%20Pyramid%20Of%20Pain.md)

---

## 🕵️ Cyber Threat Intelligence (CTI)

[CTI fundamentals and analysis methodology](./Cyber%20Threat%20Intelligence%20(CTI)):

- [Definition & concepts](./Cyber%20Threat%20Intelligence%20(CTI)/Definition.md)
- Methodology: [File Analysis](./Cyber%20Threat%20Intelligence%20(CTI)/Methodology/File%20Analysis.md) · [IP & Domain Analysis](./Cyber%20Threat%20Intelligence%20(CTI)/Methodology/IP%20and%20Domain%20Analysis.md)

---

## 🔬 Digital Forensics

In-depth [DFIR reference material](./Digital%20Forensics) covering theory and platform-specific artifacts.

| Area | Coverage |
|---|---|
| **Theory** | [DFIR process, evidence collection, acquisition methods, anti-forensics, golden rules](./Digital%20Forensics/Theory) |
| **Windows** | [Registry, evidence of execution, USB forensics, NTFS/MFT](./Digital%20Forensics/Windows) |
| **Linux** | [Artifacts, auth logs, persistence, forensic imaging, rootkit hunting](./Digital%20Forensics/Linux) |
| **Mobile** | [Android & iOS forensics, SIM cloning, cellular networks](./Digital%20Forensics/Mobile) |
| **Hypervisors** | [VMware & VirtualBox artifacts + memory dumps](./Digital%20Forensics/Hypervisors) |
| **Cross-platform** | [Browsers, email, cloud, database, ESE forensics](./Digital%20Forensics/Cross-platform) |
| **Artifact Extraction** | [IP addresses, port-scan detection](./Digital%20Forensics/Artifact%20Extraction) |

> 📌 See also the deeper, OS-by-OS breakdowns under [`Methodology/Digital Forensics`](#️-methodology).

---

## 🚨 Incident Response

[The IR layer](./Incident%20Response):

- [Incident Response Lifecycle](./Incident%20Response/Incident%20Response%20Lifecycle.md)
- [Frameworks](./Incident%20Response/Frameworks.md) · [Playbooks](./Incident%20Response/Playbooks.md)

---

## 🦠 Malware Analysis

[Malware analysis foundations](./Malware%20Analysis):

- [Analysis Stages](./Malware%20Analysis/Stages.md) · [Windows API calls](./Malware%20Analysis/Windows%20API%20calls.md)

---

## 🗺️ Methodology

The **operational core** of the repo — detailed, hands-on playbooks for detection and investigation.

### 🏰 Active Directory Defense
[Monitoring, baselining, and attack detection](./Methodology/Active%20Directory):
- [AD Visibility](./Methodology/Active%20Directory/AD%20Visibility.md) · [Authentication Events](./Methodology/Active%20Directory/Authentication%20Events.md) · [Logon Events](./Methodology/Active%20Directory/Logon%20Events.md) · [Kerberos](./Methodology/Active%20Directory/Kerberos.md)
- **[Attack Scenarios](./Methodology/Active%20Directory/Attack%20Scenarios)** — detecting Kerberoasting, DCSync, AS-REP Roasting, LSASS dumping, NTDS extraction, lateral movement, ransomware, and more

### 🔬 Digital Forensics (Deep Dive)
[Comprehensive per-platform forensic methodology](./Methodology/Digital%20Forensics):
- **[Windows](./Methodology/Digital%20Forensics/Windows)** · **[Linux](./Methodology/Digital%20Forensics/Linux)** · **[MacOS](./Methodology/Digital%20Forensics/MacOS)** · **[Mobile](./Methodology/Digital%20Forensics/Mobile)**
- **[Memory](./Methodology/Digital%20Forensics/Memory)** — acquisition + Windows/Linux analysis
- **[File System](./Methodology/Digital%20Forensics/File%20System)** — NTFS, FAT, EXT, MBR, GPT
- **[Browsers](./Methodology/Digital%20Forensics/Browsers)** · **[Microsoft Office](./Methodology/Digital%20Forensics/Microsoft%20Office)** (OneDrive, Outlook, Teams)
- **[Tools](./Methodology/Digital%20Forensics/Tools)** — Volatility, KAPE, FTK Imager, Osquery

### 📊 Log Analysis
[Making sense of the logs](./Methodology/Log%20Analysis):
- **Windows:** [Sysmon playbooks](./Methodology/Log%20Analysis/Windows%20Logging/Sysmon) (malware persistence, phishing, USB attacks) · [Event Viewer playbooks](./Methodology/Log%20Analysis/Windows%20Logging/Event%20Viewer)
- **Linux:** [Auditd & log types](./Methodology/Log%20Analysis/Linux%20Logging)
- [Firewall](./Methodology/Log%20Analysis/Firewall%20Logs.md) · [IDS](./Methodology/Log%20Analysis/IDS%20Logs.md) · [VPN](./Methodology/Log%20Analysis/VPN%20Logs.md) · [Web Servers](./Methodology/Log%20Analysis/Web%20Servers.md)

### 🔎 SIEM Search Queries
[Ready-to-use detection queries](./Methodology/SIEM%20Search%20Queries):
- **[Splunk](./Methodology/SIEM%20Search%20Queries/Splunk)** — C2, credential dumping, lateral movement, persistence, ransomware, DNS tunneling, and an [experimental queries lab](./Methodology/SIEM%20Search%20Queries/Splunk/Experimental%20Queries)
- **[Elastic](./Methodology/SIEM%20Search%20Queries/Elastic)** — command execution, account activity, web app detections

### 📡 Packet Capture Analysis
[Network forensics](./Methodology/Packet%20Capture%20Analysis):
- **[Wireshark](./Methodology/Packet%20Capture%20Analysis/Wireshark)** — ARP/DNS spoofing, tunneling, exfiltration, Kerberos, SSL stripping
- **[Tshark](./Methodology/Packet%20Capture%20Analysis/Tshark)** — CLI usage & use cases

### ☁️ Cloud Defense
[Cloud detection & investigation](./Methodology/Cloud):
- **[AWS](./Methodology/Cloud/AWS)** — CloudTrail, GuardDuty, IAM/EC2/S3/Lambda investigations
- **[Azure](./Methodology/Cloud/Microsoft%20Azure)** — Entra ID, Sentinel, Defender XDR, M365, KQL queries
- **[Containers](./Methodology/Cloud/Containers)** — Falco runtime detection

### 🤖 AI Security & Other
- **[Artificial Intelligence](./Methodology/Artificial%20Intelligence)** — LLM hardening, RAG systems, supply chain
- **[Investigations](./Methodology/Investigations)** — Linux triage + YARA threat hunting

---

## 🎯 Threat Hunting

[Proactive detection tradecraft](./Threat%20Hunting):

- [Core Windows Processes](./Threat%20Hunting/Core%20Windows%20Processes.md) · [Detection Indicators](./Threat%20Hunting/Detection%20Indicators.md) · [Windows Event IDs](./Threat%20Hunting/Windows%20Event%20IDs.md)
- [Sigma](./Threat%20Hunting/Sigma.md) · [YARA](./Threat%20Hunting/YARA.md) · [Sysmon](./Threat%20Hunting/Sysmon.md) · [Event Viewer](./Threat%20Hunting/Event%20Viewer.md)

---

## 📖 Theory

[Core defensive concepts](./Theory):

- [SIEM](./Theory/SIEM.md) · [SIEM Alerts](./Theory/SIEM%20Alerts.md) · [Threat Modelling](./Theory/Threat%20Modelling.md) · [Rootkits](./Theory/Rootkits.md)

---

## 🛠️ Tools

Usage references for the defensive toolkit:

- **[Forensic Tools](./Tools/Forensic%20Tools)** — Volatility Framework, Binwalk
- **[SIEM / Splunk](./Tools/SIEM/Splunk)** — adding data, navigation, apps, queries
- **[Palo Alto Networks](./Tools/Palo%20Alto%20Networks)** — Data Lake

---

## 🤝 Contributing

Contributions, corrections, and additions are welcome! Feel free to open an issue or submit a pull request.

## 📄 License

See [LICENSE.md](./LICENSE.md) for details.

---

<div align="center">

⭐ **If you find this useful, consider starring the repo!** ⭐

*Built and maintained by [H3llKa1ser](https://github.com/H3llKa1ser)*

*For educational and defensive security purposes.*

</div>
