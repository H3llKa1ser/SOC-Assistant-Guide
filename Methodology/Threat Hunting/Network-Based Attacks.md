# Threat Hunting for Network-Based Attacks

## What it is

Threat hunting is the proactive, human-led search for adversary activity that your existing detections missed. It starts from the assumption that you are already compromised: something is in the environment and has not triggered an alert. Detection engineering asks "what should alert?", while hunting asks "what is happening that nothing alerted on?" A good hunt usually ends by turning what it found into a new automated detection, so the same technique never needs to be hunted by hand again.

Network-based hunting uses traffic and its metadata as the main lens. The network is valuable because adversaries can delete logs, tamper with endpoint agents, and live off the land on a host, but they almost always have to communicate. Command and control (C2), lateral movement, data staging, and exfiltration all leave traces on the wire. The network is also hard to forge after the fact: a packet that crossed a sensor was captured whether or not the attacker later wiped the host.

## Guiding frameworks and mental models

A few models shape how mature teams hunt.

**The Pyramid of Pain** (David Bianco) ranks indicators by how costly they are for an attacker to change. At the bottom are hashes, IPs, and domains, which are trivial to swap. Higher up are network and host artifacts such as URI patterns, JA3/JA4 fingerprints, and user-agent quirks. At the top are tools and TTPs (tactics, techniques, and procedures). Network hunting is most valuable when it targets behaviors like "periodic outbound connections with low jitter" rather than a specific bad IP.

**MITRE ATT&CK** gives hunters a shared vocabulary and a coverage map. The network-heavy tactics are the following:
- **Command and Control (TA0011):** application layer protocols, DNS, encrypted channels, protocol tunneling, proxies, web services, non-standard ports.
- **Lateral Movement (TA0008):** remote services such as SMB, RDP, and WinRM.
- **Exfiltration (TA0010):** over C2, over alternative protocols, to cloud storage.
- **Discovery (TA0007):** network service scanning, remote system discovery.
- **Credential Access (TA0006):** LLMNR/NBT-NS poisoning, Kerberoasting, adversary-in-the-middle.

Mapping hunts to technique IDs shows where you have looked and where you are blind.

**Hunting methodologies** give the work a repeatable loop:
- The Sqrrl hunting loop: create hypothesis, investigate with tools, uncover patterns and TTPs, inform and enrich analytics.
- TaHiTI: a Dutch financial-sector methodology built around threat intelligence.
- Splunk's PEAK framework: Prepare, Execute, Act with Knowledge. PEAK distinguishes three hunt types. Hypothesis-driven hunts test a specific idea. Baseline hunts ask "what does normal look like, and what deviates?" Model-assisted hunts use statistics or machine learning to surface outliers for human review.

**The Hunting Maturity Model** (HM0 to HM4) describes how teams progress:
- HM0: relies entirely on automated alerts.
- HM1: searches threat intel indicators.
- HM2: follows other people's hunt procedures.
- HM3: creates its own procedures.
- HM4: automates successful hunts into detections as a matter of routine.

## Data sources

Hunting is only as good as its visibility. The main network data types trade fidelity against cost and scale:

| Data source | What it gives you | Tradeoffs |
|---|---|---|
| Full packet capture (PCAP) | Complete payloads, perfect ground truth, file carving | Huge storage cost, usually retained only hours to days; mostly useless for payload analysis once encrypted |
| Zeek (formerly Bro) logs | Rich protocol metadata: conn, dns, http, ssl, x509, files, smb, kerberos, ntlm, rdp, dce_rpc, weird, notice | The workhorse of network hunting; compact, parseable, retained for months |
| NetFlow / IPFIX / sFlow | Who talked to whom, when, how much, which ports | Cheap and wide coverage, but no content, and often sampled (sampling can hide low-and-slow C2) |
| Cloud flow logs (AWS VPC Flow Logs, Azure NSG/VNet flow logs, GCP VPC Flow Logs) | Flow data for cloud workloads | Often the only network visibility in cloud; limited fields by default |
| DNS logs (resolver, Zeek dns.log, Sysmon Event 22, passive DNS) | Every name lookup, response codes, record types | Among the highest-value sources; DoH/DoT can bypass it |
| Web proxy / secure web gateway logs | URLs, user agents, categories, users, bytes | Excellent for HTTP(S) C2 if TLS inspection or SNI is available |
| Firewall and IDS/IPS logs (Suricata, Snort) | Allowed/denied connections, signature hits | Signature alerts are leads, not conclusions |
| EDR network telemetry (e.g., Defender DeviceNetworkEvents, Sysmon Event 3) | Ties connections to the process and user that made them | Critical for context: "powershell.exe talked to this IP" beats "a host talked to this IP" |
| TLS metadata (SNI, certificates, JA3/JA3S/JA4+) | Fingerprints encrypted sessions without decryption | Increasingly the main lens as encryption spreads |

The strongest position combines the network view with the host view. The network tells you something odd happened. The endpoint tells you which process did it, who launched it, and what else it touched.

Common visibility gaps worth auditing include:
- **East-west traffic.** Many sensors sit only at the perimeter, but lateral movement happens internally.
- **Remote workers** off VPN.
- **Encrypted DNS.**
- **Cloud-to-cloud traffic.**
- **Sampled flow data.**

## Core analytic techniques

**Stacking (frequency analysis)** is the most important technique in network hunting. You group events by some attribute, count them, and look at the rare end. Stack destination ports, user agents, JA3 hashes, TLS certificate issuers, DNS query types, or parent processes making network connections. Malicious activity usually lives in the long tail. If 4,000 hosts share one user agent and one host has a unique one, that host deserves a look.

**Baselining** means learning what normal is for a host, subnet, or time of day, then hunting deviations. Examples include a workstation that suddenly talks to a domain controller over a new protocol, a server with outbound internet traffic it never had before, or a 3 a.m. spike in outbound bytes. A key caution: if the attacker was present when you built the baseline, their activity is now "normal."

**Pivoting** is how a lead becomes an investigation. A suspicious domain leads to its resolved IPs, then to other domains on those IPs, then to every internal host that contacted them, then to the processes on those hosts, then to what else those processes did. Tools like passive DNS, certificate transparency logs, VirusTotal, Shodan, Censys, and URLScan extend these pivots outside your network.

**Enrichment** adds context to raw data:
- GeoIP and ASN.
- Domain age (newly registered domains are high-risk).
- Domain reputation and popularity lists such as Tranco. Traffic to domains outside the top million, especially young ones, is disproportionately suspicious.
- Threat intel matches.
- Asset criticality.

**Long-tail and outlier statistics** sharpen stacking. Useful measures include coefficient of variation, standard deviation, entropy, and z-scores.

## Hunting C2 and beaconing

Most implants check in with their C2 server on a schedule, and this periodicity is detectable even when the traffic is encrypted. The signals of beaconing are:
- Regular connection intervals, even with jitter. Cobalt Strike's default is a 60-second sleep, and operators often add 10 to 50 percent jitter.
- Consistent session sizes, because the same check-in request produces similar byte counts.
- A high connection count to a single destination over a long window.
- A small number of source hosts contacting a rare destination.

You measure regularity by computing the time deltas between successive connections for each source/destination pair, then looking at their dispersion. A low coefficient of variation (standard deviation divided by mean) means machine-like timing. More robust approaches use median absolute deviation, skew of the interval distribution, and consistency of bytes transferred. RITA (Real Intelligence Threat Analytics, from Active Countermeasures) does this scoring on Zeek logs out of the box.

Long connections are a related signal. A TCP session that stays open for hours to an external host can indicate interactive C2 or a reverse tunnel, and Zeek conn.log's duration field makes this easy to stack.

False positives are everywhere in beacon hunting: Windows Update, antivirus signature checks, NTP, telemetry agents, chat clients, cloud sync tools, and monitoring software all beacon. You need a well-maintained allowlist, and a hunter who reviews context rather than trusting the score.

Here is a KQL example for Microsoft Defender or Sentinel that scores beacon-like regularity:

```kql
DeviceNetworkEvents
| where Timestamp > ago(1d) and RemoteIPType == "Public"
| sort by DeviceName asc, RemoteIP asc, Timestamp asc
| extend PrevTime = prev(Timestamp), PrevDev = prev(DeviceName), PrevIP = prev(RemoteIP)
| where DeviceName == PrevDev and RemoteIP == PrevIP
| extend Delta = datetime_diff('second', Timestamp, PrevTime)
| summarize Conns = count(), AvgDelta = avg(Delta), StdDelta = stdev(Delta),
            Procs = make_set(InitiatingProcessFileName)
          by DeviceName, RemoteIP, RemoteUrl
| where Conns > 30 and AvgDelta > 0
| extend CV = StdDelta / AvgDelta
| where CV < 0.2
| order by CV asc
```

And a quick Zeek pass for long-lived connections:

```bash
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto duration \
  | sort -t$'\t' -k5 -rn | head -50
```

Other C2 patterns to hunt:
- **C2 over trusted services.** Implants increasingly hide in Microsoft Graph, Google Drive, Dropbox, GitHub, Slack, Discord, Telegram, Notion, and Pastebin. The destination is reputable, so you hunt on which process is talking to it. For example, rundll32.exe calling api.telegram.org is suspicious. You can also hunt on volume and timing anomalies.
- **Domain fronting** and CDN abuse, where the SNI and the HTTP Host header disagree.
- **Protocols on non-standard ports**, such as HTTP on 8443 or 4444, or SSH on 443. Zeek's protocol detection identifies the protocol independently of the port, so mismatches stand out.
- **Rare ports outbound**, found by stacking destination ports across the fleet.
- **Direct-to-IP connections** with no preceding DNS lookup. Legitimate software almost always resolves a name first.

## Hunting DNS abuse

DNS is abused because it is almost always allowed out, rarely inspected, and can carry data.

**DNS tunneling** (tools such as iodine, dnscat2, DNSExfiltrator, and C2 frameworks with DNS channels) encodes data in subdomain labels and in TXT, NULL, or CNAME responses. Signals include:
- Very long query names, often near the 253-character limit.
- High Shannon entropy in subdomains.
- A large number of unique subdomains under a single parent domain.
- Unusual volumes of TXT or NULL queries.
- High query volume from one host to one domain.

The best single stack is "count of unique subdomains per registered domain per source host."

**Domain generation algorithms (DGAs)** produce many random-looking domains, most of which don't resolve. The signs are spikes in NXDOMAIN responses from a single host and high-entropy second-level domains. Dictionary-based DGAs that stitch together real words defeat entropy checks, so combine entropy with NXDOMAIN rates and domain age.

Other DNS signals:
- **Newly registered or newly observed domains.** Attackers often stand up infrastructure days before use.
- **Fast flux:** many A records with very short TTLs that rotate frequently.
- **Resolver bypass:** hosts sending DNS directly to external resolvers (port 53 to 8.8.8.8, for example) instead of your internal resolvers, or using DoH to known providers from processes that aren't browsers.
- **Typosquats and lookalike domains** of your own brand or of common SaaS providers.

A tshark one-liner for quickly finding long queries in a PCAP:

```bash
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e ip.src -e dns.qry.name \
  | awk '{ print length($2), $1, $2 }' | sort -rn | head -30
```

## Hunting in encrypted traffic

With TLS 1.3, QUIC, and increasingly Encrypted Client Hello (ECH), payload inspection is fading. Hunting shifts to metadata.

**JA3 and JA4 fingerprints.** JA3 hashes the TLS ClientHello parameters (version, ciphers, extensions, curves). JA3S does the same for the server response. The JA4+ suite from FoxIO is the modern successor and is more robust to extension-order randomization that breaks JA3 in Chrome. JA4+ also covers HTTP (JA4H), SSH (JA4SSH), certificates (JA4X), and more. Stack fingerprints across your fleet, and investigate rare ones, especially when paired with rare destinations. Known malware fingerprints are useful but brittle, since tooling like Cobalt Strike malleable profiles can change them. The rarity approach is more durable.

**Certificate analysis** looks for:
- Self-signed certificates on internet-facing destinations.
- Default certificates from C2 frameworks. Metasploit, Cobalt Strike, and Sliver have known defaults that lazy operators leave in place.
- Very recently issued certificates on young domains.
- Free-CA certificates on domains with no reputation (not bad on its own, but useful in combination).
- Mismatches between the certificate subject and the SNI.
- Unusually long or short validity periods.
- Empty or odd subject fields.

**Traffic shape** can reveal behavior without decryption. Packet size and timing sequences can distinguish interactive shells from web browsing. JA4SSH, for instance, can suggest whether an SSH session is interactive or a file transfer.

**TLS inspection** at a proxy restores visibility for managed devices, at the cost of privacy considerations, certificate pinning breakage, and performance overhead.

## Hunting lateral movement

Internal (east-west) traffic is where attackers spend most of their time, and it's where many organizations have the least visibility.

**SMB (445).** Hunt for:
- Workstation-to-workstation SMB, which is rare in most environments.
- Access to admin shares (C$, ADMIN$, IPC$).
- Service creation via the svcctl named pipe, which is how PsExec-style tools work.
- File writes of executables to remote shares.

Zeek's smb_mapping.log, smb_files.log, and dce_rpc.log are very useful here.

**Remote execution over RPC** leaves recognizable DCE-RPC operations:
- Remote service creation: svcctl CreateServiceW.
- Scheduled tasks: atsvc or ITaskSchedulerService.
- WMI: IWbemServices over DCOM.
- DCOM lateral movement: MMC20.Application, ShellWindows.
- Remote registry.

The telltale pattern is a single source hitting many destinations with these operations in a short window.

**RDP (3389).** Look for:
- RDP from unusual sources, such as a workstation connecting to many servers.
- RDP chains, where A connects to B and B then connects to C.
- RDP from the internet.
- RDP to servers where the source is not a jump host.

**WinRM (5985/5986) and SSH.** Stack source-destination pairs, and flag any pair that's new relative to the baseline.

**Fan-out patterns.** One host connecting to an unusual number of internal hosts on admin ports is either a management server or an attacker.

**Internal reconnaissance** shows up as:
- Port scans: many destination ports, or many hosts on one port.
- Connection attempts that get rejected (Zeek conn_state values REJ, S0).
- LDAP queries enumerating the domain, as BloodHound/SharpHound do.
- Many SMB session enumerations from one host.

## Hunting credential attacks on the wire

**Kerberoasting.** Look for a single account requesting TGS tickets for many service accounts in a short time, especially with RC4 encryption (etype 0x17/23) in an environment that otherwise uses AES. Zeek's kerberos.log records cipher and service fields, and Windows Event 4769 gives the same view from the domain controller.

**AS-REP roasting.** Look for AS-REQ traffic for accounts without pre-authentication.

**NTLM relay and downgrade.** Look for NTLMv1 in a modern environment, NTLM authentication where Kerberos is expected, and NTLM traffic from unexpected source IPs for a given account.

**LLMNR, NBT-NS, and mDNS poisoning** (Responder, Inveigh). Hunt for a single host answering name-resolution broadcasts for many different names. The best fix is to disable these protocols entirely.

**Adversary-in-the-middle on the LAN.** Signs include ARP spoofing (one MAC claiming many IPs, or a gateway MAC changing), rogue DHCP servers, and IPv6 router advertisement abuse (mitm6).

**Brute force and password spraying.** Brute force appears as many failed authentications against one account. Spraying appears as one or a few failures across many accounts from one source, across SMB, LDAP, RDP, VPN, or SaaS login portals.

## Hunting exfiltration

Signals of exfiltration include:
- **Upload/download ratio inversion.** Normal clients download far more than they upload, so a host with sustained large outbound transfers stands out. Zeek's orig_bytes versus resp_bytes makes this easy to stack.
- **Large transfers to cloud storage or file-sharing services** from hosts or processes that don't normally use them. Rclone traffic to Mega or similar is a classic ransomware-group precursor.
- **Off-hours transfers.**
- **Data staging:** internal hosts pulling large volumes from file servers before an outbound transfer.
- **Exfiltration over alternative protocols:** DNS, ICMP (large or high-volume echo payloads), FTP, SMTP, or unusual HTTP POST patterns.
- **Low and slow exfiltration** that stays under volume thresholds but persists for days. Long-window aggregation catches this where short-window alerts don't.

## Hunting HTTP-specific anomalies

Where HTTP is visible (cleartext, proxy logs, or TLS inspection), look for:
- **Rare or malformed user agents.** Examples include outdated browser strings, scripting-language defaults (python-requests, curl, Go-http-client, PowerShell's WindowsPowerShell string), and user agents that don't match the fingerprint of the client.
- **Unusual methods**, such as PUT or unexpected POST patterns.
- **Repetitive URIs with encoded parameters.**
- **Missing headers** that real browsers always send, like Accept-Language or Referer.
- **Downloads of executables, scripts, or archives** from rare domains. Zeek files.log gives MIME types and hashes.
- **Web shell activity on your own servers:** inbound requests to odd script paths followed by the server making outbound connections or spawning processes.

## Constructing good hypotheses

A good hypothesis is specific, testable, and grounded in intelligence or a known gap. "Look for bad stuff" is not a hypothesis. Compare these:

- "An adversary using Cobalt Strike with default or common malleable profiles is beaconing from our workstations, which would show up as low-jitter periodic HTTPS to rare domains with JA4 fingerprints unseen elsewhere in the fleet."
- "Following the recent advisory on group X, which uses Rclone for exfiltration to Mega, we will look for any Mega-bound traffic, or any Rclone-like TLS fingerprints, from servers."
- "An attacker with a foothold would move laterally using PsExec-style service creation. We'll look for svcctl CreateService operations originating from non-admin workstations."
- "DNS tunneling would appear as a single host generating hundreds of unique subdomains under a single registered domain."

Sources of hypotheses include threat intelligence reports, incident post-mortems (from yours or from others in your sector), red team findings, ATT&CK coverage gaps, new vulnerabilities in your exposed services, and simple curiosity about an anomaly you noticed.

## The hunt workflow

1. **Prepare.** Pick a hypothesis, identify the required data, and confirm you actually have it. A surprising number of hunts end at this step with a visibility gap, which is a valuable finding in itself.
2. **Scope.** Define the time window, systems, and success criteria.
3. **Execute.** Query, stack, and pivot, then triage the outliers. For each outlier, work out whether it's benign-explained, benign-unexplained, or suspicious.
4. **Escalate.** If you find real malicious activity, the hunt becomes an incident, and incident response takes over. Preserve PCAP and logs before retention windows roll over.
5. **Act on knowledge.** Document what you did and found, and build detections from the successful logic. Tune out the false positives you identified, feed allowlists and baselines back into the system, and record data gaps for engineering to close.

## Tooling

**Sensors and analysis platforms:**
- Zeek and Suricata are the core open-source pair: Zeek for metadata, Suricata for signatures plus its own protocol logs.
- Security Onion bundles both with Elastic and case management.
- Arkime (formerly Moloch) indexes full PCAP at scale.
- Malcolm (from CISA/INL) is another packaged stack.
- Commercial NDR platforms include Corelight (commercial Zeek), ExtraHop, Vectra, and Darktrace.

**Analysis tools:**
- Wireshark and tshark for packet-level work.
- Zui (formerly Brim) for fast Zeek log and PCAP exploration.
- NetworkMiner for file and credential extraction from PCAP.
- RITA and AC-Hunter for beacon and long-connection scoring.
- CyberChef for decoding.
- Jupyter notebooks with pandas for custom statistics.

**Query platforms:** Splunk (SPL), Microsoft Sentinel and Defender (KQL), Elastic (ES|QL, EQL), Google SecOps (YARA-L), and Velociraptor for pulling host context during network hunts.

**Enrichment:** passive DNS (DomainTools, SecurityTrails), certificate transparency (crt.sh), Shodan, Censys, GreyNoise (which helps filter internet background noise), VirusTotal, URLScan, WHOIS for domain age, and the Tranco list.

## Common pitfalls

- **Alert-chasing disguised as hunting.** Searching intel IOCs is useful but is the lowest rung of maturity.
- **Drowning in false positives.** Without allowlists for update services, CDNs, and telemetry, beacon and rarity hunts are unusable.
- **Ignoring time zones and clock skew** when correlating network and host data.
- **Sampled flow data** silently hiding low-volume C2.
- **Perimeter-only sensors** that are blind to lateral movement.
- **Short PCAP retention**, so you find the lead but the evidence is gone. Metadata retention should be measured in months.
- **Failing to document**, so every hunt starts from scratch.
- **Not closing the loop**, so successful hunts never become detections.

## Measuring success

Finding an attacker is the dramatic outcome but not the only one. Useful metrics include:
- Hunts completed and ATT&CK techniques covered.
- New detections created from hunts.
- Visibility gaps found and closed.
- Misconfigurations and policy violations uncovered, such as shadow IT, cleartext credentials, legacy protocols, and exposed services.
- Reduction in dwell time for incidents that do happen.
- Reduction in false positives from tuning.

## Building skill

**Practice datasets:**
- Malware-Traffic-Analysis.net, which offers PCAP exercises with answers.
- The Stratosphere Lab malware captures.
- Active Countermeasures' sample beacon datasets.
- CIC-IDS and UNSW-NB15 academic datasets.
- The Splunk Boss of the SOC (BOTS) datasets.
- Security Onion's included sample PCAPs.

**Courses:** SANS FOR572 (Advanced Network Forensics) and SEC503 (Network Monitoring and Threat Detection), Active Countermeasures' free beacon-hunting courses, and Chris Sanders' work on network security monitoring. Richard Bejtlich's *The Practice of Network Security Monitoring* remains a foundational read.

**Build a lab.** A small home lab with Zeek, Suricata, and a C2 framework like Sliver or Mythic, run against your own VMs, is the fastest way to learn what attacks actually look like on the wire and to test whether your hunts would catch them.

---

