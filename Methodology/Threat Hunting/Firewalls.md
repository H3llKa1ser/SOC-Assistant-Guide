# Threat Hunting with Firewalls

# Threat Hunting with Firewalls

## What it is and why firewalls matter

Threat hunting is the proactive, human-led search for adversaries who have already evaded your automated defenses. Detection waits for an alert. Hunting assumes compromise and goes looking. Firewall hunting uses the logs and telemetry from perimeter and internal firewalls to find those adversaries in network behavior.

Firewalls are valuable for hunting for three reasons:

- **They sit at chokepoints.** Almost every attack eventually has to cross the network: command-and-control (C2), data exfiltration, lateral movement, downloading tooling.
- **They are hard for an attacker on an endpoint to tamper with.** Malware can kill an EDR agent or wipe local logs, but it can't easily erase what the firewall already sent to your SIEM.
- **They cover unmanaged devices.** IoT, OT, printers, contractor laptops, and appliances often can't run an agent, but they still generate network traffic.

The important caveat is that a firewall only sees what crosses it. A flat internal network with only a perimeter firewall is blind to east-west movement. That's one of the strongest arguments for internal segmentation firewalls.

## The data sources you hunt in

Modern next-generation firewalls (NGFWs) produce far more than allow/deny logs. The main log types are:

- **Traffic logs.** Source and destination IP, ports, protocol, bytes in and out, packets, session duration, action, rule matched, NAT translations, and the session end reason. On NGFWs you also get the application identified (App-ID on Palo Alto, application control on Fortinet and others) and the user identity mapped to the IP.
- **Threat logs.** IPS signature hits, antivirus and anti-spyware detections, vulnerability exploit attempts, and C2 signature matches.
- **URL filtering logs.** Full URLs or hostnames, URL category, user agent, and sometimes HTTP method and referrer.
- **DNS logs.** Many NGFWs can act as a DNS proxy or inspect DNS, giving you the queried domain, record type, response, and DNS security verdicts.
- **Decryption/TLS logs.** SNI, certificate issuer and subject, validity dates, TLS version, cipher, and sometimes JA3/JA4 fingerprints.
- **Sandbox verdicts.** Examples are WildFire and FortiSandbox: files that crossed the firewall and what the sandbox concluded.
- **VPN and remote-access authentication logs.** User, source IP, geolocation, client version, and success or failure.
- **System and configuration audit logs.** Admin logins, config commits, rule changes, and software updates. These matter for hunting attacks against the firewall itself.

Many teams also pull NetFlow/IPFIX from routers, or run Zeek sensors, to complement firewall logs with richer protocol metadata.

## Prerequisites: making firewall data huntable

Most hunting programs fail on data quality before they ever reach analysis. Check these first:

- **Log allowed traffic, not just denies.** Log at session end so byte counts and duration are complete. Many organizations log only denies, which makes hunting for successful C2 or exfiltration nearly impossible.
- **Synchronize all devices to NTP.** Correlation across sources depends on consistent timestamps.
- **Keep enough history.** Dwell times can run to weeks or months, so aim for at least 90 days searchable, and ideally a year in cheaper storage.
- **Centralize logs** in a SIEM or data lake: Splunk, Microsoft Sentinel, Elastic, Google SecOps/Chronicle, QRadar, or a Databricks/Snowflake-style lake.
- **Enrich the data:**
  - Asset inventory, so you know what each IP is and who owns it.
  - DHCP and VPN lease history, because IPs change hands.
  - User identity mapping.
  - GeoIP and ASN data.
  - Threat intelligence feeds.
  - Domain registration age.
  - A list of known-good destinations for your environment.
- **Record NAT translations.** Without them you can see that "the firewall's public IP" did something but can't trace it back to the internal host.

## Hunting methodology

There are three broad hunt types:

- **Hypothesis-driven hunts** start from an idea about attacker behavior, usually framed with MITRE ATT&CK. An example: "an attacker with a foothold would beacon to C2 on a regular interval over HTTPS."
- **Intelligence-driven hunts** start from indicators or TTPs in a threat report. You sweep your historical logs for a newly published C2 IP range or a technique a relevant threat group uses.
- **Anomaly-driven hunts** start from the data itself. You look for outliers, rarities, and deviations from baseline without a specific hypothesis.

A typical cycle runs through these steps:

1. Form a hypothesis.
2. Identify the data needed.
3. Query and analyze.
4. Investigate the leads.
5. Respond to anything real.
6. Turn the successful logic into an automated detection, so you never have to hunt for that thing manually again.

Frameworks like PEAK (from Splunk's SURGe team) and TaHiTI formalize this cycle. The Sqrrl Hunting Maturity Model (HMM0 to HMM4) is a common way to measure how far along a program is.

The Pyramid of Pain is worth keeping in mind. Hunting for specific IPs and domains is easy but brittle, because attackers rotate them cheaply. Hunting for behaviors is harder but far more durable: beaconing patterns, protocol misuse, abnormal data volumes. Firewall data is especially good at behavioral hunting.

## The core hunts

### C2 beaconing

Malware implants typically check in with their C2 server on a schedule. The firewall signature is many connections from one internal host to one external destination at suspiciously regular intervals, often with consistent byte sizes.

To find it, calculate the time delta between consecutive connections for each source-destination pair. Then measure how consistent those deltas are. A low coefficient of variation (standard deviation divided by mean) indicates machine-like regularity.

Frameworks like Cobalt Strike, Sliver, and Mythic support jitter to defeat this. Even with 20–30% jitter, the distribution of intervals is usually still tighter than human browsing. Tools like RITA (Real Intelligence Threat Analytics) score beaconing statistically using interval consistency, data-size consistency, and connection count together.

Also look for:

- Very long-duration sessions, which suggest persistent tunnels.
- Low-and-slow connections that transfer tiny amounts of data over hours.

Expect heavy false positives. Software updaters, telemetry, NTP, AV cloud lookups, and SaaS heartbeats all beacon legitimately. You'll build and maintain an allowlist of known-good beaconing destinations.

A Splunk-style example:

```spl
index=firewall sourcetype=pan:traffic action=allowed dest_zone=untrust
| sort 0 src_ip dest_ip _time
| streamstats current=f window=1 last(_time) as prev_time by src_ip dest_ip dest_port
| eval delta=_time-prev_time
| stats count as conns avg(delta) as avg_int stdev(delta) as sd_int
        avg(bytes_out) as avg_out stdev(bytes_out) as sd_out by src_ip dest_ip dest_port
| where conns > 50
| eval interval_cv=sd_int/avg_int, size_cv=sd_out/avg_out
| where interval_cv < 0.25
| lookup known_good_destinations dest_ip OUTPUT dest_ip as known
| where isnull(known)
| sort interval_cv
```

### Rare and first-seen destinations

This is "long-tail" or least-frequency analysis. Most legitimate traffic goes to destinations that many hosts in your environment visit. Attacker infrastructure is usually contacted by one or two hosts and has never been seen before.

Stack-count destinations by how many distinct internal hosts talk to them. Focus on external IPs or domains that are first seen recently and touched by very few hosts, especially when combined with:

- Uncategorized URL categories.
- Newly registered domains.
- Dynamic DNS providers.
- Hosting-provider ASNs, as opposed to major SaaS providers.

A KQL example for Sentinel (field values for actions vary by vendor):

```kql
let baseline = CommonSecurityLog
    | where TimeGenerated between (ago(30d) .. ago(1d))
    | where DeviceAction in~ ("allow", "accept")
    | distinct DestinationIP;
CommonSecurityLog
| where TimeGenerated > ago(1d)
| where DeviceAction in~ ("allow", "accept")
| where not(ipv4_is_private(DestinationIP))
| where DestinationIP !in (baseline)
| summarize Hosts=dcount(SourceIP), Sessions=count(), BytesOut=sum(SentBytes)
    by DestinationIP, DestinationPort, ApplicationProtocol
| where Hosts <= 2
| order by BytesOut desc
```

### Data exfiltration

Look for internal hosts whose outbound bytes greatly exceed inbound bytes. Normal browsing downloads far more than it uploads, so heavy upload asymmetry stands out. Other signals:

- Large uploads to cloud storage and file-sharing services, especially ones your organization doesn't sanction. MEGA, generic file-drop sites, and paste sites have been heavily abused. Ransomware groups often use tools like rclone to push data to cloud storage before encrypting.
- Uploads at unusual hours.
- Transfers to unusual countries.
- Servers that normally never initiate outbound connections suddenly sending gigabytes out.

```spl
index=firewall action=allowed dest_zone=untrust
| stats sum(bytes_out) as out sum(bytes_in) as in dc(dest_ip) as dests values(app) as apps by src_ip
| eval ratio=round(out/(in+1),2), out_gb=round(out/1024/1024/1024,2)
| where out_gb > 1 AND ratio > 3
| sort - out_gb
```

### DNS abuse

DNS is abused both as a C2 channel and for exfiltration. Signals of DNS tunneling (tools like iodine and dnscat2, and DNS C2 modes in commercial frameworks) include:

- Very long subdomain labels.
- High Shannon entropy in query names.
- Unusually high query volumes to a single parent domain.
- Many unique subdomains under one domain.
- Heavy use of TXT or NULL record types.

Domain generation algorithm (DGA) malware shows up as bursts of NXDOMAIN responses for random-looking domains.

Also hunt for DNS that bypasses your internal resolvers:

- Hosts sending port 53 traffic directly to internet resolvers.
- DNS-over-HTTPS to public resolvers like 8.8.8.8, 1.1.1.1, or 9.9.9.9 on 443. This hides queries from your DNS logging entirely.

Most NGFWs can identify and block DoH, and you should consider doing so for managed endpoints.

### Protocol and port mismatches

NGFW application identification lets you catch traffic that doesn't match its port:

- Non-HTTP applications on 80/443.
- SSL/TLS on unusual high ports.
- SSH on 443.
- Traffic identified as "unknown-tcp," "unknown-udp," "incomplete," or "insufficient-data" going to external destinations.

Outbound use of protocols that should almost never leave your network is also a strong signal:

- SMB (which can leak NTLM hashes).
- RDP, LDAP, and raw SSH from workstations.
- Telnet.
- IRC.
- Large ICMP payloads (ICMP tunneling).
- Mining protocols like Stratum on mining-pool ports.

### Remote access tools and anonymizers

Attackers, especially ransomware affiliates, love legitimate remote monitoring and management tools because they blend in: AnyDesk, TeamViewer, ScreenConnect, Atera, Splashtop, NetSupport, and others. Hunt for RMM application traffic from hosts that aren't supposed to use them, or tools your organization doesn't sanction at all.

Similarly, look for:

- Tor traffic (NGFWs identify it, and Tor exit/relay lists are public).
- Commercial VPN clients.
- Web proxies.
- Tunneling tools such as ngrok, Cloudflare Tunnel from unexpected hosts, or Chisel.

### Lateral movement

This requires firewalls or segmentation between internal zones. The signals are:

- Workstation-to-workstation SMB, RDP, WinRM (5985/5986), WMI/DCOM (135 plus high RPC ports), or SSH. In most environments, workstations have no legitimate reason to administer each other.
- Administrative protocols originating from hosts that aren't jump servers or admin workstations.
- Sudden spikes in LDAP or Kerberos traffic to domain controllers from a single host, which suggests Active Directory enumeration with tools like BloodHound/SharpHound.

### Reconnaissance and scanning

Internal scanning is a high-fidelity signal, because a host scanning your internal network is either an authorized scanner or compromised:

- **Horizontal scans:** one source reaching many hosts on the same port.
- **Vertical scans:** one source reaching many ports on one host.

Denied traffic is useful here. A single host generating a burst of denies across many internal destinations stands out.

```spl
index=firewall src_zone=trust dest_zone=trust
| stats dc(dest_ip) as hosts dc(dest_port) as ports count by src_ip
| where hosts > 100 OR ports > 50
| lookup authorized_scanners src_ip OUTPUT src_ip as authorized
| where isnull(authorized)
```

### Hunting in denied traffic

Denies are often ignored as "the firewall did its job," but they're rich hunting ground. Look for:

- A host repeatedly trying to reach blocked destinations. Malware keeps retrying its C2 even when blocked, so the host is still infected.
- Repeated threat-signature hits on the same internal host.
- Denies to known-bad categories like malware, C2, or newly registered domains.

A block tells you the attempt failed, not that the infection is gone.

### TLS and certificate anomalies

With decryption or TLS metadata logging enabled, look for:

- Self-signed certificates on external servers.
- Certificates with very short or strangely long validity.
- Freshly issued certificates on newly registered domains.
- Mismatches between SNI and certificate subject.
- Known malicious JA3/JA3S or JA4 fingerprints, such as default configurations of offensive frameworks. Mature operators customize these.
- Default Cobalt Strike certificate artifacts, which lazy operators still leave in place.

### Geographic and ASN anomalies

Watch for:

- Traffic to countries your business has no presence in.
- Outbound connections to hosting-provider and VPS ASNs from hosts that normally only talk to major SaaS.
- VPN logins that show impossible travel.
- VPN logins from hosting ASNs, Tor, or residential proxy networks.

Be aware that sophisticated actors increasingly route through residential proxies and compromised home routers (so-called ORB networks, used notably by China-nexus groups) specifically to defeat geo and ASN heuristics.

### Servers that shouldn't talk out

Some systems rarely need internet access at all:

- Domain controllers
- Database servers
- Backup servers
- OT/ICS systems
- Hypervisor management interfaces

Build a list of them and hunt for any outbound internet connections they make. This is one of the highest signal-to-noise hunts there is, and a strong case for default-deny egress on those segments.

## Hunting the firewall itself

Firewalls and VPN gateways are now among the most targeted assets in any network. They're internet-facing, often lack EDR, have privileged network positions, and have suffered a string of critical, widely exploited vulnerabilities. Notable examples:

- **PAN-OS GlobalProtect:** CVE-2024-3400.
- **FortiOS SSL-VPN:** CVE-2022-42475 and CVE-2024-21762.
- **FortiOS authentication bypass:** CVE-2024-55591.
- **Cisco ASA ("ArcaneDoor" campaign):** CVE-2024-20353 and CVE-2024-20359.

State-sponsored groups like Volt Typhoon have built entire campaigns around living on edge devices. Check the CISA Known Exploited Vulnerabilities catalog for anything newer than my knowledge.

Hunting here means looking at the firewall's own logs and state:

- Admin logins from unexpected IPs or at odd hours.
- New or modified admin accounts.
- Unexpected config commits, especially new rules, NAT changes, or changes to logging.
- Log gaps, which may mean logging was disabled.
- Outbound connections originating from the firewall's management plane.
- Crashes or reboots that coincide with exploitation attempts.
- Brute-force or password-spraying patterns against the VPN portal.

Vendors often publish integrity-checking tools and specific indicators after major exploitation waves. Fortinet disclosed in 2025 that attackers had planted symlink-based persistence surviving patches, which shows why checking device integrity matters and patching alone isn't enough. Make sure management interfaces are never exposed to the internet.

## Analytic techniques

The main techniques are:

- **Stack counting (frequency analysis).** Count occurrences of a value across the environment and examine the rarest.
- **Baselining and statistical deviation.** Compare a host's behavior today to its own history, or to its peer group, using z-scores or percentiles.
- **Time-series analysis.** Catch spikes, off-hours activity, and periodicity.
- **Peer-group analysis.** Why is this one accounting laptop behaving differently from the other forty?
- **Graph and link analysis.** Visualize who talks to whom and find unusual bridges.
- **Machine learning and clustering.** Useful at scale, but it produces explainability challenges and needs a human to interpret.

Many hunters do exploratory work in Jupyter notebooks with pandas, pulling data out of the SIEM, before hardening the logic into saved searches.

## Pivoting and correlation

A firewall lead is rarely the end of an investigation. From a suspicious session, the typical pivot path is:

1. **DNS logs:** what domain resolved to that IP?
2. **Proxy logs:** what URLs and user agents were involved?
3. **EDR telemetry:** which process on the host made the connection? This is the single most important pivot, and it's why integrating firewall and endpoint data is so powerful.
4. **Identity logs:** who was logged in?
5. **Threat intelligence:** VirusTotal, GreyNoise, abuse.ch feeds (Feodo Tracker, URLhaus, ThreatFox), AlienVault OTX, Shodan/Censys to fingerprint the remote server, and passive DNS to see its hosting history.

Vendors increasingly do this stitching automatically. Examples are Palo Alto's Cortex XDR/XSIAM, Fortinet's FortiAnalyzer/FortiSIEM, and Microsoft's integration of network data into Defender. The underlying reasoning stays the same.

## Limitations and pitfalls

### Encryption

Most traffic is TLS, and TLS 1.3 encrypts more of the handshake. Encrypted Client Hello (ECH) is starting to hide the SNI. QUIC/HTTP3 runs over UDP and evades many inspection engines. A common mitigation is to block QUIC so browsers fall back to TCP/TLS, where the firewall can see more. Decryption helps enormously but brings privacy, legal, performance, and certificate-pinning complications.

### Trusted-service abuse

Attackers route C2 and exfiltration through services you can't block: Microsoft Graph/OneDrive, Google Drive, Slack, Discord, Telegram, GitHub, Dropbox, and CDNs like Cloudflare. At the IP/domain level this traffic looks legitimate, and you need behavioral or content-level signals to catch it. Domain fronting and CDN hosting also hide the true destination.

### Attribution problems

NAT, DHCP churn, VPN pools, and shared proxies break the link between an IP and a device unless you keep the mapping logs.

### Volume and cost

Logging all allowed sessions is expensive. Teams sometimes filter or sample, which directly degrades hunting capability. Tiered storage helps.

### False positives

Legitimate software is noisy: updaters, telemetry, backup agents, and vulnerability scanners. Good allowlists and asset context are the difference between a productive hunt and drowning.

### Sophisticated adversaries

Well-resourced actors deliberately mimic normal traffic, use jitter, operate during business hours, and use residential infrastructure. Firewall hunting catches the majority of adversaries, not all of them.

## Operationalizing results

Every hunt should produce something:

- A confirmed incident to respond to.
- A new or improved detection rule.
- A policy improvement.
- A documented negative result: "we looked for X across 90 days and found nothing," which is still valuable assurance.

Common policy improvements that come out of firewall hunting are:

- Default-deny egress for server segments.
- Blocking unsanctioned RMM tools, Tor, and DoH.
- Blocking or controlling uncategorized and newly registered domains.
- Adding internal segmentation.
- Enabling decryption for high-risk categories.
- Feeding hunt-derived indicators into external dynamic block lists.

Track metrics like hunts completed, detections created, mean time to detect, and coverage of ATT&CK techniques.

## Tools

These are the tools most commonly used alongside or with firewall data:

- **SIEMs and data platforms:** Splunk, Microsoft Sentinel, Elastic, Google SecOps, QRadar, Sumo Logic, plus data lakes for long-term cheap storage.
- **Vendor analytics:** Palo Alto Strata Logging Service/Cortex, Fortinet FortiAnalyzer, Check Point SmartEvent, Cisco Secure Firewall Management Center.
- **Open-source network analysis:** Zeek, Suricata, RITA/AC-Hunter for beaconing, Security Onion as an integrated platform, Arkime for full packet capture.
- **Threat intelligence:** MISP, OpenCTI, and commercial feeds.
- **Reference frameworks:** MITRE ATT&CK, the PEAK framework, Sigma rules (a vendor-neutral detection format with many network rules), and the SANS hunting resources.

## A practical starting plan

If you're starting from zero:

1. **Audit your logging.** Are allowed sessions logged, with bytes and application data, centralized, time-synced, and retained for 90+ days?
2. **Get asset and identity context** joined to the logs.
3. **Run the high-signal hunts first:**
   - Outbound traffic from servers that shouldn't have any.
   - Internal scanning.
   - Unsanctioned RMM and anonymizer use.
   - Direct-to-internet DNS.
   - Repeated denies to malicious categories.
4. **Move to the statistical hunts:** beaconing, rare destinations, and exfiltration ratios, building your allowlists as you go.
5. **Hunt your firewalls themselves**, especially against any vendor advisories affecting your platform.
6. **Convert each successful hunt into a scheduled detection**, then pick the next hypothesis from ATT&CK.

