# Threat Hunting with IPS/IDS

# Threat Hunting with IPS/IDS

## The foundations: what IDS and IPS actually are

An **Intrusion Detection System (IDS)** watches traffic or host activity and raises alerts when something looks malicious. An **Intrusion Prevention System (IPS)** does the same job but sits inline, so it can drop packets, reset connections, or block sources in real time. The core technology is often identical. Suricata, for example, can run in either mode, and the difference is mostly deployment. An IDS typically gets a copy of traffic through a SPAN/mirror port or a network TAP. An IPS sits directly in the traffic path, which means it can stop attacks but also adds latency and becomes a potential point of failure. That is why many organizations run IPS in "detect-only" mode on some rules.

Several distinctions matter for hunting:

- **Network vs. host sensors.** Network-based systems (NIDS/NIPS) see packets on the wire. Host-based systems (HIDS/HIPS, such as OSSEC or Wazuh) see file changes, process activity, and logs on endpoints. Network sensors give you breadth across many hosts. Host sensors give you depth, especially for encrypted traffic you can't inspect on the wire.
- **Detection methods.** Signature-based detection matches known patterns: byte sequences, protocol fields, known-bad domains. It is precise but blind to novel attacks. Anomaly-based detection builds a baseline of normal behavior and flags deviations, which catches unknowns but produces more noise. Stateful protocol analysis checks whether traffic conforms to how a protocol should behave, such as an HTTP request with impossible header structure or DNS responses that don't match queries.

## Hunting vs. alert triage: the key mindset shift

Traditional IDS/IPS work is reactive. A rule fires, an analyst triages it. Threat hunting flips this. It is proactive, iterative, and assumes breach: you start from the premise that an attacker is already inside and evaded your automated detections, and you go looking for them.

That means the IDS stops being just an alarm system and becomes a **data source and a hunting instrument**. The most valuable hunting data from a modern IDS is often not the alerts at all. It is the protocol metadata the sensor logs for *all* traffic. Suricata's EVE JSON output can record every DNS query, HTTP request, TLS handshake, file transfer, and flow, whether or not a rule fired. Zeek (formerly Bro), which is technically a network security monitor rather than a signature IDS, is built almost entirely around this kind of rich metadata logging and is a staple of network hunting.

## The data an IDS/IPS gives a hunter

It helps to think in layers of fidelity:

1. **Alerts.** These include the high-severity ones everyone watches and, more interestingly for hunters, the huge volume of low-severity, informational, and policy alerts that nobody triages.
2. **Protocol and flow metadata.** This covers DNS queries and answers, HTTP hosts/URIs/user agents, TLS SNI and certificate details, JA3/JA4 client and server fingerprints, SMB and DCE-RPC activity, file hashes, and flow records with byte counts, durations, and packet counts.
3. **Full packet capture (PCAP).** This is the ground truth. It is expensive to store, so usually retained for days rather than months. Tools like Arkime (formerly Moloch) index PCAP so you can search and pivot through it.

The hunter's usual workflow moves from cheap, wide data (metadata) to expensive, deep data (PCAP) as a lead gets more interesting.

## Hunting methodologies and frameworks

Hunts generally follow one of three approaches. **Hypothesis-driven** hunts start from a theory about attacker behavior, usually grounded in MITRE ATT&CK. An example: "If an attacker is using DNS tunneling for command and control, we'd see unusually long, high-entropy subdomains to a small number of parent domains." **Intelligence-driven** hunts start from threat intel, such as a report on a campaign targeting your sector, with its indicators and TTPs. **Situational or entity-driven** hunts focus on crown-jewel assets or high-risk users, asking what abnormal activity touches the systems that matter most.

Several frameworks structure this work:

- **The Pyramid of Pain** (David Bianco) reminds you that hunting on hashes and IPs is easy for attackers to evade. Hunting on tools and TTPs costs them far more. IDS signatures often live at the low end of the pyramid, so good hunters push toward behavioral patterns.
- **The Hunting Maturity Model** (HMM0 through HMM4, originally from Sqrrl) describes progression from relying purely on automated alerts to fully automating successful hunt procedures.
- **Hunt processes** such as Splunk's PEAK framework (Prepare, Execute, Act with Knowledge) and the TaHiTI methodology formalize the lifecycle of scoping, hunting, documenting, and handing off.
- **MITRE ATT&CK** is the lingua franca for mapping what you're hunting to adversary techniques and identifying coverage gaps.

## Core hunting techniques using IDS data

**Stack counting and least-frequency analysis** is the workhorse technique. You aggregate a field (user agents, JA3 hashes, destination ports, DNS domains, TLS certificate issuers) across your whole environment and look at the rare values. Malware and attacker tools often stand out because they're the only thing on the network doing something a particular way. A query over Suricata DNS logs in a SIEM might look something like this:

```
index=suricata event_type=dns dns.type=query
| stats count dc(src_ip) as hosts by dns.rrname
| where hosts <= 2
| sort count
```

**Mining low-severity alerts** is underrated. Individually, alerts like "ET INFO" or policy-category signatures are noise. But clustering them by host, looking for a single machine that triggers many unrelated low-severity rules, or sequencing them in time can reveal an intrusion that no single high-severity alert caught. Emerging Threats even publishes an "ET HUNTING" rule category designed specifically for this: rules that are too noisy to page anyone but useful to hunt through.

**Beaconing detection** targets command-and-control. Implants tend to call home at regular intervals, often with added jitter. You look for connections from an internal host to the same external destination with consistent intervals, similar packet sizes, and long total duration. RITA (Real Intelligence Threat Analytics) automates this analysis over Zeek logs, and similar logic can be built over Suricata flow data.

**DNS hunting** is one of the richest areas. You're looking for several signs:

- Very long or high-entropy subdomains, which suggest tunneling or exfiltration.
- Algorithmically generated domains (DGAs).
- Spikes in NXDOMAIN responses, which can indicate DGA malware cycling through dead domains.
- Unusual record types like large TXT responses.
- Newly registered domains.
- Internal hosts bypassing your approved resolvers to talk directly to external DNS or DNS-over-HTTPS providers.

**TLS hunting** matters because most traffic is encrypted, but the handshake still leaks a lot. JA3 and the newer JA4 family fingerprint how clients and servers negotiate TLS, and known malware families and offensive frameworks have recognizable fingerprints. You can also hunt for:

- Self-signed or very short-lived certificates.
- Certificates with default or odd subject fields.
- SNI values that don't match certificate names.
- TLS sessions with no SNI to raw IP addresses.

**HTTP hunting** looks for rare or malformed user agents, POST requests directly to IP addresses, unusual URI patterns, executables or scripts downloaded from uncategorized domains, and missing headers that real browsers always send.

**Lateral movement hunting** focuses on east-west traffic, which requires sensors placed inside the network, not just at the perimeter. Signs worth pursuing include:

- Workstations talking SMB, RDP, WinRM, or DCE-RPC to other workstations.
- Remote service creation or scheduled-task activity visible in SMB/DCE-RPC traffic.
- Admin shares being accessed.
- Kerberos anomalies.
- A single host suddenly scanning internal subnets.

**Exfiltration hunting** looks at byte ratios, meaning hosts that suddenly upload far more than they download. It also covers large transfers to cloud storage or unusual destinations, transfers at odd hours, and data leaving over protocols not normally used for bulk transfer.

**Protocol/port mismatch** hunting finds traffic where the protocol detected by the sensor doesn't match the port, such as SSH on 443 or HTTP on a high random port. Suricata and Zeek identify protocols dynamically rather than trusting port numbers, which makes this straightforward.

**Retro-hunting** is a powerful IDS-specific technique. When new threat intel or a new signature is released, you replay stored PCAP through the IDS with the new rules. That answers "were we hit by this before anyone knew to look for it?"

**Revisiting suppressed and disabled rules** is also worth doing. Over time, teams silence noisy rules. Attackers benefit from that silence, so periodically hunting through what you've tuned out is legitimate and productive.

## Writing rules for hunting

Hunters often write custom signatures that are deliberately broad, intended to generate leads rather than confident alerts. Here's an illustrative Suricata rule that flags HTTP POSTs sent directly to an IP address rather than a hostname, a common trait of cheap malware and staging infrastructure:

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HUNT Outbound HTTP POST to raw IP host"; flow:established,to_server; http.method; content:"POST"; http.host; pcre:"/^\d{1,3}(\.\d{1,3}){3}(:\d+)?$/"; classtype:policy-violation; sid:9000001; rev:1;)
```

Useful rule features for hunting include:

- **`flowbits`**, which track state across multiple packets or events. For example, you can alert only if a download is followed by a callback.
- **Thresholds and detection filters**, which reduce noise.
- **Dataset and IP reputation lists**, for matching against large indicator sets efficiently.
- **Lua scripting**, for logic too complex for standard rule keywords.

For hunts that run in a SIEM rather than on the sensor, **Sigma** is the vendor-neutral format for writing detections that can be converted into Splunk, Elastic, Sentinel, and other query languages.

## Tooling landscape

On the open-source side:

- **Suricata** is multi-threaded and has excellent protocol logging.
- **Snort 3** is the modernized version of the original IDS, with Cisco Talos rules.
- **Zeek** provides metadata and scripting.
- **Security Onion** is a full distribution bundling Suricata, Zeek, full packet capture, and a hunting interface built on Elastic.
- **Arkime** handles indexed PCAP search.
- **RITA** does beacon and C2 analysis.

For rule content, the main sources are Emerging Threats (ET Open is free, ET Pro is commercial), Talos rulesets, and community sources. Commercial IPS capabilities are usually built into next-generation firewalls and dedicated platforms from vendors like Palo Alto Networks, Fortinet, Cisco (Firepower/Secure Firewall), Check Point, and Trellix. In practice, their logs feed into a SIEM or XDR platform where the actual hunting happens.

## Limitations and pitfalls

- **Encryption** is the biggest challenge. Payload signatures are useless against TLS unless you do TLS inspection, which brings privacy, legal, performance, and certificate-pinning complications. This is why handshake metadata, flow behavior, and endpoint telemetry have become so important.
- **Sensor placement** determines what you can see. A sensor only at the internet edge is blind to lateral movement. Cloud workloads need cloud-native traffic mirroring or different tools entirely. A sensor dropping packets under load silently loses visibility, so monitoring sensor health is itself part of hunting hygiene.
- **Evasion techniques** can slip past poorly configured sensors. These include fragmentation, overlapping segments, encoding tricks, and traffic shaped to exploit differences between how the sensor and the target reassemble streams. Proper stream reassembly and protocol normalization settings matter.
- **Noise and alert fatigue** can bury real signals, which is exactly why hunting emphasizes aggregation and rarity over individual alerts.
- **IPS blocking can tip off an attacker.** It can cause them to change infrastructure before you've scoped the intrusion. During an active investigation, teams sometimes deliberately watch rather than block.

## The hunt lifecycle and turning hunts into value

A mature hunt runs roughly like this:

1. Form a hypothesis tied to an ATT&CK technique or intel.
2. Identify which data sources can confirm or refute it, and check that they exist and are complete.
3. Execute the analysis, starting broad and pivoting deeper.
4. Investigate leads down to PCAP or endpoint data.
5. Document everything, including negative results.
6. Hand off confirmed incidents to incident response.

The final and most important step is converting what you learned into **automated detections**: new IDS rules, SIEM correlation searches, or tuning. A successful hunt should mean nobody ever has to manually hunt for that specific thing again. Useful metrics include new detections created, visibility gaps discovered and fixed, dwell time reduced, and ATT&CK coverage improved. Counting "incidents found" is less useful, since a good hunt that finds nothing still proves something.

## A quick example hunt

Suppose intel suggests attackers in your sector are using DNS tunneling for C2. Your hypothesis is that a compromised host would generate many queries with long, random-looking subdomains under one parent domain. You pull a week of DNS logs from Suricata or Zeek, calculate subdomain length and entropy, and group by parent domain. You then filter out known-legitimate high-entropy services like CDNs and security vendor lookups. You find one workstation making thousands of queries to a domain registered twelve days ago. You pivot to that host's flow data and see a regular query cadence. You retrieve PCAP showing encoded payloads in TXT responses, then escalate to IR. Finally, you write a Suricata rule and a SIEM detection for the pattern so it's caught automatically next time.

## Getting good at it

The skills that make someone effective here include:

- Deep knowledge of network protocols. Reading packets in Wireshark fluently is essential.
- A solid understanding of what "normal" looks like in your specific environment.
- Familiarity with attacker tradecraft through ATT&CK and threat reports.
- Comfort with a query language (SPL, KQL, EQL, or Lucene).
- Enough statistics to reason about baselines and outliers.

Good ways to practice include running Security Onion in a home lab, working through public PCAP challenge sites (malware-traffic-analysis.net is a long-standing favorite), and replaying samples through Suricata to see what fires and what doesn't.

