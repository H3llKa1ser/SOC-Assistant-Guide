# Threat Hunting with DNS 

# Threat Hunting with DNS

DNS is one of the most productive hunting grounds because almost every stage of an intrusion touches it. Phishing lures, payload staging, C2, exfiltration, lateral discovery, and cloud abuse all tend to involve a name lookup. Attackers need infrastructure, and infrastructure needs names. DNS telemetry is also compact compared with full packet capture or proxy logs, so you can keep months of it. That long retention is what lets you establish baselines and hunt retrospectively when new intel lands.

The difficulty is that DNS is noisy, heavily cached, and routed through forwarders. It is increasingly encrypted, and most of it is benign machine traffic from CDNs, telemetry, and security products. Good DNS hunting is mostly about getting the right vantage point and suppressing noise intelligently.

---

## 1. Telemetry: where to collect and what you lose at each layer

**Endpoint telemetry** is the richest because it gives you **process attribution**.
- Sysmon Event ID 22 (DNSEvent) records the querying image, query name, status, and results.
- The Windows `Microsoft-Windows-DNS-Client` ETW provider gives similar data without Sysmon.
- Defender for Endpoint surfaces `DnsQueryResponse` in `DeviceEvents` (the query string is in `AdditionalFields`).
- Other EDRs have equivalents.

The catch is that the Windows DNS Client service caches lookups, and some tools cache or resolve on their own. So you see lookups, not connections, and not every lookup. Coverage is also limited to managed hosts.

**Resolver logs** give you the whole estate from one place, including unmanaged devices, servers, and appliances.
- Windows DNS Server analytical logging (ETW `Microsoft-Windows-DNSServer/Analytical`, collected via AMA into Sentinel's `ASimDnsActivityLogs`).
- BIND querylog, Unbound, Infoblox, and PowerDNS.

The main pitfall is forwarding chains. If branch resolvers forward to a central one, the central log shows the forwarder's IP, not the client's. Log at the tier closest to clients.

**Network sensors** see DNS on the wire regardless of which resolver was used. That includes hosts talking directly to 8.8.8.8, which is itself a finding.
- Zeek `dns.log` fields: `query`, `qtype_name`, `rcode_name`, `answers`, `TTLs`, `AA`, `RD`, `rejected`.
- Suricata EVE `dns` events and Corelight.

**Protective DNS and cloud resolvers** provide policy verdicts and category data alongside the queries.
- Cloudflare Gateway (export via Logpush), Cisco Umbrella, Infoblox Threat Defense, Zscaler.
- AWS Route 53 Resolver query logs, which GuardDuty also consumes for its DNS findings.
- Azure DNS and Private Resolver diagnostics, GCP Cloud DNS logging.
- CoreDNS logs in Kubernetes.

If you're already moving edge services onto Cloudflare, Gateway DNS logs can land in the same pipeline.

**Passive DNS** covers the outside world rather than your estate. It records historical resolutions across the internet and is essential for pivoting from an IOC to related infrastructure. Sources include DomainTools/Farsight DNSDB, Validin, SecurityTrails, CIRCL pDNS, and VirusTotal relations.

**Fields you want everywhere:**
- timestamp, client IP (and hostname/user via enrichment)
- query name, qtype, rcode
- answers, TTL
- the process where available
- the resolver used

Normalise them into one schema so hunts don't have to be rewritten per source. ASIM `_Im_Dns`, Elastic ECS `dns.*`, and OCSF DNS Activity all serve this purpose.

---

## 2. How adversaries use DNS (and the ATT&CK mapping)

| Abuse | What it looks like | ATT&CK |
|---|---|---|
| C2 over DNS / tunneling | Data encoded in subdomains, returned in TXT/NULL/CNAME/AAAA answers (iodine, dnscat2, Cobalt Strike DNS beacons, Sliver, DNSExfiltrator) | T1071.004, T1572 |
| Exfiltration over DNS | High-volume unique subdomains under one parent domain | T1048 |
| Domain generation algorithms | Bursts of algorithmic names, mostly NXDOMAIN | T1568.002 |
| Fast flux / double flux | Many A records, very low TTLs, rotating IPs or name servers | T1568.001 |
| Staging on fresh infrastructure | Newly registered or newly observed domains, cheap TLDs | T1583.001 |
| Abuse of trusted services | Dynamic DNS (duckdns, no-ip), tunnels (ngrok, trycloudflare), serverless (workers.dev, pages.dev, azurewebsites), paste/CDN sites (pastebin, raw.githubusercontent, cdn.discordapp) | T1102, T1583 |
| Phishing / brand impersonation | Typosquats, combosquats (`brand-login-secure.com`), homoglyphs/punycode (`xn--`) | T1583.001, T1566 |
| DNS infrastructure compromise | Hijacked NS/A records at registrar or DNS provider (Sea Turtle, DNSpionage) | T1584.002 |
| Subdomain takeover | Your CNAMEs pointing at deprovisioned cloud resources | T1584.001 |
| Internal discovery | SRV lookups for `_ldap._tcp.dc._msdcs`, PTR sweeps, AXFR attempts | T1018, T1590.002 |
| Name-resolution poisoning | LLMNR/NBT-NS/mDNS/WPAD responses from non-servers (Responder) | T1557.001 |
| DNS rebinding | Public domain resolving to RFC1918 or loopback addresses | T1071 |
| Resolver bypass | Clients using external resolvers or DoH/DoT to evade monitoring | T1572, T1071.004 |

---

## 3. Hunt hypotheses and techniques

### 3.1 DNS tunneling and exfiltration

Tunnels must pack data into labels, and a label is capped at 63 characters and a full name at 253. They also need unique names to defeat caching. Look for these signals:
- **Long query names.** Total length over ~50–60 characters, or individual labels over ~30.
- **High entropy in the subdomain portion.** Shannon entropy above ~3.5–4 for base32/base64 encodings.
- **Unique subdomain count per registered domain per host.** This is the strongest single signal: a host generating hundreds or thousands of distinct subdomains under one eTLD+1 in an hour.
- **Unusual record types.** High TXT/NULL/CNAME volume, or any NULL queries at all.
- **Total query bytes per domain per host over time**, which catches slow exfil.
- **Many unique names but no matching TCP/UDP flows** to the answered IPs.

Always compute the registered domain using the Public Suffix List, not "last two labels." Otherwise `co.uk`, `com.mt`, and similar suffixes break the math. Splunk's URL Toolbox, Python's `tldextract`, and ASIM parsers all handle this.

Benign lookalikes you must allowlist: AV and reputation lookups (McAfee GTI, Sophos, ESET, and others encode hashes in subdomains), DNSBL/RBL queries from mail servers, `*.akamaiedge`, Apple/Microsoft/Google telemetry, and ad-tech. Build the allowlist on registered domains and review it periodically. Attackers know people allowlist whole CDNs.

```spl
index=dns sourcetype=zeek:dns
| lookup ut_parse_extended_lookup url AS query
| eval sub=replace(query, "\.".ut_domain."$", "")
| eval sublen=len(sub)
| `ut_shannon(sub)`
| stats dc(query) AS uniq_names avg(sublen) AS avg_len avg(ut_shannon) AS avg_entropy
        values(qtype_name) AS qtypes BY id.orig_h ut_domain
| where uniq_names > 200 AND avg_len > 20 AND avg_entropy > 3.5
| sort - uniq_names
```

### 3.2 Beaconing

Implants check in periodically. DNS shows this in two ways: the lookups themselves, and the connection pattern to the resolved IPs.

The standard method:
- Compute inter-arrival times per (host, domain) pair.
- Score regularity using the coefficient of variation (stddev/mean), Bowley skewness, and median absolute deviation.
- Weight by connection count and time coverage.

RITA from Active Countermeasures implements this well against Zeek logs.

Caching distorts the picture. A beacon to a domain with a 300-second TTL may produce one lookup every 5 minutes regardless of the true sleep. Very low TTLs, around 60 seconds or less, on low-reputation domains are therefore interesting in their own right. Pair DNS with connection logs to see the true cadence. Jittered beacons (for example Cobalt Strike with 30% jitter) lower regularity scores but still stand out over long windows.

### 3.3 DGAs and NXDOMAIN storms

Malware using a DGA queries many candidate names until one resolves. That produces:
- A single host with a burst of NXDOMAINs to names that have never been seen before.
- High character entropy and low bigram likelihood against English or your baseline corpus.
- Unusual consonant/vowel ratios and digit mixing.

Dictionary DGAs (Suppobox, Matsnu, Gozi variants) concatenate real words and defeat entropy checks. For those, rely on the NXDOMAIN rate per host and the novelty of names, or use ML classifiers (LSTM/character CNN models trained on DGArchive-style data). Mark Baggett's `freq.py` is a cheap, effective frequency-score tool.

```kql
// Hosts with abnormal NXDOMAIN bursts (ASIM)
_Im_Dns(starttime=ago(1d), responsecodename="NXDOMAIN")
| summarize nx=count(), uniq=dcount(DnsQuery) by SrcIpAddr, bin(TimeGenerated, 10m)
| where uniq > 50
| join kind=leftouter (
    _Im_Dns(starttime=ago(14d))
    | summarize baseline=avg(1.0) by SrcIpAddr) on SrcIpAddr
| order by uniq desc
```

### 3.4 Rarity and novelty ("least frequency of occurrence")

This is the most reliable general-purpose DNS hunt:
- Take every registered domain seen today.
- Subtract everything seen in the previous 30–90 days.
- Look at what resolved from very few hosts.

Commodity malware, targeted implants, and phishing clicks all sit in this long tail. Enrich what remains with:
- **Domain age** from WHOIS/RDAP (under 30 days is highly suspicious).
- **TLD** (`.top`, `.xyz`, `.click`, `.shop`, `.zip`, `.mov`, `.su`, `.icu` and similar are disproportionately abused).
- **Hosting ASN.** Bulletproof or cheap VPS ranges are a signal.
- **Certificate Transparency first-seen.**
- **Protective DNS category.**

Then triage by how many hosts queried it and which processes did.

### 3.5 Process-level anomalies (endpoint DNS)

With Sysmon 22 or EDR DNS events, you can ask which binaries should be resolving external names at all. High-yield patterns:
- LOLBins resolving rare domains: `rundll32`, `regsvr32`, `mshta`, `msbuild`, `installutil`, `certutil`, `bitsadmin`, `wscript`/`cscript`, `powershell`.
- Office apps or PDF readers resolving newly seen domains, which suggests a document payload.
- Non-browser processes resolving paste sites, GitHub raw, Discord CDN, Telegram API, ngrok, or trycloudflare.
- Processes running from `%TEMP%`, `%APPDATA%`, `ProgramData`, or user Downloads making any external lookups.
- `lsass`, `svchost` with odd command lines, or signed-but-unexpected binaries resolving rare domains.

```kql
DeviceEvents
| where Timestamp > ago(7d) and ActionType == "DnsQueryResponse"
| extend q = tostring(parse_json(AdditionalFields).DnsQueryString)
| where InitiatingProcessFileName in~ ("rundll32.exe","regsvr32.exe","mshta.exe","msbuild.exe",
        "certutil.exe","wscript.exe","cscript.exe","powershell.exe","winword.exe","excel.exe")
| summarize hosts=dcount(DeviceId), first=min(Timestamp) by q, InitiatingProcessFileName
| where hosts <= 3
| order by first desc
```

### 3.6 Resolver bypass and encrypted DNS

If hosts can resolve without you seeing it, every other hunt has a blind spot. Hunt for:
- **Direct UDP/TCP 53 to external IPs** from anything other than your resolvers, visible in firewall and flow logs.
- **DoT on TCP 853.**
- **DoH to known endpoints** (`dns.google`, `cloudflare-dns.com`, `1.1.1.1`, `9.9.9.9`, `doh.opendns.com`, NextDNS) from non-browser processes or from servers. Browsers can be managed by policy. Honouring the canary domain `use-application-dns.net` disables Firefox's automatic DoH.
- **Traffic to public DoH resolver IPs on 443**, which you can match via SNI/JA3/JA4 even without decryption.

The durable fix is architectural: force DNS through your resolvers, block outbound 53/853, and restrict known DoH endpoints. Then any bypass attempt becomes a detection.

### 3.7 Response-side anomalies

Most hunters only look at queries, but the answers carry signal too:
- **Fast flux:** many A records, TTLs under about 300 seconds, IPs spread across many ASNs or countries, answers rotating between queries.
- **Rebinding:** external domains answering with RFC1918, `127.0.0.0/8`, or link-local addresses.
- **Sinkhole and parking IPs** in answers, which reveal infected hosts still calling dead C2.
- **Answers landing in ASNs or IPs from threat intel** even when the domain looks innocent.
- **CNAME chains** ending in abused hosting (`*.azurewebsites.net`, `*.herokuapp.com`, `*.r2.dev`).

### 3.8 Lookalikes and brand impersonation

For an operator running several consumer brands, this is extremely high-value because phishing and credential harvesting almost always use lookalike domains.
- Generate permutations of every brand with `dnstwist` or `urlcrazy`: typos, bitsquats, homoglyphs, TLD swaps, and combo words like `login`, `bonus`, `verify`, `casino`, `bet`, `promo`.
- Watch Certificate Transparency via certstream or crt.sh for new certificates containing brand strings.
- Check passive DNS and new-registration feeds.
- Hunt internal DNS for employees resolving these names, since that indicates phishing clicks.
- Look for punycode (`xn--`) names that render like your brands.

Feed confirmed lookalikes into blocklists and takedown workflows. They also serve as useful context for account-takeover investigations.

### 3.9 Internal reconnaissance and poisoning

- **SRV queries** for `_ldap._tcp`, `_kerberos._tcp`, or `_gc._tcp` from hosts that don't normally do AD discovery. BloodHound/SharpHound and AD enumeration tools generate these, as do new implants mapping the domain.
- **Mass PTR lookups** from one host, meaning reverse-resolving a subnet. That is a classic sign of scanning (nmap does this by default).
- **AXFR/IXFR attempts** from non-secondary servers.
- **WPAD, LLMNR, NBT-NS, or mDNS responses** coming from workstations. Responder and Inveigh answer these. Better still, disable LLMNR and NBT-NS and alert on any traffic.
- **Queries for non-existent internal hostnames** at volume, such as typos or honeytoken names. Canary DNS records are a cheap, high-fidelity tripwire.

### 3.10 Hunting your own DNS infrastructure

Attackers also target the zones you own. Hunt for:
- **Unexpected changes** to NS, MX, A, TXT (SPF/DMARC), or CAA records. Diff zones daily and monitor registrar and DNS-provider audit logs.
- **Dangling CNAMEs** to deprovisioned S3 buckets, Azure App Service, CloudFront, GitHub Pages, or Heroku, which enable subdomain takeover. Enumerate your zones and check that each target still exists and is still yours.
- **Registrar lock, DNSSEC, and 2FA** on registrar accounts. Hijacking campaigns like Sea Turtle succeeded by abusing registrar and provider access.
- **Certificates issued for your domains** that you didn't request (CT monitoring).

---

## 4. Pivoting with passive DNS and intel

Once you have one suspicious domain or IP, expand outward.

From a domain, pull:
- historical A/AAAA answers and the IPs involved
- co-hosted domains on those IPs, filtered to low-density hosting because shared hosting is useless for this
- the name servers used, plus other domains on the same, often uncommon, NS pair
- SOA email, registrant or registrar patterns
- registration timing clusters
- certificate reuse (same SAN sets, same JARM/JA4S fingerprints)
- identical page hashes via urlscan

Tools for this work include DomainTools Iris, Validin, SecurityTrails, VirusTotal graph, urlscan, Censys, Shodan, and MISP/OpenCTI for tracking what you find.

The goal is to find infrastructure the adversary hasn't used against you yet and block it preemptively. Then go back through your own DNS logs for any historical hits against the expanded set.

---

## 5. Pitfalls that wreck DNS hunts

- **Caching** hides frequency and repeat lookups, so combine DNS with flow data.
- **Forwarders and NAT** hide the true client. Collect as close to the endpoint as possible and enrich with DHCP and asset data.
- **Naive domain parsing** without the Public Suffix List corrupts every aggregate.
- **Over-broad allowlists** (whole CDNs, `*.amazonaws.com`, `*.azurewebsites.net`) are exactly where attackers live.
- **QNAME minimisation** at upstream resolvers means upstream logs may only show partial names. Your own resolver or endpoint logs are authoritative.
- **Encrypted DNS** silently erodes visibility unless you enforce resolver policy.
- **Volume.** Aggregate early (per host, per registered domain, per hour), keep raw data for a shorter window, and keep summaries for longer to support baselining.
- **Split-horizon DNS and internal TLDs** (`.local`, `.corp`, `.internal`) must be excluded or handled separately, or they will dominate your rare-domain lists.
- **IPv6.** Don't forget AAAA answers and hosts preferring v6 paths that bypass your v4 controls.

---

## 6. Tooling cheat sheet

| Purpose | Tools |
|---|---|
| Collection and analysis | Zeek, Suricata, Security Onion, Corelight, Sysmon, Elastic/Splunk/Sentinel |
| Beaconing analysis | RITA (Zeek-based) |
| Scoring | `freq.py`, `tldextract`, DGA ML classifiers |
| Lookalike generation | `dnstwist`, `urlcrazy` |
| Certificate monitoring | certstream, crt.sh |
| Enrichment | passive DNS providers, WHOIS/RDAP, threat intel feeds, protective DNS verdicts |
| Detection content | Sigma DNS rules (SigmaHQ `dns_query` category), Elastic and Sentinel content hubs |

---

## 7. Turning hunts into a program

A mature approach runs hypothesis-driven hunts on a cadence:
- rare domains weekly
- tunneling and DGA checks daily
- beaconing over rolling 24-hour and 7-day windows
- lookalike sweeps continuously

Each confirmed finding should produce three things:
1. A detection rule, with tuned thresholds and a maintained allowlist.
2. A response action: RPZ or protective-DNS sinkhole or block, isolation, and credential resets where relevant.
3. An intel update from the pivot results.

Track coverage by ATT&CK technique and by telemetry source, since gaps in DNS visibility are usually the first thing to fix. A useful maturity check: can you answer "which process on which host resolved X, when, and what did it connect to next?" for any domain over the last 90 days? If you can, you have a genuinely strong DNS hunting capability.
