# Threat Hunting for C2 with RITA

RITA is a free, open-source network threat hunting framework from Active Countermeasures, the company that grew out of Black Hills Information Security, with Chris Brenton and John Strand as its best-known advocates. The name actually stands for Real Intelligence Threat **Analytics**, not Analysis. It does one thing well: it ingests Zeek network logs and uses statistics to find hosts that behave like they are under remote control. It is not an IDS. It doesn't use signatures to catch "known bad." It looks for the behavioral shape of command-and-control (C2): regular check-ins, persistent sessions, and data smuggled through DNS. That approach still works when the payload is encrypted and the domain is brand new.

Below is the full picture: architecture, detection logic, workflow, tuning, evasion, and how to practice.

---

## 1. Why C2 hunting works at the network layer

Every piece of malware that needs instructions has to "phone home," and that creates patterns that are hard to hide completely:

1. **Timing.** Implants sleep, wake, check in, and sleep again. Even with jitter, the intervals cluster statistically.
2. **Size.** Idle check-ins ("anything for me?" / "no") produce very consistent request and response sizes.
3. **Persistence.** Some C2 holds a single session open for hours or days instead of polling.
4. **Protocol abuse.** DNS tunneling produces huge numbers of unique subdomains under one parent domain.
5. **Rarity.** Few internal hosts talk to the destination, and the destination is new to your environment.

Encryption hides content, but it doesn't hide timing, volume, duration, or who-talks-to-whom. RITA exploits exactly that gap. It also covers something endpoint tools miss: devices with no EDR, like IoT, printers, appliances, and unmanaged systems, which still show up on the wire.

---

## 2. Architecture and versions

**Data source:** RITA doesn't capture packets itself. It relies on **Zeek** (formerly Bro), which turns raw traffic into structured logs. The logs that matter are `conn.log` (the core), `dns.log`, `http.log`, and `ssl.log`. Version 5 also uses Zeek's `open_conn`, `open_http`, and `open_ssl` logs so it can see connections that are still in progress, which matters for long-lived C2.

**Version history:**
- **v4 and earlier:** Go binary with a MongoDB backend. You ran `rita import`, then `rita show-beacons` and similar commands, or generated HTML reports.
- **v5 (released 2024):** A complete rewrite. RITA was entirely restructured, with a complete overhaul of its underlying storage system and significant improvements in how it analyzes and displays data. The backend moved to ClickHouse, a columnar database that is much faster at this kind of aggregation. The HTML reports were replaced by an interactive terminal UI. With this release, just about everything runs in a Docker container, which makes the code far more portable, so OS changes should be far less of an issue.

**Commercial sibling:** AC-Hunter (formerly AI-Hunter) uses the same concepts, with a GUI, continuous ingestion, threat scoring, and team workflows. There is also a Community Edition.

---

## 3. Sensor placement (where most deployments fail)

RITA can only analyze what Zeek sees, so where you put the sensor matters more than any setting.

- **Put the sensor inside the NAT/firewall.** If you capture outside the NAT, every internal host collapses into one public IP, and you can't tell which workstation is beaconing.
- **Mind the proxies.** If traffic goes through an explicit web proxy, a sensor behind the proxy sees every host talking only to the proxy. Either capture on both sides of it, or rely on HTTP Host headers and TLS SNI to attribute destinations. RITA v5's FQDN beaconing, covered below, partly addresses this.
- **Capture both directions** through a TAP or SPAN port. Asymmetric capture breaks the byte counts and connection state.
- **Keep at least 24 hours of data.** Long sleep intervals (hourly, every six hours) can't be detected statistically in a two-hour sample. Active Countermeasures has long recommended analyzing 24-hour chunks as a minimum.
- **Watch the internal DNS resolver.** If all clients query through one internal resolver, a sensor at the perimeter only sees the resolver talking to the internet. Capture where client queries are visible too.

---

## 4. Installing and running v5

Installation is a script-driven process. In short, you download the install tarball and extract the contents, run the install script specifying where RITA and Zeek should be installed, and select a network interface where Zeek should monitor traffic.

```bash
wget https://github.com/activecm/rita/releases/download/<version>/rita-<version>.tar.gz
tar -xzvf rita-<version>.tar.gz
cd rita-<version>-installer
./install_rita.sh localhost   # or a remote host to deploy to
```

Because Zeek runs in a container, what you actually interact with is a script called "zeek" which interconnects with the container running Zeek. You can process a PCAP with it the same way you would with native Zeek (`zeek -r capture.pcap`).

A typical workflow looks like this (flag names may change between releases, so check `rita --help`):

```bash
rita import --database hunt_0928 --logs /opt/zeek/logs/2026-09-28/
rita import --database sensor1 --logs /opt/zeek/logs/ --rolling   # continuous/rolling dataset
rita list                        # list datasets
rita view hunt_0928              # interactive TUI
rita view --stdout hunt_0928 > results.csv   # export for SIEM/spreadsheet
rita delete hunt_0928
```

Rolling datasets let you keep feeding hourly Zeek logs into one database and age out old data, which is how you get near-continuous hunting rather than one-off analysis.

Configuration lives in a config file (`config.hjson` in v5; it was `rita.yaml` in v4). It defines internal subnets, always-include and never-include lists for IPs, CIDRs, and domains, threat intel feeds, and scoring thresholds.

---

## 5. The detections in detail

### 5.1 Beacon analysis (the flagship)

For every internal-to-external pair, RITA collects all connection timestamps and byte counts and scores how machine-like they are. The score runs from 0 to 1, and it is built from several components.

**Timestamp component.** RITA computes the intervals between successive connections, then looks at:
- **Skewness.** RITA uses a quartile-based measure (Bowley skewness) rather than a mean-based one, so outliers such as a missed check-in or a laptop sleeping don't wreck the score. A symmetric interval distribution looks mechanical.
- **Dispersion.** The Median Absolute Deviation of the intervals. A low MAD means tight, regular timing.
- **Connection count** relative to the dataset's time span. A 60-second beacon over 24 hours should produce roughly 1,440 connections.

**Data size component.** The same statistics applied to bytes per connection: skew, MAD, and how dominant the most common size is. Idle C2 check-ins are remarkably uniform in size.

**Duration and histogram components.** These were added in later versions to handle jitter and long sleeps. RITA buckets connections across the dataset (for example, by hour) and asks whether the activity is spread consistently across the whole window, the way malware behaves, rather than bunched into business hours, the way humans behave. The histogram approach also catches bimodal or jittered patterns that defeat a simple interval-regularity check. For example, a Cobalt Strike beacon with a 60-second sleep and 30% jitter won't have perfect intervals, but it will still fire steadily around the clock.

**Three kinds of beacon:**
- **IP beacons:** source to destination IP.
- **FQDN/SNI beacons:** source to hostname, taken from DNS, the HTTP Host header, or the TLS SNI. This catches C2 behind CDNs and cloud front-ends where the destination IP rotates constantly but the hostname doesn't. It also partly covers the proxy scenario.
- **Proxy beacons:** in v4 these were a separate analysis, for traffic to an explicit proxy where HTTP `CONNECT` targets reveal the true destination.

**Interpreting scores.** A score around 0.7 or higher deserves a look. Scores in the high 0.8s and 0.9s are very regular and are usually either C2 or legitimate automation, such as update checkers, telemetry, NTP, or monitoring. Deciding which one it is, is the hunter's job.

### 5.2 Long connections

Some C2, especially reverse shells, SSH tunnels, and websocket or long-poll channels, holds a single connection open instead of polling. RITA sums the duration per pair and flags pairs with very long total or single-session durations. In v5, open-connection logs mean you can see a tunnel that has been up for 30 hours even though Zeek hasn't closed and logged it yet. A workstation holding a nine-hour TCP session to a VPS in an unfamiliar ASN is a classic finding.

### 5.3 DNS tunneling and DNS-based C2

Tools such as dnscat2, iodine, and DNS beacons in commercial frameworks encode data into subdomains. RITA counts **unique subdomains per base domain**. A normal domain might have a few dozen subdomains; a tunnel generates thousands of random-looking labels (`a8f3e9c1.x.evil.com`). High counts under an obscure domain are a strong signal. Expect benign offenders too: CDNs, anti-virus cloud lookups, and some telemetry services are well known for this.

v5 also flags **C2 over DNS / direct DNS connections**, meaning internal hosts that query external resolvers directly instead of using your internal DNS. That behavior is itself suspicious in most corporate networks.

### 5.4 Strobes / large number of connections

In v4, a pair with an extreme number of connections (the default threshold was around 86,400 per day, one per second) was pulled out as a separate "strobe," because statistical beacon math is unreliable at that volume. In v5 this became the **"Large Number of Connections"** threat modifier. Strobes are usually misbehaving software, but very fast beacons show up here too.

### 5.5 Threat intelligence

RITA checks destination IPs and domains against blocklist feeds and any custom feeds you configure. This is the least important part of RITA. Its whole philosophy is that behavioral findings matter more than reputation lookups, because fresh C2 infrastructure is rarely on a list yet. A threat intel hit on its own, with no behavior behind it, is often a one-off ad-network request.

### 5.6 Threat modifiers (v5)

v5 combines everything into one severity rating (critical, high, medium, low). It starts from the base behavioral score and adjusts it using modifiers:

- **Prevalence:** how many internal hosts talk to this destination. One host out of 3,000 is suspicious; 2,900 out of 3,000 is probably a business service.
- **First Seen:** a destination that has only recently appeared in your environment.
- **Missing Host Header:** HTTP with no Host header, which is unusual for real browsers.
- **Rare Signature:** unusual user agents or TLS fingerprints (JA3-style) seen on very few hosts.
- **MIME type / URI mismatch:** for example, a URI ending in `.jpg` that returns an executable.
- **Long connection** and **large number of connections**, as above.
- **Threat intel hit.**

In v4 some of these were separate reports, such as rare user agents and invalid certificates. In v5 they add weight to a finding rather than standing alone.

---

## 6. The hunting methodology

Active Countermeasures teaches a repeatable loop. In rough order:

**1. Collect** at least 24 hours of Zeek data from a sensor with internal visibility.

**2. Triage** by severity in the TUI. Start with the top beacons and the longest connections, since that's where C2 concentrates.

**3. Investigate the destination.** Who owns the IP or ASN? Look up WHOIS and domain age, reverse DNS, passive DNS history, the certificate details (self-signed, Let's Encrypt on a two-day-old domain, default framework certificates), and the geography relative to your business. Cheap VPS providers and freshly registered domains raise concern. Microsoft, Google, and AWS don't prove innocence, since attackers use cloud infrastructure, but they shift the odds.

**4. Investigate the source.** What is this host, who uses it, and does its role justify the traffic? A domain controller beaconing to the internet is very different from a developer laptop hitting a package registry.

**5. Ask "is there a business reason?"** Most high-scoring beacons turn out to be legitimate software. Identifying the software is the key step.

**6. Pivot to the endpoint.** Network data tells you *which host* and *where*, but not *which process*. Use EDR, Sysmon Event ID 3 (network connection), `netstat -ano` / `Get-NetTCPConnection`, or Active Countermeasures' **BeaKer**, which visualizes Sysmon network events, to tie the connection to a binary. Then examine the binary: its path, signature, parent process, and persistence.

**7. Decide and document.** It's either confirmed malicious (escalate to incident response and block), benign (add it to the allowlist), or unknown (keep watching and collect more data).

**8. Tune.** Every benign finding you allowlist makes the next hunt cleaner. After a few cycles the top of the list becomes very high-signal.

---

## 7. Common false positives and tuning

You'll routinely see these high-scoring but benign patterns: NTP; Windows Update and delivery optimization; anti-virus and EDR cloud check-ins (ironically, often the most perfect beacons on the network); Office 365, Teams, and OneDrive sync; Google/Chrome update; Slack; Zoom; Dropbox; printer and IoT vendor telemetry; RMM and backup agents; monitoring such as SNMP polling; certificate revocation checks; and internal resolvers talking to root and TLD servers.

To tune:
- **Define internal subnets correctly** in the config. If this is wrong, the direction logic is wrong and results are garbage.
- **Never-include lists** for known-good destinations. Be careful, because allowlisting a whole CDN or cloud provider also hides attackers who use that CDN or cloud.
- **Always-include lists** for ranges you want scored even though filters would normally drop them.
- **Filter by internal source** to leave out noisy infrastructure, such as your proxy or DNS server, when that makes sense.

The central tension: every exclusion is a place an attacker can hide. Prefer narrow, specific entries (an exact FQDN or a specific host pair) over broad ones (an entire ASN).

---

## 8. How attackers evade it, and how you respond

**Heavy jitter and long sleeps.** Randomizing intervals by 50% or more and sleeping for hours weakens interval statistics. Your response: analyze longer windows, lean on the histogram/duration scoring and data-size consistency (the payload size often stays uniform even when timing doesn't), and pay attention to low-prevalence destinations regardless of score.

**Domain fronting and CDN abuse.** The destination looks like a large CDN. FQDN/SNI beaconing helps, but if the fronting is done well, you can't see the real Host header without TLS inspection.

**C2 over legitimate services.** Slack, Teams, Telegram, GitHub, Google Sheets, Dropbox, and Notion have all been used as C2 channels. Legitimate clients generate the same traffic, so the question becomes "why is *this* host, which never used Slack before, suddenly talking to the Slack API every 60 seconds from a non-Slack user agent?" Prevalence and rare-signature modifiers matter here.

**Blending into business hours.** Malware that only beacons 9-to-5 defeats the "active all night" signal. Timing and size regularity still apply.

**Peer-to-peer and internal-pivot C2.** SMB named pipes, internal TCP chains, and similar methods mean only one host talks outward. RITA focuses on internal-to-external traffic by default, so internal chains need other visibility, such as internal sensors or endpoint telemetry.

**Irregular, operator-driven traffic.** Hands-on-keyboard sessions don't beacon. Long connections, first-seen destinations, and rare signatures carry the load there.

**Protocols RITA doesn't parse.** RITA's view is limited to what Zeek logs. QUIC/HTTP3, ICMP tunnels, and custom UDP show up in `conn.log` with timing and bytes, which still gets you beacon scoring, but you lose the protocol-level detail.

---

## 9. What RITA doesn't do

RITA doesn't block anything, it doesn't inspect payloads, and it doesn't identify processes (you need the endpoint pivot for that). It needs Zeek in front of it. It works on batches, so even rolling imports are near real-time rather than live, unless you move to AC-Hunter or build your own pipeline. It points you toward suspicious hosts; it doesn't hand you conclusions. A human still has to decide whether a finding is legitimate. Its real strength is turning millions of connections into a ranked shortlist of a few dozen pairs worth human attention.

---

## 10. Complementary tools

- **Zeek** itself, especially adding JA3/JA4 fingerprinting scripts, which make TLS signatures much richer.
- **Suricata**, for signature coverage alongside RITA's behavioral coverage.
- **Active Countermeasures' other free tools:** BeaKer (Sysmon network visualization), espy (Sysmon to Zeek-format logs), passer (passive asset discovery), and zcutter (Zeek log manipulation).
- **Sysmon and EDR** for the process attribution step.
- **SIEM integration**, via `--stdout` CSV exports or by querying ClickHouse directly, to correlate RITA findings with authentication and endpoint logs.

---

## 11. Practicing and learning

- **Generate your own C2 in a lab.** Run Sliver, Mythic, Havoc, or even a simple `while true; do curl https://yourvps/; sleep 60; done` loop against a VPS you control. Capture the traffic, run it through Zeek, import it, and watch how the score changes as you add jitter or lengthen the sleep. This is the fastest way to build intuition for what the numbers mean.
- **Active Countermeasures sample datasets and PCAPs**, used in their webcasts and labs.
- **Antisyphon / Black Hills training.** Chris Brenton's network threat hunting courses are built around RITA and AC-Hunter and have often been offered free or pay-what-you-can.
- **The Threat Hunter Community Discord.** Active Countermeasures runs a Threat Hunter Community Discord server where RITA users and developers talk.
- **Malware-traffic-analysis.net PCAPs.** Real infection captures you can process with Zeek and hunt with RITA.
- **Their webcast archive,** which includes walkthroughs of v5's new features.

---

## TL;DR

RITA uses statistics on Zeek logs to ask four questions about every internal-to-external pair: Is it too regular (beaconing)? Is it too persistent (long connections)? Is it abusing DNS (subdomain volume, direct resolver use)? Is it rare or new (prevalence, first seen, unusual signatures)? v5 runs in Docker, stores data in ClickHouse, uses a terminal UI, and rolls everything into one severity score. To use it well, get your sensor placement right, collect at least 24 hours of data, investigate the destination and the source, pivot to the endpoint to find the process, and keep tuning your allowlists. The tool narrows the haystack. Your judgment finds the needle.

If it would help, I can turn this into a doc you can keep, or walk you through building a lab that generates C2 traffic so you can watch RITA score it.
