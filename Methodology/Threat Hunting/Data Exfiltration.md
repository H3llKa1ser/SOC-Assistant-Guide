# Threat Hunting for Data Exfiltration

Data exfiltration is the stage where an intrusion turns into a breach. Threat hunting for it means proactively searching your telemetry for signs that data is being collected, staged, or moved out of your environment, without waiting for an alert. The difficulty is that competent adversaries try to look like normal business traffic: HTTPS to cloud storage, DNS lookups, scheduled backups, email. A hunter's job is to find the small differences between legitimate data movement and theft.

## How Exfiltration Actually Happens

Exfiltration is usually the end of a chain, and each link leaves evidence. The attacker first finds the data through discovery: share enumeration, database queries, SharePoint searches, or tools like AdFind and SharpShares. Next comes collection, where they gather files, email, or database dumps, often with scripts or automated tooling. Then staging: the data is copied to one location, commonly an odd directory such as `C:\PerfLogs`, `C:\ProgramData`, `\$Recycle.Bin`, or a temp folder, or to a single "staging" server inside the network. They usually compress and encrypt it with 7-Zip, WinRAR (often password-protected and split into chunks), or tar/gzip on Linux. After that comes the transfer itself, and finally some attackers clean up by deleting archives, clearing logs, or removing tools.

This matters for hunting because the transfer itself is often the hardest step to catch, especially over encrypted channels. The staging and compression steps on the endpoint are frequently easier to spot. Good exfiltration hunts look across the whole chain, not just at network egress.

## The MITRE ATT&CK View

The Exfiltration tactic (TA0010) is the standard reference, and it pairs closely with Collection (TA0009).

| Technique | What it looks like |
|---|---|
| T1041 Exfiltration Over C2 Channel | Data leaves over the same channel as command-and-control, e.g. a Cobalt Strike beacon doing large HTTP POSTs |
| T1048 Exfiltration Over Alternative Protocol | DNS tunneling, ICMP, FTP/SFTP, SMTP, or unusual ports |
| T1567 Exfiltration Over Web Service | Uploads to Mega, Dropbox, Google Drive, OneDrive, GitHub, paste sites, Telegram or Discord webhooks |
| T1537 Transfer Data to Cloud Account | Sharing snapshots, buckets, or backups with an attacker-controlled cloud account |
| T1052 Exfiltration Over Physical Medium | USB drives, external disks, phones |
| T1029 Scheduled Transfer | Transfers timed for specific hours to blend in |
| T1030 Data Transfer Size Limits | Chunking data into small pieces to stay under volume thresholds |
| T1020 Automated Exfiltration | Scripts or tools that exfiltrate without operator interaction |
| T1011 Other Network Medium | Wi-Fi, Bluetooth, cellular modems that bypass corporate egress |

Related collection techniques worth hunting alongside these include T1560 (Archive Collected Data), T1074 (Data Staged), T1114 (Email Collection, including forwarding rules), T1213 (Data from Information Repositories like SharePoint or Confluence), and T1530 (Data from Cloud Storage).

## Data Sources You Need

You can't hunt what you don't log, so the first question for any exfiltration hunt is visibility.

On the network side, the most valuable sources are flow data (NetFlow, IPFIX, VPC Flow Logs) and Zeek connection logs, because they record bytes sent and received per connection. That single field powers most volumetric hunting. Web proxy or secure web gateway logs give you URLs, HTTP methods, upload sizes, and user attribution. DNS logs, ideally from your resolvers and not just the firewall, are essential for tunneling detection. TLS metadata such as SNI, certificate details, and JA3/JA4 fingerprints helps characterize encrypted traffic you can't decrypt. Firewall logs fill gaps, and full packet capture (via Arkime or similar) is useful for confirming findings, although rarely available at scale.

On endpoints, EDR telemetry is the backbone: process creation with command lines, file creation, and network connections tied to processes. Sysmon provides much of this for free: Event ID 1 for process creation, 3 for network connections, 11 for file creation, 22 for DNS queries, and 23 for file deletion. Windows Security events 4663 (object access, if auditing is enabled) and 5145 (detailed network share access) reveal mass file reading. Removable media events, including Event ID 6416 for new external devices, cover the physical channel.

In cloud and SaaS, you want AWS CloudTrail including S3 data events (which are off by default and cost money, but are critical), Azure Activity and Storage logs, GCP audit logs, and the Microsoft 365 Unified Audit Log with operations like `FileDownloaded`, `FileSyncDownloadedFull`, `MailItemsAccessed`, and `New-InboxRule`. GitHub audit logs, Salesforce event monitoring, and Snowflake query and login history also matter, depending on where your sensitive data lives.

Supporting context from DLP, CASB, email gateways, HR systems (departing employees, performance issues), and an asset inventory that identifies where your crown-jewel data actually sits makes every hunt sharper.

## Hunting Hypotheses and Analytics

### Volumetric anomalies

The simplest hypothesis is that some host is sending far more data outbound than it normally does or than its peers do. You aggregate outbound bytes per internal host per destination over a time window, then look for outliers against the host's own baseline and its peer group. Ratios help: most workstations download far more than they upload, so a host with a high upload-to-download ratio toward an external destination stands out. Long-duration connections carrying steady outbound data are another signal.

The catch is that backups, video calls, software builds, and legitimate cloud sync generate large uploads, so you need allow-lists and business context. Attackers also know about volume thresholds and may chunk data (T1030) or throttle it, which is why per-destination cumulative totals over days can reveal what per-hour views miss.

A Splunk example against Zeek conn logs:

```
index=zeek sourcetype=zeek_conn local_orig=true local_resp=false
| stats sum(orig_bytes) as bytes_out, sum(resp_bytes) as bytes_in,
        count as conns, dc(id.resp_p) as ports
        by id.orig_h, id.resp_h
| eval ratio = round(bytes_out / (bytes_in + 1), 2)
| where bytes_out > 500000000 AND ratio > 5
| sort - bytes_out
```

### Beaconing and low-and-slow transfer

When exfiltration rides the C2 channel, you often see periodic connections with consistent timing and sizes. Hunters measure the regularity of connection intervals, tolerate some jitter, and flag destinations contacted at machine-like cadence by only one or a few hosts. RITA (Real Intelligence Threat Analytics) by Active Countermeasures automates beacon scoring on Zeek data and is a staple for this.

### DNS tunneling

DNS is attractive because it's almost always allowed out. Tools like iodine and dnscat2, and many custom implants, encode data into subdomain labels. Signs include unusually long query names, high character entropy in subdomains, a very high count of unique subdomains under one parent domain, heavy use of TXT, NULL, or CNAME records, and one internal host generating far more queries to a single domain than anything else. Newly registered domains and domains with no web presence add weight.

```
index=dns
| rex field=query "(?<sub>.+)\.(?<parent>[^\.]+\.[^\.]+)$"
| eval sublen = len(sub)
| stats dc(sub) as unique_subs, avg(sublen) as avg_len, count by src_ip, parent
| where unique_subs > 500 AND avg_len > 30
| sort - unique_subs
```

CDNs, anti-virus reputation lookups, and some SaaS telemetry legitimately produce long, random-looking subdomains, so expect to build an allow-list. Also note that DNS over HTTPS (DoH) can hide this activity from your resolvers entirely; hunting for endpoints talking to known DoH providers is its own useful hunt.

### ICMP and protocol abuse

Normal ICMP echo payloads are small and predictable. Large or variable payloads, or high volumes of ICMP to a single external host, suggest tunneling. More generally, look for protocol mismatches: non-TLS traffic on port 443, SSH on unusual ports, or FTP from hosts that have no business using it.

### Exfiltration to web services and cloud storage

This is the dominant method in modern ransomware and data-extortion operations. The Conti playbooks that leaked in 2022 showed operators relying heavily on rclone to push stolen data to Mega and other cloud storage, and many groups still do the same. LockBit developed its own tool, StealBit. State-sponsored groups have abused legitimate services too; APT29, for instance, has been reported using Dropbox and Google Drive for C2 and data transfer.

Productive hunts include looking for rclone and similar tools (MEGAsync, MEGAcmd, restic, WinSCP, FileZilla, curl with upload flags) on hosts where they don't belong, including renamed binaries caught via original filename metadata. Look for rclone configuration files (`rclone.conf`) on disk, and for command lines containing remote names like `mega:` along with flags such as `--transfers`, `--no-check-certificate`, or `--max-age`. On the network side, hunt for large uploads to personal file-sharing services, anonymous upload sites (gofile, transfer.sh, file.io, and similar), paste sites, and chat platform webhooks, especially from servers that never normally browse the web.

A Microsoft Defender KQL example:

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where FileName =~ "rclone.exe"
    or ProcessVersionInfoOriginalFileName =~ "rclone.exe"
    or (ProcessCommandLine has_any ("copy", "sync")
        and ProcessCommandLine has_any ("mega:", "--transfers", "--config"))
| project Timestamp, DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine
```

Living-off-the-land binaries also get used for uploads: PowerShell `Invoke-WebRequest` or `Invoke-RestMethod` with `-Method Post` and `-InFile`, `curl.exe -T` or `-F`, `bitsadmin` upload jobs, and occasionally `ftp.exe` with a script file.

### Staging and compression on endpoints

This is often the highest-yield hunt, because it catches the attack before or during transfer. Look for archive tools (7z, rar, WinRAR, makecab, tar) run from unusual parent processes or by service accounts, command lines using password flags (`-hp` or `-p` for RAR, `-p` for 7-Zip) and volume splitting (`-v`), and very large archive files created in staging directories. On file servers, a single account reading thousands of files in a short window, visible through share access events or EDR file telemetry, is a strong collection indicator. Database utilities like `sqlcmd`, `bcp`, `mysqldump`, and `pg_dump` running outside their normal maintenance windows deserve a look as well.

### Email exfiltration

Attackers who compromise mailboxes commonly create inbox rules that forward mail externally, or set mailbox-level forwarding. Hunt for `New-InboxRule`, `Set-InboxRule`, and `Set-Mailbox` with `ForwardingSmtpAddress` in the M365 audit log, especially rules that forward to external domains, delete or mark as read, or match keywords like "invoice," "payment," or "password." Also look for users sending large attachments to personal webmail addresses, and for spikes in `MailItemsAccessed` from unfamiliar IPs or applications, which may indicate bulk mailbox harvesting through a malicious OAuth app.

### Cloud infrastructure exfiltration

In IaaS, the attacker often doesn't need to download anything; they can simply share a resource with their own account. In AWS, hunt CloudTrail for `ModifySnapshotAttribute` and `ModifyDBSnapshotAttribute` that grant access to unknown external account IDs, `PutBucketPolicy` or `PutBucketAcl` changes making buckets public or cross-account, `CreateImage` or `CopySnapshot` to other regions or accounts, and spikes in S3 `GetObject` calls from one principal. In Azure, look for storage account key listing (`listKeys`), generation of long-lived SAS tokens, and disk snapshot exports via SAS URLs. In GCP, watch IAM policy changes on buckets that add `allUsers` or external identities.

The 2024 campaign against Snowflake customer instances, attributed by Mandiant to UNC5537, is a good cautionary tale: attackers used credentials stolen by infostealer malware to log into accounts without MFA and exported large volumes of data directly. Hunting there meant reviewing login history for unusual client applications and source IPs, and query history for bulk `SELECT` and `COPY INTO` activity toward external stages.

### SaaS and code repositories

Bulk downloads from SharePoint or OneDrive, especially `FileSyncDownloadedFull` from unmanaged devices, mass creation of anonymous sharing links, cloning of many GitHub repositories by one user in a short time, and large report exports from Salesforce or other CRMs are all worth baselining.

### Insider threat patterns

Insiders don't need malware, so the signals are behavioral. Departing employees are statistically the highest-risk group, and joining HR data (resignation or notice dates) with activity logs is one of the most effective insider hunts. Look for unusual volumes of file access, printing, USB writes, uploads to personal cloud accounts, emailing documents to personal addresses, and access to data outside the person's normal role, particularly in the weeks before departure and outside working hours.

### Encrypted traffic characterization

Since most exfiltration is over TLS, metadata becomes your lens. Useful angles include connections to newly registered or rarely seen domains, self-signed or freshly issued certificates on unfamiliar hosts, JA3/JA4 fingerprints that don't match the claimed user agent (a "Chrome" user agent with a Python or Go TLS fingerprint), SNI values that don't match the certificate, and signs of domain fronting. Stacking fingerprints across your fleet and investigating the rare ones is a solid long-tail technique.

## Hunting Methodology

Frameworks like PEAK (from Splunk's SURGe team) and TaHiTI (from the Dutch financial sector) structure hunting into preparation, execution, and follow-through. Hunts generally fall into three styles. Hypothesis-driven hunts start from a specific idea, such as "a threat actor is using rclone to exfiltrate from our file servers." Intelligence-driven hunts start from a report about a group targeting your industry and search for their tools and infrastructure. Baseline or anomaly-driven hunts establish what normal looks like and investigate deviations.

A few techniques recur across all of them. Stacking (or long-tail analysis) means counting occurrences of something across the environment, such as process names making outbound connections or destination domains per host, and examining the rarest entries. Peer grouping compares a host or user to others with the same role rather than to the whole organization. Pivoting means taking one suspicious finding, such as a destination IP, and searching for every other host that talked to it, what process initiated the connection, and what happened on that host beforehand.

Starting with crown jewels is the most efficient approach. If you know where your intellectual property, customer data, and financial records live, you can focus hunts on those systems and the accounts that access them, rather than trying to analyze all egress at once.

Every hunt should end with documentation and, ideally, a new or improved detection. A hunt that finds nothing still produces value: it validates that your telemetry works, establishes a baseline, and may reveal logging gaps worth fixing.

## Tools Commonly Used

For network analysis, the common toolset is Zeek, Suricata, RITA or AC-Hunter, Arkime, and Security Onion as an integrated platform. For endpoints, it's EDR platforms (Defender for Endpoint, CrowdStrike, SentinelOne, Elastic), Sysmon, osquery, and Velociraptor for scalable forensic collection. Analysis happens in SIEMs and data platforms like Splunk, Microsoft Sentinel, Elastic, Google SecOps, or plain Jupyter notebooks with pandas for more exploratory work. Sigma rules provide a vendor-neutral way to share and convert detection logic, and the Sigma repository already contains many exfiltration-related rules, including rclone and archive-staging detections.

## Common Challenges

Encryption hides content, so you're mostly working from metadata. Remote workers on split-tunnel VPNs may never pass through your proxy, making endpoint telemetry more important than network sensors. QUIC and HTTP/3 are less visible to some legacy inspection tools. Legitimate cloud usage is enormous and noisy, so distinguishing a corporate OneDrive tenant from a personal one (by tenant ID or domain) becomes crucial. Cloud logging is often incomplete by default, and data events in particular are frequently disabled for cost reasons. Finally, false positives are unavoidable, and hunters need good relationships with IT and business teams to confirm what's expected.

## When You Find Something

If a hunt turns up likely exfiltration, the priorities shift to scoping and preserving evidence. Determine what data was accessed and how much left, which hosts and accounts were involved, and whether the channel is still active. Preserve logs and endpoint artifacts before remediation destroys them, and be careful not to tip off an active attacker prematurely by blocking one channel while they have others. Bring in legal and privacy teams early, because confirmed exfiltration of personal data can trigger notification obligations under regimes like GDPR (72 hours to notify the supervisory authority where required) and various sector rules. Once contained, feed the indicators and behaviors back into detections so the same technique alerts automatically next time.

## Complementary Prevention

Hunting works best alongside egress controls: restricting which servers can reach the internet at all, blocking or monitoring personal cloud storage and anonymous file-sharing categories at the proxy, enforcing tenant restrictions so only your corporate Microsoft 365 or Google tenant is reachable, controlling USB storage, requiring MFA everywhere (especially for cloud data platforms), and applying least-privilege access to sensitive repositories. Each control reduces the number of channels an attacker can use, which makes the remaining ones easier to hunt.

---

