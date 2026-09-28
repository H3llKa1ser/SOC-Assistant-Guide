# Threat Hunting with Deception

# Threat Hunting with Deception

## The core idea

Threat hunting is the proactive, hypothesis-driven search for adversaries who have already evaded your automated defenses. Deception is the practice of planting fake assets (systems, credentials, files, accounts, data) that no legitimate user or process has any reason to touch. Combined, they reverse the usual defender's problem. Normally the defender has to find a needle in a haystack of legitimate activity. With deception, **any interaction with a decoy is suspicious by definition**, so the signal-to-noise ratio is extremely high.

The usual framing is that deception flips the attacker's asymmetry. An attacker only needs to be right once to get in, but once inside they have to be right every time. Every host they scan, credential they try, or share they browse might be a trap. Defenders call this "making the attacker's job expensive and uncertain."

## Why it works so well for hunting

Deception offers several things that conventional detection struggles with. The first is **high-fidelity alerts**. A well-placed decoy has a false-positive rate close to zero, so its alerts can drive a hunt directly instead of sitting in a triage queue.

The second is **mid-kill-chain detection**. Perimeter controls watch initial access, and DLP watches exfiltration. Deception is strongest in the messy middle: discovery, credential access, privilege escalation, and lateral movement. This is where adversaries spend most of their dwell time and where they are forced to explore an environment they don't know.

The third is **behavior-based, signature-independent detection**. It doesn't matter whether the attacker uses a zero-day, living-off-the-land binaries, or a stolen legitimate credential. If they touch the decoy, you know.

Deception also **generates intelligence**. Interaction with decoys reveals tools, TTPs, objectives, and sometimes operator skill level. That feeds new hunt hypotheses and detections.

Finally, it can **slow adversaries down** by wasting their time on fake targets, which buys your responders time.

## A short history

The lineage is older than most people assume. Cliff Stoll's *The Cuckoo's Egg* (1986–89) describes planting a fake "SDInet" project folder to keep a KGB-linked hacker online long enough to trace him. That is arguably the first documented honeytoken operation. Bill Cheswick's "An Evening with Berferd" (1991) described luring and studying an intruder in a jail environment.

Fred Cohen's Deception Toolkit came in 1997 and Niels Provos's honeyd in the early 2000s. Lance Spitzner founded the Honeynet Project in 1999 and published *Honeypots: Tracking Hackers* in 2002. The term "honeytoken" is credited to Augusto Paes de Barros around 2003. Early honeypots were mostly research tools for studying attackers on the internet.

The shift to **production deception inside the enterprise** came in the mid-2010s. Gartner popularized "deception technology" as a category, and vendors like Attivo, Illusive, TrapX, and Thinkst Canary appeared. MITRE released Shield in 2020 and replaced it with **MITRE Engage** in 2022. Engage is now the standard framework for adversary engagement and deception planning. Around 2023, Microsoft added native decoy accounts and lures to Defender XDR, a sign that deception was going mainstream.

## Taxonomy of deception assets

### Honeypots
Honeypots are fake systems or services, classified by interaction level.

- **Low-interaction** honeypots emulate a service banner or protocol handshake (for example OpenCanary or honeyd). They are cheap, safe, and easy to deploy widely, but easier to fingerprint.
- **Medium-interaction** honeypots emulate enough of a service to capture commands and payloads (for example Cowrie for SSH/Telnet, or Dionaea for malware capture).
- **High-interaction** honeypots are real operating systems and applications, heavily instrumented. They give you the richest intelligence and are the hardest to detect. They are also risky, because a compromised one can become a pivot point.

A second distinction is between **research honeypots**, usually internet-facing and used to study the threat landscape, and **production honeypots**, placed inside your network to detect intrusions. For hunting, production deception matters most.

### Honeynets
A honeynet is an entire fake network segment, sometimes with simulated users and traffic, designed for high-interaction engagement.

### Honeytokens, breadcrumbs, and lures
These are arguably the most powerful and underused category. They are pieces of fake data rather than whole systems.

- **Honey credentials** are fake usernames and passwords placed where attackers harvest them: LSASS memory, Windows Credential Manager, browser saved passwords, config files, scripts, `.bash_history`, RDP connection histories, SSH `known_hosts` and private keys.
- **Honey accounts** are fake Active Directory users, ideally made to look like privileged, stale, or service accounts.
- **Honey SPNs** are fake service principal names on a decoy account. Any Kerberos ticket request for one is a strong sign of Kerberoasting.
- **Honey files** are documents like `passwords.xlsx`, `VPN_config_backup.txt`, or `M&A_2026_confidential.docx`, with auditing or embedded beacons.
- **Canarytokens** are objects that "phone home" when opened or used: URLs, DNS names, Word/PDF documents, AWS API keys, Azure login certificates, QR codes, SQL triggers, Kubernetes configs, and more.
- **Honey records** are fake rows in databases, such as a fake customer with a unique email address or card number. If that data shows up anywhere, you know the database leaked.
- **Honey email addresses** are unique addresses seeded into specific systems or partners to detect data leaks or phishing targeting.
- **Honey DNS entries** are fake internal hostnames (such as `backup-dc02` or `vault-prod`) that should never be resolved.
- **Honey cloud resources** are fake S3 buckets, IAM keys, secrets in Secrets Manager or Key Vault, and fake Lambda functions, all monitored through cloud audit logs.
- **Honey code/secrets** are fake API keys committed to internal repos to catch someone scraping source code.

### Network-level deception
This includes tarpits like LaBrea, which slow down scanners and worms, and fake ARP or LLMNR responses. There are also "anti-responder" tricks: you send LLMNR/NBT-NS queries for nonexistent hosts and alert on anyone who answers, which catches Responder-style poisoning.

### Endpoint deception
Agents or scripts plant lures on real workstations: fake mapped drives, fake cached credentials, fake browser bookmarks to decoy admin panels, and fake recent-file entries. This is how commercial platforms achieve density, because every endpoint becomes a potential tripwire.

### OT/ICS deception
Tools like Conpot emulate PLCs, SCADA protocols (Modbus, S7, BACnet), and HMIs. They are especially valuable because OT networks are quiet and deterministic, which makes decoy interactions stand out even more.

## Mapping deception to ATT&CK

Good deception programs are designed against specific adversary behaviors. The table below shows common mappings.

| ATT&CK tactic / technique | Deception that catches it |
|---|---|
| Discovery: Account Discovery (T1087), Domain Trust / Permission Groups Discovery | Honey accounts with enticing attributes; SACL auditing on reads of those objects (Event 4662) |
| Discovery: Remote System Discovery (T1018), Network Service Scanning (T1046) | Decoy hosts and services, honey DNS records |
| Discovery: File and Directory Discovery (T1083), Network Share Discovery (T1135) | Honey shares and files with access auditing (4663, 5145) |
| Credential Access: OS Credential Dumping (T1003) | Honey credentials in LSASS or Credential Manager; alert when they are *used* |
| Credential Access: Kerberoasting (T1558.003) | Honey SPN account; alert on any 4769 request for it, especially with RC4 encryption |
| Credential Access: AS-REP Roasting (T1558.004) | Honey account with "do not require pre-auth" set; alert on 4768 |
| Credential Access: Unsecured Credentials (T1552) | Fake creds in scripts, GPP cpassword in SYSVOL, config files, repos |
| Credential Access: Adversary-in-the-Middle / LLMNR poisoning (T1557.001) | Spoofed queries for nonexistent names; alert on any responder |
| Lateral Movement: Remote Services (T1021) | Decoy RDP, SMB, SSH, WinRM hosts |
| Collection / Exfiltration | Honey files with beacons, honey records, canary documents |
| Impact: Data Encrypted for Impact (T1486) | Canary files monitored for modification to catch ransomware early |

**MITRE Engage** complements ATT&CK. It organizes adversary engagement around strategic goals (*Expose*, *Affect*, *Elicit*) and a catalog of activities such as lures, decoy artifacts, network manipulation, and pocket litter. Each activity maps to the ATT&CK behaviors it exploits. Engage emphasizes that deception should serve a defined operational objective, not just be "put some honeypots out there."

## How deception plugs into the hunting process

Most hunting methodologies (Sqrrl's Hunting Loop, TaHiTI, Splunk's PEAK framework) share a cycle: hypothesis, investigation, discovery of patterns and TTPs, then automation and enrichment. Deception fits into that cycle in several distinct ways.

### 1. Deception as a lead generator
A decoy fires, and that alert becomes the starting point of a hunt. The question is no longer "is something bad happening?" but "we know something touched this, now what else did it do?" You pivot from the source host, the account used, and the time window. You look for the process tree on the source endpoint, other authentication attempts from the same account, other hosts contacted, and persistence mechanisms. A single tripwire often unravels an entire intrusion that other tools missed.

### 2. Deception as hypothesis validation
Hunters often form hypotheses they can't easily test with existing telemetry, such as "an attacker is enumerating AD looking for privileged accounts." Raw LDAP query logs are noisy and ambiguous. Plant a honey admin account with an enticing description and SACL auditing, and the hypothesis becomes testable: anyone reading that object's attributes is worth investigating. Deception turns vague hypotheses into binary, observable conditions.

### 3. Deception for scoping and containment
Once you have a suspected compromise, targeted deception can scope it. Drop fresh breadcrumbs on suspect hosts that point to a unique decoy. If that decoy gets touched, you've confirmed the adversary is active on that specific host and can see which path they took.

### 4. Deception for intelligence and TTP collection
Medium- and high-interaction decoys let you observe the adversary's hands-on-keyboard behavior: commands, tools, dropped payloads, C2 infrastructure, and objectives. That becomes IOCs, new behavioral detections, and new hunt hypotheses for the rest of the estate.

### 5. Deception for detection-coverage testing
In purple-team exercises, deception assets reveal which attacker behaviors you currently can't see. If red team harvested honey creds and your EDR didn't flag the dump but the decoy flagged the use, you've found a gap.

### 6. Retro-hunting with honeytoken data
Because honeytokens are unique strings, you can search historical logs for them. If a honey credential shows up in old authentication logs, or a honey email address appears in a breach dump, you can date the compromise and hunt backward from there.

## Design principles

The difference between deception that works and deception that gets ignored or fingerprinted comes down to a few principles.

**Believability.** Decoys must match the environment. Use your naming conventions, OS versions, hostname patterns, OU structure, and banner strings. A decoy called `HONEYPOT01` running a default Cowrie banner is worse than useless. Sophisticated attackers check account attributes like `whenCreated`, `lastLogonTimestamp`, `logonCount`, `pwdLastSet`, and `badPwdCount`. A "domain admin" created yesterday that has never logged on looks fake. Aged, plausible accounts with occasional scripted logons look real.

**Enticement.** Decoys should look more valuable than real targets: "legacy admin," "backup service account," "SQL prod creds," or a file named after a sensitive project. The goal is for the decoy to sit on the attacker's likely path and be the most attractive thing there.

**Placement and density.** Put deception where attackers go: domain controllers, jump boxes, admin workstations, file servers, CI/CD systems, cloud identity. Endpoint breadcrumbs spread widely create density, so an attacker on almost any host encounters a lure.

**Non-interference.** Decoys must never break production or confuse users. Honey accounts should be disabled from real use or have unusable passwords where appropriate. Honey data must never flow into real business processes. Critically, never use real sensitive data as bait.

**Secrecy.** Limit knowledge of deception assets to a small group. Insiders who know where the decoys are can avoid them, and leaked inventories destroy the program's value.

**Tuning for legitimate noise.** Vulnerability scanners, asset inventory tools, backup software, and IT admins browsing AD will touch decoys. Document and allowlist these sources carefully. Be precise, though, because attackers love to hide behind your own scanners.

**Freshness.** Rotate and refresh lures so they don't become stale or known, and keep decoys patched and consistent with the rest of the environment.

## Concrete, practical examples

**Honey domain admin.** Create an account that looks like an old admin, such as `adm-jsmith-legacy`, in the Domain Admins group or with `adminCount=1`. Give it a long random password and deny it interactive logon where possible. Enable SACL auditing on the object. Alert on any 4624/4625 logon, any 4768/4769 ticket request, and any 4662 directory read of its attributes from non-allowlisted sources. BloodHound-style enumeration and password spraying both tend to trip this.

**Kerberoasting tripwire.** Assign a fake SPN such as `MSSQLSvc/sql-finance-old.corp.local:1433` to a honey account. No legitimate client will ever request a ticket for it, so any 4769 event for that SPN is almost certainly Kerberoasting. RC4 encryption type (0x17) in the request strengthens the signal.

**Credential injection into memory.** Place fake credentials into LSASS on high-value endpoints, for example using `runas /netonly` with a fake account so the creds sit in memory without a real logon. If those credentials are ever used on the network, someone dumped memory on that host. This detects Mimikatz-style credential theft without needing to catch the dump itself.

**Canary AWS keys.** Plant fake AWS access keys (from Canarytokens or a dedicated honey IAM user with no permissions) in dev laptops, repos, CI variables, and wikis. Any API call using them shows up in CloudTrail with the caller's IP, and nobody should ever call anything with them.

**Honey file shares.** Create a share like `\\fileserver\IT-Backups` containing plausible files. Enable object-access auditing and alert on 4663/5145. Embed canary beacons in documents so opening them offline still phones home, if the attacker's machine has connectivity.

**Ransomware canaries.** Scatter canary files across shares and endpoints, often with names that sort first alphabetically so encryptors hit them early. Monitor with file integrity monitoring. Modification triggers automated host isolation.

**Anti-Responder.** Periodically broadcast LLMNR/NBT-NS queries for nonexistent hostnames. No legitimate host should answer, so any response identifies a poisoning tool on the segment.

**Decoy hosts.** Deploy lightweight decoys (OpenCanary or commercial sensors) that mimic file servers, network printers, NAS devices, or old Windows servers in each VLAN. Set up internal DNS entries for them with enticing names.

**Honey records.** Insert a fake customer with a unique email address into your CRM or production database. If that address receives mail, or appears in a leak dump, you know the data escaped and roughly which system it came from.

## Tooling landscape

The open-source ecosystem is strong. **Thinkst Canarytokens** (free, hosted or self-hosted) is the easiest starting point for honeytokens. **OpenCanary** is a lightweight multi-protocol decoy daemon. **T-Pot** (from Deutsche Telekom) bundles many honeypots with an ELK stack and is popular for research deployments. **Cowrie** (successor to Kippo) is the go-to SSH/Telnet honeypot. **Dionaea** captures malware. **Conpot** emulates ICS devices. Nikhil Mittal's **Deploy-Deception** PowerShell module creates AD decoy users, computers, and groups with auditing. Secureworks released **DCEPT** for honey credentials. **Beelzebub** and **Galah** are newer honeypots that use LLMs to generate realistic responses to attacker input. Black Hills Information Security's ADHD distribution bundled many active-defense tools for training.

On the commercial side, the market has consolidated heavily. Attivo Networks was acquired by SentinelOne (2022). Illusive was acquired by Proofpoint (2022). TrapX was acquired by Commvault (2022). Smokescreen was acquired by Zscaler (2021). Independent players include **Thinkst Canary**, **Acalvio ShadowPlex**, and **CounterCraft**. **Microsoft Defender for Identity** supports honeytoken account tagging, and **Defender XDR** added automated decoy accounts and lures. Rapid7 InsightIDR also includes honeypots and honey credentials. The vendor landscape moves fast, so check the current state before buying anything.

## Operationalizing: integration and automation

Deception alerts are only valuable if they reach the right people fast. Standard practice is to send decoy events into the SIEM with top-tier severity. Enrich them automatically with asset and user context. Then tie them to SOAR playbooks that can isolate the source host via EDR, disable the associated account, and open a hunt ticket with the relevant pivot queries pre-populated.

Because deception alerts are so reliable, many organizations are comfortable with **automated containment** on a decoy trip, which they would never allow for a noisy behavioral detection.

Useful program metrics include:
- mean time to detect in exercises with and without deception
- percentage of network segments and critical assets covered by decoys
- percentage of ATT&CK techniques in your threat model with deception coverage
- false-positive rate per decoy type
- number of hunts initiated from deception leads and what they found

## Risks, pitfalls, and adversary countermeasures

**Fingerprinting.** Attackers and researchers actively look for honeypots. Default banners, unrealistic response timing, missing artifacts, and known virtualization indicators give them away. Internet scanners like Shodan even publish honeypot likelihood scores for exposed hosts. Always customize defaults. Assume advanced adversaries will probe for deception and design decoys that survive scrutiny.

**Pivot risk.** A compromised high-interaction honeypot can become a launch point against your real network or third parties. Isolate it, restrict egress, and monitor it intensely.

**Legal and privacy considerations.** "Entrapment" is a common worry, but it's a doctrine that restricts law enforcement, not private organizations defending their own networks. More relevant concerns are privacy law (GDPR and similar rules can apply to data captured about attackers or accidentally about employees), liability if your decoy is used to attack others, and employee-monitoring rules in some jurisdictions. Get legal sign-off, especially for high-interaction or data-capturing deployments.

**Operational noise.** Poorly tuned decoys get tripped constantly by IT tooling. The team loses trust in them, and the program dies quietly. Tuning and allowlisting at launch are essential.

**Insider knowledge.** An administrator who knows the decoy inventory can avoid it. That argues for tight need-to-know and periodic rotation.

**Neglect.** Decoys that are never updated drift away from how the real environment looks and become obvious.

**Not a substitute.** Deception does not replace patching, hardening, logging, or EDR. It is a layer that catches what gets past them.

**Deception is not hack-back.** Everything described here lives inside your own environment. Canary beacons report back when your stolen document is opened, but they don't attack anyone. Keep it that way; offensive "active defense" against attacker infrastructure is legally hazardous almost everywhere.

## A pragmatic roadmap for getting started

In the first few weeks, start with honeytokens because they're nearly free and extremely high-signal. Create a honey admin account and a honey SPN account in AD. Plant canary AWS keys and canary documents in obvious places. Set up an anti-Responder check. Wire all of it to your SIEM with a clear response playbook.

Next, add low-interaction decoy hosts to key network segments, particularly near domain controllers, admin jump hosts, and file servers. Seed endpoint breadcrumbs on admin and high-value workstations. Map everything to your ATT&CK threat model and look for gaps.

As the program matures, adopt MITRE Engage planning for specific adversary behaviors you're worried about. Run purple-team exercises to test decoy believability. Build automated containment for decoy trips. Use decoy-derived intelligence to drive new hunt hypotheses. Consider medium- or high-interaction engagement environments for specific threat actors, if you have the staff to run them safely.

## Emerging directions

A few trends are shaping the field as of 2026. **LLM-powered honeypots** generate dynamic, realistic responses to arbitrary attacker commands, which makes them harder to fingerprint and extends engagement time. **Identity-centric deception** has become the dominant focus, as attacks increasingly revolve around credentials, tokens, and identity providers rather than malware. **Cloud and SaaS deception** covers fake OAuth apps, honey service principals, decoy Kubernetes secrets, and canary tokens inside SaaS platforms. **Deception against AI agents** is newer: honeytokens and decoy tools are used to detect autonomous attack agents or compromised internal agents that follow injected instructions. Academic work continues on game-theoretic deception placement and on **moving target defense**, which shifts the environment's attack surface over time.

## Further reading

The most useful sources are:
- Chris Sanders, *Intrusion Detection Honeypots* (2020): arguably the best practical book on production deception for detection.
- MITRE Engage (engage.mitre.org): the framework and activity matrix.
- Lance Spitzner, *Honeypots: Tracking Hackers*, and Niels Provos & Thorsten Holz, *Virtual Honeypots*: foundational references.
- Cliff Stoll, *The Cuckoo's Egg*: for the history and a genuinely great read.
- John Strand et al., *Offensive Countermeasures: The Art of Active Defense*: practical active-defense techniques.
- Thinkst's blog: excellent ongoing writing on honeytokens and decoy design.
- Splunk's PEAK threat hunting framework: to anchor deception within a structured hunting methodology.

