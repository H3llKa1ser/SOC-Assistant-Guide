# Threat Hunting for Email-Based Attacks

Email remains the most common initial access vector for everything from commodity malware to nation-state intrusions and ransomware. Automated controls like secure email gateways, sandboxing, and SPF/DKIM/DMARC catch most of it. Threat hunting assumes something got through anyway, then goes looking for it proactively and without waiting for an alert. Below is a practitioner's view of the whole discipline.

---

## 1. What email threat hunting actually is

Detection engineering asks "what rule fires when X happens?" Hunting asks "if an attacker had done X last month, would we know, and where would the evidence be?" A hunt is usually driven by one of three things.

**Hypothesis-driven hunts** start from attacker behavior. For example: "Adversary-in-the-middle phishing kits are stealing session tokens from our finance users, and the only trace is a sign-in from a hosting provider ASN shortly after a URL click."

**Intelligence-driven hunts** start from a report, an ISAC bulletin, or a peer's incident, and sweep your environment for the named indicators and techniques.

**Anomaly-driven hunts** use stacking and baselining to find what's rare. Examples include a sender domain seen once, an attachment type nobody normally receives, or an inbox rule with a strange name.

The output of a good hunt is either a confirmed incident, a clean bill of health with documented scope, or a new automated detection. Ideally the hunt always produces the last one, so you never hunt the same thing manually twice.

Frameworks that formalize this include the Sqrrl/TaHiTI hunting loops, PEAK (Prepare, Execute, Act with Knowledge), and the MITRE ATT&CK mapping. The most relevant ATT&CK techniques are T1566 Phishing (.001 attachment, .002 link, .003 via service, .004 voice), T1534 Internal Spearphishing, T1114 Email Collection, T1564.008 Email Hiding Rules, T1528 Steal Application Access Token, T1557 Adversary-in-the-Middle, and T1656 Impersonation.

---

## 2. The modern email threat landscape (what you're hunting for)

**Credential phishing** is the bulk of it. The key shift is that simple fake login pages have largely given way to **adversary-in-the-middle (AiTM) kits** like Evilginx, EvilProxy, Tycoon 2FA, Mamba 2FA, and Rockstar 2FA. These proxy the real Microsoft or Google login, capture the session cookie after MFA completes, and let the attacker replay it. MFA alone doesn't stop this; phishing-resistant MFA (FIDO2, passkeys, Windows Hello) and token-binding or compliant-device Conditional Access do.

**Business Email Compromise (BEC)** often contains no malware and no link at all, just a convincing request from a CEO, lawyer, or vendor to change bank details or buy gift cards. **Vendor Email Compromise** is the nastier variant, where the attacker has actually compromised a supplier's mailbox and replies within a real, existing thread (thread hijacking). Because it comes from a legitimate, authenticated domain with history, authentication checks pass cleanly.

**Malware delivery** evolves as vendors close holes. After Microsoft blocked internet-sourced macros in 2022, attackers moved to ISO/IMG/VHD containers (to dodge Mark-of-the-Web), LNK files, OneNote attachments, HTML smuggling (the HTML file assembles the payload in the browser via JavaScript blobs), password-protected ZIPs with the password in the body, SVG files carrying scripts, and links to payloads hosted on trusted services. Loaders like QakBot's successors, Pikabot, Latrodectus, DarkGate, and various infostealers commonly arrive this way and lead to ransomware.

**Living off trusted sites** is a huge trend. Lures are hosted on or routed through SharePoint, OneDrive, Google Drive, Dropbox, DocuSign, Adobe, Canva, Notion, Webflow, Cloudflare Workers/Pages, IPFS, and open redirects on reputable domains. Reputation-based filtering struggles because the domain genuinely is trustworthy.

**QR code phishing ("quishing")** puts the URL in an image, often inside a PDF, so text-based URL scanning misses it. It also pushes the victim onto a personal phone outside corporate controls.

**Callback phishing / TOAD (Telephone-Oriented Attack Delivery)** sends a fake invoice or subscription renewal with a phone number. The call center then walks the victim into installing remote-access tools. There's nothing malicious in the email to scan.

**OAuth consent phishing** tricks users into granting a malicious app permissions like Mail.Read or offline_access. Resetting the password doesn't remove that access. **Device code phishing** (heavily used by Russian state actors in 2025) gets the victim to enter a code at the legitimate microsoft.com/devicelogin page, handing the attacker tokens.

**Internal phishing** follows any successful compromise. The attacker sends lures from the victim's real mailbox to colleagues and partners, which is far more convincing and bypasses most inbound controls.

**AI-generated lures** have largely eliminated the bad-grammar tell and make targeted, localized, high-volume spear phishing cheap. They also enable deepfake voice follow-ups to BEC emails.

---

## 3. Data sources

Hunting is only as good as the telemetry you can reach. For email, the relevant sources fall into four layers.

**The message layer** includes message trace and delivery logs (sender, recipient, subject, IP, delivery verdict, final location), full headers, authentication results, URL and attachment metadata, and sandbox detonation verdicts. In Microsoft Defender XDR this is the EmailEvents, EmailUrlInfo, EmailAttachmentInfo, and EmailPostDeliveryEvents tables. In Google Workspace it's the Email Log Search and the Security Investigation Tool. Third-party gateways (Proofpoint TAP, Mimecast, Abnormal, Sublime, Cisco) each have their own logs and APIs.

**The user interaction layer** is click telemetry (Safe Links / URL Defense click logs, UrlClickEvents in Defender), user-reported phish submissions, and whether a user clicked through a warning page.

**The identity and mailbox layer** is where post-compromise evidence lives: sign-in logs (Entra ID, Google), mailbox audit logs (including MailItemsAccessed, which shows what an attacker read), inbox rule creation, forwarding changes, MFA method registration, OAuth consent grants, and the Unified Audit Log.

**The endpoint and network layer** shows what happened when an attachment was opened or a link visited: process creation from Outlook or a browser, files written to Downloads or Temp, DNS lookups, proxy logs, and EDR telemetry.

The core hunting skill is **pivoting across these layers using shared keys**. These include NetworkMessageId or Message-ID, recipient UPN, URL, file hash, sender IP, and timestamps.

---

## 4. Email header analysis

Headers are the forensic backbone of email investigation. The most useful fields are these:

| Header | What to look for |
|---|---|
| `From` | Display name spoofing ("CEO Name" <random@gmail.com>), lookalike domains |
| `Return-Path` / envelope `MAIL FROM` | Mismatch with From domain; this is what SPF checks |
| `Reply-To` | Differs from From, a classic BEC sign that routes replies to the attacker |
| `Received` chain | Read bottom-up; the first hop reveals the true origin IP and HELO name |
| `Authentication-Results` | SPF, DKIM, DMARC pass/fail, plus `compauth` in Microsoft |
| `DKIM-Signature` `d=` | Which domain actually signed it; a pass for an unrelated domain is meaningless for trust |
| `ARC-*` | Authentication results preserved through forwarders and mailing lists |
| `Message-ID` | Domain in the ID should typically match the sending infrastructure; odd formats hint at specific mailers or kits |
| `X-Mailer` / `User-Agent` | Mass-mailing tools, PHP mailers, scripting libraries |
| `X-MS-Exchange-*`, `X-Forefront-Antispam-Report` | Microsoft's own verdicts, SCL, country, and IP details |

Remember that **authentication passing does not mean safe**. Attackers register their own domains with perfect SPF, DKIM, and DMARC, use compromised legitimate accounts, or send through Gmail, Outlook.com, and SaaS platforms that authenticate correctly. Authentication tells you the message came from where it claims, not that the sender is benign.

---

## 5. Core hunting techniques

**Stacking (frequency analysis)** is the workhorse. Count occurrences of sender domains, attachment extensions, URL domains, X-Mailer values, or sending IPs, then look at the long tail. Things seen once or twice across the whole organization deserve attention, especially when combined with other weak signals.

**Relationship and first-contact analysis** asks whether this sender has ever emailed this recipient, or anyone in the organization, before. First-time senders requesting payment, sharing documents, or impersonating an internal display name are high-value leads. Behavioral email security vendors built businesses on this idea.

**Lookalike and cousin domain detection** compares inbound sender and link domains against your own domains, and those of your key vendors, using edit distance (Levenshtein), homoglyph substitution (rn→m, l→1, Cyrillic characters, punycode/IDN), added words (-secure, -portal, -invoice), and TLD swaps. Combine this with domain age from WHOIS or passive DNS; anything registered in the last 30 days is suspicious. Tools like dnstwist generate permutations proactively.

**URL analysis** looks at redirect chains, URL shorteners, open redirects on trusted domains, IPFS gateways, Cloudflare Workers/Pages, newly registered domains, unusual TLDs, and URLs containing the recipient's email address (base64 or plain), which many phishing kits use to prefill the login and personalize the page.

**Attachment analysis** focuses on risky types (HTML, SVG, ISO, IMG, VHD, LNK, ONE, JS, VBS, HTA, WSF, password-protected archives), double extensions, and mismatches between extension and actual file type. On the endpoint, the critical hunt is **Outlook or a browser spawning something unusual**: outlook.exe → cmd, powershell, wscript, mshta, rundll32, or msiexec, or a file opened from the Outlook temp cache (Content.Outlook / INetCache) followed by network activity.

**Correlation of click → sign-in** is the single most valuable hunt against AiTM phishing. Find users who clicked a URL, then look for a successful sign-in within minutes from an IP, ASN, or country that the user has never used, especially hosting providers and VPS ranges, often with a different user agent from the user's normal devices.

**Campaign clustering** groups messages by shared attributes (same subject pattern, same sending IP, same URL path structure, same attachment hash, same Message-ID format) so that one reported email expands into the full campaign and every recipient.

---

## 6. Example hunt queries (Microsoft Defender XDR / KQL)

Since many organizations use Microsoft 365, here are practical starting points. Adjust table and column names to your tenant, as the schema evolves.

**First-time external senders with a Reply-To mismatch or payment language:**

```kql
let lookback = 14d;
let known_senders = EmailEvents
    | where Timestamp between (ago(90d) .. ago(lookback))
    | where EmailDirection == "Inbound"
    | distinct SenderFromDomain;
EmailEvents
| where Timestamp > ago(lookback)
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| where SenderFromDomain !in (known_senders)
| where Subject has_any ("invoice","payment","wire","bank details","remittance","urgent","overdue")
| project Timestamp, SenderFromAddress, SenderMailFromAddress, RecipientEmailAddress, Subject, SenderIPv4, AuthenticationDetails
```

**Emails that failed authentication but were still delivered:**

```kql
EmailEvents
| where Timestamp > ago(7d)
| where EmailDirection == "Inbound" and DeliveryAction == "Delivered"
| extend Auth = parse_json(AuthenticationDetails)
| where Auth.DMARC in ("fail") or Auth.SPF in ("fail","softfail") or Auth.CompAuth == "fail"
| summarize Count = count(), Recipients = dcount(RecipientEmailAddress) by SenderFromDomain, SenderIPv4
| order by Recipients desc
```

**Risky attachment types that reached mailboxes:**

```kql
EmailAttachmentInfo
| where Timestamp > ago(14d)
| where FileType in~ ("html","htm","svg","iso","img","vhd","lnk","one","js","vbs","hta","wsf")
    or FileName matches regex @"\.(pdf|docx?|xlsx?)\.(html?|exe|js|lnk)$"
| join kind=inner (EmailEvents | where DeliveryAction == "Delivered") on NetworkMessageId
| project Timestamp, SenderFromAddress, RecipientEmailAddress, FileName, FileType, SHA256, Subject
```

**URL click followed by a sign-in from a new IP (AiTM hunt):**

```kql
let clicks = UrlClickEvents
    | where Timestamp > ago(7d) and ActionType == "ClickAllowed"
    | project ClickTime = Timestamp, AccountUpn, Url, NetworkMessageId;
let signins = AADSignInEventsBeta
    | where Timestamp > ago(7d) and ErrorCode == 0
    | project SigninTime = Timestamp, AccountUpn, IPAddress, Country, UserAgent, Application;
clicks
| join kind=inner signins on AccountUpn
| where SigninTime between (ClickTime .. (ClickTime + 30m))
| summarize by AccountUpn, Url, ClickTime, SigninTime, IPAddress, Country, UserAgent, Application
```

Then filter out the user's historically known IPs and countries, and enrich remaining IPs with ASN data to spot hosting providers.

**Suspicious inbox rules (BEC persistence):**

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("New-InboxRule","Set-InboxRule","UpdateInboxRules")
| extend Raw = tostring(RawEventData)
| where Raw has_any ("RSS Feeds","Conversation History","Archive","DeleteMessage","MoveToFolder","ForwardTo","RedirectTo")
    or Raw has_any ("invoice","payment","bank","wire","helpdesk","phish","hack")
| project Timestamp, AccountDisplayName, IPAddress, ActionType, Raw
```

**Outlook spawning a script host or LOLBin on the endpoint:**

```kql
DeviceProcessEvents
| where Timestamp > ago(14d)
| where InitiatingProcessFileName in~ ("outlook.exe","olk.exe")
| where FileName in~ ("powershell.exe","pwsh.exe","cmd.exe","wscript.exe","cscript.exe","mshta.exe","rundll32.exe","regsvr32.exe","msiexec.exe")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

Equivalent logic applies in Splunk, Sentinel, Google Chronicle, Elastic, or Sublime Security's MQL. The latter has an open library of email detection rules worth studying even if you don't use the product.

---

## 7. Hunting for post-compromise mailbox activity

Many of the most damaging email attacks only become visible after the mailbox is taken over. Classic signs include these:

- **Inbox rules** that move messages to obscure folders like RSS Feeds, Conversation History, or Archive, mark them read, or delete them. Rule names are often a single character, dots, or random strings. Keywords typically target "invoice," "payment," the victim's bank, or words like "hacked" and "phishing" so the victim doesn't see warnings from colleagues.
- **Forwarding** to external addresses via rules, mailbox settings, or transport rules.
- **New MFA methods** registered shortly after a risky sign-in, which the attacker uses for persistence.
- **OAuth app consents** for unfamiliar apps with mail or file permissions, and new service principals or app credentials if an admin was compromised.
- **Mass reading** visible in MailItemsAccessed, often from an IP that doesn't match the user.
- **Outbound anomalies**, such as a burst of sent mail to external contacts, emails with a single link to a file-sharing page, or messages then deleted from Sent Items.
- **Sign-in anomalies**, including impossible travel, hosting-provider ASNs, unusual user agents (python-requests, axios, odd browser strings), and session tokens used from a new IP without a fresh interactive MFA.

In BEC investigations, finance-related threads are the attacker's target. Look for replies inserted into real conversations, sometimes from a lookalike domain registered to match the vendor, so the victim doesn't notice the subtle switch.

---

## 8. Manual analysis of a suspicious email

When hunting surfaces a candidate, or a user reports something, a disciplined triage looks like this. Obtain the original as an .eml or .msg file, never a forwarded copy, because forwarding strips or rewrites headers. Review headers as described above. Extract URLs without clicking and examine them in a sandbox or with services like urlscan.io, VirusTotal, or a detonation environment. Decode QR codes from images. Extract attachments safely, hash them, and check reputation. For Office files use oletools (olevba, oleid); for PDFs use pdfid and pdf-parser; for HTML files, read the JavaScript for base64 blobs, atob calls, or form actions posting to external domains. CyberChef is invaluable for decoding layered obfuscation.

Then **scope the campaign**: search for the same sender, IP, subject pattern, URL, or hash across all mailboxes. Determine who received it, who clicked, who opened, and who entered credentials. Scoping is where hunting and incident response merge.

Tools worth knowing include PhishTool, ThePhish, emlAnalyzer, MailHeader analyzers (Microsoft's Message Header Analyzer, Google's Messageheader), dnstwist, urlscan.io, VirusTotal, ANY.RUN, Joe Sandbox, Hybrid Analysis, MalwareBazaar, and PhishTank/OpenPhish feeds.

---

## 9. Response and remediation

When a hunt confirms malicious activity, act across the same layers you hunted in. **Purge** the messages from all mailboxes using Threat Explorer remediation or Compliance Search and Purge in Microsoft 365, or the Security Investigation Tool in Google Workspace. **Block** the sender, domain, URLs, and hashes in your gateway and tenant allow/block lists. For any user who interacted, **reset credentials, revoke all sessions and refresh tokens** (critical for AiTM, since a password reset alone doesn't kill stolen cookies in all cases), review and remove attacker-added MFA methods, inbox rules, forwarding, and OAuth grants, and check whether the account sent internal phishing. On endpoints, isolate and investigate any host that ran a payload. For BEC, contact your bank immediately. Fast recall requests can sometimes recover wired funds, and in many jurisdictions law enforcement (such as the FBI IC3 in the US, or national cybercrime units in Europe) should be notified.

Finally, **feed findings back**: convert the hunt logic into scheduled detections, update awareness training with the real lure, and tune gateway policies.

---

## 10. Strategic and preventive context

Hunting finds what slips through, but several controls dramatically shrink what there is to find. These include DMARC at p=reject for your own domains (with monitoring for lookalikes), phishing-resistant MFA, Conditional Access requiring compliant devices or token protection, restricting user consent to OAuth apps, blocking legacy authentication, disabling external auto-forwarding by default, external-sender tagging, blocking high-risk attachment types outright, and an easy one-click "report phish" button, since user reports are one of the richest hunting inputs available. Mature programs track metrics like time from delivery to detection, percentage of hunts that produce new detections, click-to-report ratio, and dwell time for mailbox compromises.

---

## 11. Common pitfalls

A few mistakes come up repeatedly. Treating authentication pass as trust is the big one. Others are hunting only inbound mail and ignoring internal and outbound traffic; resetting passwords without revoking sessions after AiTM; investigating forwarded copies instead of originals; ignoring messages that were "only" quarantined after delivery (users may have clicked in the window before zero-hour auto purge); forgetting mobile and personal devices in quishing cases; and failing to retain enough log history. Microsoft's default audit retention, for example, may be shorter than the dwell time of a quiet BEC actor.

---

