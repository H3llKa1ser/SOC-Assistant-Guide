# Threat Hunting with Email Security

## What it is and why email matters

Email threat hunting is the proactive, hypothesis-driven search through email telemetry (and the identity, endpoint, and cloud data connected to it) for malicious activity that your automated controls missed. Detection waits for an alert. Hunting assumes something already got through and goes looking for it.

Email deserves its own hunting discipline for three reasons. It remains the most common initial access vector for ransomware, credential theft, and fraud. Much of today's email threat carries no malware at all: business email compromise (BEC), callback phishing, and credential harvesting through legitimate cloud services can all pass signature and sandbox checks. And a compromised mailbox becomes a launchpad for internal phishing and payment fraud, which makes post-delivery and post-compromise hunting as important as inbound hunting.

A useful mental model is that an email attack has three phases, and you hunt in all of them. **Delivery** covers what arrived, from whom, and how it was authenticated. **Interaction** covers who opened, clicked, scanned a QR code, replied, or ran an attachment. **Consequence** covers what happened next: a suspicious sign-in, a new inbox rule, OAuth consent, mass forwarding, a payment change request, or an endpoint process launched from an attachment.

## The threat landscape you're hunting for

**Credential phishing** is the volume leader. Modern campaigns rarely host fake login pages on obviously bad domains. They abuse trusted platforms (SharePoint, OneDrive, Google Docs/Forms/Sites, Dropbox, DocuSign, Adobe, Canva, Notion, Figma, Webflow), serverless hosting (Cloudflare Workers and Pages, Vercel, Netlify, Azure Blob, Firebase), and IPFS. Adversary-in-the-middle (AiTM) phishing kits proxy the real Microsoft or Google login, capture the session cookie, and defeat standard MFA. Phishing-as-a-service platforms have made this widely available. Filters often miss these because of CAPTCHA and Turnstile gates, geofencing, bot detection, and redirect chains that show sandboxes a benign page.

**QR code phishing ("quishing")** puts the malicious URL inside an image or PDF so that URL rewriting and scanning never see it. The victim scans it on a personal phone that sits outside your endpoint and proxy controls.

**Business email compromise and vendor email compromise** use no payload, only social engineering. They include CEO or executive impersonation, payroll diversion, gift card scams, invoice fraud, and banking detail change requests. Vendor email compromise is especially dangerous because the attacker sends from the vendor's real, compromised mailbox, often replying inside an existing thread, so authentication checks pass.

**Thread hijacking** occurs when attackers reply to stolen, legitimate conversations with malicious links or attachments. Loader families like Qakbot made this famous, and the technique persists.

**Malware delivery** has shifted as Microsoft blocked internet macros. Attackers now use HTML smuggling (an HTML attachment that assembles a payload in the browser), SVG attachments with embedded script or redirects, archives (ZIP, RAR, 7z, often password-protected with the password in the body), disk images (ISO, IMG, VHD) used historically for Mark-of-the-Web bypass, LNK files, OneNote attachments, JavaScript and VBS files, and links to payloads on legitimate file-sharing services.

**Callback phishing (TOAD, telephone-oriented attack delivery)** sends a fake invoice or subscription renewal with a phone number and no link. The victim calls, and the "support agent" talks them into installing remote access tools.

**OAuth consent phishing** tricks users into granting a malicious app access to mail and files. It persists through password resets because it never used the password.

**Internal and lateral phishing** sends phish from a compromised internal account to colleagues. It is highly trusted and often weakly inspected, since many gateways only scan inbound traffic.

**Email bombing plus impersonation** floods a user with thousands of subscription emails, then follows up on Teams or by phone as "IT help desk" offering to fix it. Ransomware affiliates have used this heavily.

**AI-assisted phishing** means grammatical, localized, and personalized lures at scale. The old heuristic of "look for typos" is dead. Hunting has to lean on behavioral and infrastructure signals rather than content quality.

## Mapping to MITRE ATT&CK

Framing hunts in ATT&CK helps with coverage tracking and reporting. The core techniques are T1566 Phishing (with sub-techniques .001 attachment, .002 link, .003 via service, and .004 voice), T1598 Phishing for Information (the reconnaissance variant), T1534 Internal Spearphishing, T1114 Email Collection (including .003 email forwarding rule), T1564.008 Hide Artifacts: Email Hiding Rules, T1528 Steal Application Access Token (OAuth abuse), T1539 Steal Web Session Cookie (AiTM), T1656 Impersonation, and T1204 User Execution. BEC fraud itself falls under impact-oriented techniques such as T1657 Financial Theft.

## Data sources

Good hunting depends on knowing what telemetry you have and how long you keep it.

| Source | What it gives you |
|---|---|
| Message trace / gateway logs | Sender, recipient, subject, sender IP, delivery verdict, size, direction |
| Authentication results | SPF, DKIM, DMARC, composite auth, ARC |
| URL data | Every URL in body and attachments, rewrite status, click events, click-through on warnings |
| Attachment data | File name, type, size, hashes, sandbox verdict |
| Post-delivery events | Zero-hour auto purge (ZAP), admin remediation, user moves, user reports |
| User-reported phish | Often your highest-signal hunting lead |
| Mailbox audit logs | MailItemsAccessed, Send, SendAs, SendOnBehalf, inbox rule creation, forwarding changes |
| Identity / sign-in logs | Sign-ins after a click, impossible travel, new devices, token anomalies, MFA registration changes |
| OAuth / app consent logs | New app grants, high-privilege scopes like Mail.Read or Mail.Send |
| Endpoint telemetry | Processes spawned from Outlook, browsers, or archive tools; files written from attachments |
| Proxy / DNS logs | Clicks that happened outside the rewrite (copy-pasted links, QR scans on managed networks) |
| DMARC aggregate (RUA) reports | Who is sending as your domain, including spoofing and shadow IT |
| Full message headers | Received chain, Return-Path, Reply-To, Message-ID, X-Originating-IP, vendor-specific headers |

In Microsoft Defender XDR advanced hunting, the core tables are `EmailEvents`, `EmailUrlInfo`, `EmailAttachmentInfo`, `EmailPostDeliveryEvents`, and `UrlClickEvents`, joined on `NetworkMessageId`, plus `CloudAppEvents` for mailbox and Exchange activity and sign-in tables for identity. Default retention in advanced hunting is 30 days, so if you want to hunt historical campaigns, stream this data to a SIEM like Sentinel, Splunk, or Databricks.

## Header analysis fundamentals

Knowing headers well is the foundation of every email investigation.

The **Received** headers are read bottom to top. The lowest one closest to your infrastructure that you trust tells you the real sending IP. Everything above your own servers is attacker-controllable.

**From (header From) vs. envelope sender (MAIL FROM / Return-Path)** is the distinction that matters most. SPF validates the envelope sender, and users see the header From. DMARC ties them together through alignment. A pass on SPF for `bounce.randomsaas.com` means nothing about whether the visible From is legitimate.

A **Reply-To** that differs from From, especially to a freemail address or a lookalike domain, is a classic BEC signal.

A **Message-ID** domain that doesn't match the sending infrastructure can reveal the real sending tool or platform.

**Authentication-Results** shows SPF, DKIM, and DMARC verdicts. A "compauth" (composite authentication) in Microsoft environments summarizes implicit authentication for domains without DMARC enforcement.

A **display name** set to an executive's name but with an external address is one of the simplest and most productive BEC hunts.

Understanding authentication failures helps too. SPF breaks on forwarding. DKIM survives forwarding unless the body is modified, which mailing lists and some gateways do. ARC exists to preserve authentication across intermediaries. Many "suspicious" failures are just broken forwarding, which is why raw auth failure hunting is noisy without context.

## Hunting methodology

Structured frameworks keep hunts repeatable. PEAK (Prepare, Execute, Act with Knowledge) and TaHiTI are the two most common, and both split hunting into hypothesis-driven, intelligence-driven, and baseline or anomaly-driven types.

**Hypothesis-driven hunts** start from an attacker behavior: "An attacker who compromised a mailbox through AiTM would create an inbox rule to hide replies within hours of the sign-in."

**Intelligence-driven hunts** start from indicators or a campaign report: a new phishing kit, a sender domain, a hash, a lure theme, and a sweep for them across your retention window. IOC sweeps are the least durable form of hunting. Pivot quickly from IOCs to the behaviors and infrastructure patterns behind them.

**Baseline and anomaly hunts** use statistics to find the rare: first-time senders to finance, rare attachment types, rare sending IPs for a known partner, unusual send volume from an internal user.

A good hunt cycle runs like this in practice. Define the hypothesis and the ATT&CK technique. Identify the required data and confirm you actually have it. Write the query, starting broad and narrowing. Triage results, separating true positive, benign true positive, and false positive. Pivot on anything suspicious (same sender, same URL domain, same IP, same subject cluster, same attachment hash) to scope the campaign. Respond. Then, crucially, convert the hunt into a scheduled detection or an automated rule if it proved valuable, and document what you learned. Hunts that don't produce detections, tuning, or visibility-gap tickets are wasted effort.

## High-value hunting hypotheses and example queries

The queries below use Defender XDR KQL because it's the most common platform, but the logic translates to Proofpoint, Mimecast, Sublime, Abnormal, or any SIEM. Column names can change between schema updates, so validate them in your tenant before operationalizing anything.

### 1. Clicked a link, then a suspicious sign-in (AiTM detection)

This is arguably the most valuable email hunt, because it connects delivery to consequence.

```kql
let clicks = UrlClickEvents
| where Timestamp > ago(7d)
| where ActionType in ("ClickAllowed", "UrlScanInProgress") or IsClickedThrough == true
| project ClickTime = Timestamp, AccountUpn, Url, NetworkMessageId, ClickIP = IPAddress;
AADSignInEventsBeta
| where Timestamp > ago(7d)
| where ErrorCode == 0
| project SignInTime = Timestamp, AccountUpn, SignInIP = IPAddress, Country, Application, UserAgent
| join kind=inner clicks on AccountUpn
| where SignInTime between (ClickTime .. (ClickTime + 1h))
| where SignInIP != ClickIP
| project ClickTime, SignInTime, AccountUpn, Url, ClickIP, SignInIP, Country, Application, UserAgent
```

A successful sign-in from a different IP shortly after a click, particularly from hosting-provider or VPS ASNs or with an unusual user agent, strongly suggests session token theft.

### 2. New inbox rules that hide or forward mail

Attackers create rules that move messages containing words like "invoice," "payment," "phish," "hacked," or the victim's IT helpdesk address into obscure folders (RSS Feeds, RSS Subscriptions, Conversation History, Archive) or delete them, so the victim never sees replies or warnings.

```kql
CloudAppEvents
| where Timestamp > ago(30d)
| where ActionType in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| extend Params = tostring(RawEventData.Parameters)
| where Params has_any ("DeleteMessage", "MoveToFolder", "ForwardTo", "RedirectTo", "ForwardAsAttachmentTo", "MarkAsRead")
| where Params has_any ("RSS", "Archive", "Conversation History", "invoice", "payment", "wire", "bank", "phish", "hack", "security", "helpdesk")
    or Params matches regex @"Name\W+[\.\s,;]{1,3}\W"
| project Timestamp, AccountDisplayName, IPAddress, ActionType, Params
```

The last condition catches rules named with a single character like "." or ",", which is a very common attacker habit. Also hunt `Set-Mailbox` with `ForwardingSmtpAddress` for mailbox-level forwarding to external addresses.

### 3. Executive display name impersonation

```kql
let vips = dynamic(["Jane Smith", "John Doe"]); // your executives and finance leaders
EmailEvents
| where Timestamp > ago(14d)
| where EmailDirection == "Inbound"
| where SenderDisplayName has_any (vips)
| where SenderFromDomain !in ("yourcompany.com")
| project Timestamp, SenderDisplayName, SenderFromAddress, RecipientEmailAddress, Subject, DeliveryAction, ThreatTypes
```

Pair this with a check on Reply-To mismatches if your gateway logs it, and with content cues like "are you available," "quick favor," "confidential," and "urgent payment."

### 4. First-time senders reaching finance with payment language

```kql
let finance = dynamic(["ap@yourcompany.com", "payroll@yourcompany.com"]);
let known = EmailEvents
| where Timestamp between (ago(90d) .. ago(7d))
| distinct SenderFromDomain;
EmailEvents
| where Timestamp > ago(7d)
| where RecipientEmailAddress in (finance)
| where SenderFromDomain !in (known)
| where Subject has_any ("invoice", "payment", "remittance", "bank", "account change", "wire", "ACH", "overdue")
| project Timestamp, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, DeliveryAction
```

### 5. Lookalike domains of your own brand and key vendors

Hunt for domains that are within a small edit distance of your domain or your top vendors' domains, contain homoglyphs (rn for m, 0 for o, Cyrillic characters), use punycode (`xn--`), or add words like "-secure," "-invoice," "-support." KQL doesn't have native Levenshtein, but you can prefilter on substrings and punycode, then score in Python or a notebook. Cross-reference hits against domain registration age; domains registered in the last 30 days sending to you are high-signal. External brand-monitoring and certificate transparency log monitoring (for certificates issued to lookalikes) complements this.

### 6. Rare and risky attachment types

```kql
EmailAttachmentInfo
| where Timestamp > ago(14d)
| extend Ext = tolower(tostring(split(FileName, ".")[-1]))
| where Ext in ("html", "htm", "shtml", "svg", "iso", "img", "vhd", "vhdx", "lnk", "one", "js", "jse", "vbs", "wsf", "hta", "xll", "chm", "msi", "url", "library-ms")
| join kind=inner (EmailEvents | project NetworkMessageId, SenderFromAddress, Subject, DeliveryAction, EmailDirection) on NetworkMessageId
| where DeliveryAction == "Delivered"
| summarize Count = count(), Recipients = make_set(RecipientEmailAddress, 50) by Ext, SenderFromAddress, Subject
| order by Count desc
```

HTML and SVG attachments deserve special attention, because they're heavily used for credential phishing and HTML smuggling and are rarely needed for legitimate business. Encrypted archives are another strong signal because sandboxes can't open them.

### 7. Links to abused legitimate hosting and newly observed domains

```kql
EmailUrlInfo
| where Timestamp > ago(7d)
| where UrlDomain has_any ("workers.dev", "pages.dev", "ipfs", "r2.dev", "web.app", "firebaseapp.com", "glitch.me", "netlify.app", "vercel.app", "blob.core.windows.net", "sites.google.com", "forms.gle", "docs.google.com", "canva.site", "notion.site", "webflow.io", "ngrok")
| join kind=inner (EmailEvents | where EmailDirection == "Inbound" and DeliveryAction == "Delivered") on NetworkMessageId
| summarize Messages = dcount(NetworkMessageId), Recipients = dcount(RecipientEmailAddress) by UrlDomain, SenderFromDomain
| order by Recipients desc
```

Tune this against your own business: some of these domains are used legitimately. The question is whether a first-time or low-reputation sender is linking to them.

### 8. Quishing: messages with images or PDFs and no or few URLs

A crude but useful proxy is inbound mail with an image or PDF attachment, zero or one URLs, and a short body with MFA, password, document-signing, or benefits themes. Some platforms (Defender, Sublime, Abnormal, Proofpoint) now extract QR codes and expose the decoded URL, so check whether yours does. Where QR codes are decoded, hunt those URLs exactly like any other.

### 9. Delivered messages later caught by ZAP, then clicked

```kql
EmailPostDeliveryEvents
| where Timestamp > ago(7d)
| where ActionType has "ZAP"
| join kind=inner (UrlClickEvents | project ClickTime = Timestamp, NetworkMessageId, AccountUpn, Url) on NetworkMessageId
| where ClickTime < Timestamp
| project ZapTime = Timestamp, ClickTime, AccountUpn, Url, ThreatTypes
```

This finds users who clicked in the window between delivery and retroactive removal. Each hit is someone who needs a follow-up sign-in and endpoint check.

### 10. Internal account behaving like a spammer

Hunt for internal senders whose volume, recipient count, or number of external recipients spikes far above their baseline, especially with the same subject to many recipients or messages containing links to file-sharing pages. This catches compromised accounts used for lateral phishing or outbound spam.

```kql
EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection in ("Intra-org", "Outbound")
| summarize Daily = count() by SenderFromAddress, Day = bin(Timestamp, 1d)
| summarize Avg = avg(Daily), Std = stdev(Daily), Max = max(Daily) by SenderFromAddress
| where Max > Avg + 5 * Std and Max > 100
```

### 11. Suspicious OAuth consent after an email

Look for new app consents granting `Mail.Read`, `Mail.ReadWrite`, `Mail.Send`, `offline_access`, or `Files.ReadWrite.All`, particularly to unverified publishers, apps with generic names ("Outlook Sync," "Mail Security," "PDF Viewer"), or apps created in foreign tenants shortly before consent.

### 12. Email bombing precursor to help-desk impersonation

Hunt for a single recipient receiving an abnormal number of newsletter or subscription confirmations within a short window, then correlate against external Teams chats or calls to that user and any remote-access tool installs (Quick Assist, AnyDesk, ScreenConnect) on their endpoint.

### 13. Attachments launched by the user

Correlate `EmailAttachmentInfo` SHA256 values with endpoint file and process events. Parent-child chains matter most: `outlook.exe` or a browser leading to archive tools, then to `wscript`, `mshta`, `rundll32`, `regsvr32`, `powershell`, or an unfamiliar executable in a Temp or Downloads path.

## Scoping and pivoting a campaign

When a hunt finds one bad message, assume there are more. Pivot on the sender address and domain, the sending IP and its /24 and ASN, the subject and its variations (attackers rotate subjects but keep structure), the URL domain and URL path patterns, the attachment hash and file name patterns, and the email cluster ID if your platform provides one (Defender groups similar messages by content fingerprint). Then identify every recipient, every one who clicked or opened, and every one who then showed a consequence signal. That produces three concentric circles: exposed, interacted, and likely compromised. Each circle gets a different response.

## Response actions

For the message itself: soft-delete or purge from all mailboxes, block the sender, domain, and URL, and submit false negatives to your vendor so their models improve.

For users who interacted: revoke sessions and refresh tokens (resetting a password alone doesn't kill a stolen session cookie in AiTM cases), reset credentials, review and re-register MFA methods, remove malicious inbox rules and forwarding, revoke suspicious OAuth grants, review mailbox audit logs for what the attacker accessed (MailItemsAccessed) and sent, and isolate and investigate endpoints for attachment-based cases.

For BEC with financial exposure: engage finance immediately, contact the bank to attempt a recall, and in the US file with the FBI's IC3 quickly, since recovery odds drop rapidly after the first day or two. Notify affected vendors or customers if a compromised mailbox was used to contact them.

## Turning hunts into durable controls

Mature programs treat each hunt as a potential engineering output. A hunt that finds real activity becomes a scheduled detection rule with tuned thresholds, a gateway or transport rule (for example, tagging or quarantining HTML attachments from external senders, warning banners on first-time senders, or blocking newly registered domains), a SOAR playbook (auto-triaging user-reported phish, auto-purging clusters that match a confirmed bad message), or a visibility gap ticket (for example, "we can't see QR code URLs" or "we don't retain mailbox audit logs beyond 90 days").

Some platforms are built around this model. Sublime Security exposes a detection language (MQL) specifically for writing email detection rules and hunting over them, and publishes an open rules repository that's worth studying even if you don't use the product. Defender custom detections can be created directly from advanced hunting queries.

## Foundational controls that make hunting easier

Several controls reduce noise and make the remaining signal sharper. Enforce DMARC at `p=reject` on your own domains and monitor aggregate reports. Use phishing-resistant MFA (FIDO2 keys, passkeys, Windows Hello for Business) to neutralize AiTM, which is the single biggest risk-reduction lever against credential phishing. Apply conditional access with device compliance and token protection where available. Restrict user consent to OAuth apps so only verified publishers or admin-approved apps are allowed. Disable automatic external forwarding by default. Enable mailbox auditing and make sure retention matches your hunting needs. Build an easy "report phish" button and a fast triage feedback loop, because user reports are one of the best hunting inputs you have, and users who get feedback keep reporting.

## Metrics worth tracking

Useful measures include mean time from delivery to removal for malicious messages, the click rate on messages later confirmed malicious, user-reported phish volume and true positive rate, the number of hunts converted into detections, coverage against the ATT&CK techniques listed above, and time from click to session revocation for confirmed compromises. Avoid vanity metrics like "number of emails blocked," which mostly measure spam volume.

## Common pitfalls

Teams often hunt only inbound mail and ignore internal and outbound traffic, where compromised accounts show up. Many treat authentication failures as high fidelity when forwarding and mailing lists make them noisy. Some rely on password resets after AiTM when session revocation is what matters. IOC-only hunting has a short shelf life because phishing infrastructure is disposable. Retention gaps quietly kill investigations, since 30 days of advanced hunting data is often not enough to scope a BEC that started two months ago. Finally, hunts that aren't documented and converted into detections have to be rediscovered every time.

## Tools and resources

The main platforms are Microsoft Defender for Office 365 (Threat Explorer, advanced hunting, AIR), Proofpoint (TAP, TRAP), Mimecast, Abnormal Security (behavioral, API-based), Sublime Security, Cisco Secure Email, and Google Workspace's security investigation tool. Useful free and analyst tools include URLScan.io, VirusTotal, Any.Run and Joe Sandbox for detonation, PhishTool and MXToolbox's header analyzer, dnstwist for lookalike domain generation, and CyberChef for decoding obfuscated HTML and base64 payloads. For learning, Microsoft's advanced hunting query repositories on GitHub, Sublime's open detection rules repo, the MITRE ATT&CK pages for T1566 and T1114, and vendor threat reports on phishing kits and BEC trends are all good starting points.

