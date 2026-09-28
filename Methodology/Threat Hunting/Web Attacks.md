# Threat Hunting for Web Attacks

## 1. What threat hunting is, and why web apps are a prime target

Threat hunting is the proactive, human-led search for adversary activity that your existing detections missed. Alerting waits for a rule to fire. Hunting starts from the assumption that you are already compromised and tests that assumption with a hypothesis, data, and analysis. Anything you find gets turned into a new automated detection, so each hunt raises your baseline.

Web applications deserve special attention for several reasons. They are internet-facing by design, so anyone can reach them. They sit on a trust boundary, so web servers often hold database credentials, API keys, cloud roles, and routes into internal networks. Traffic is mostly HTTPS, which hides attacks from network sensors unless you decrypt at the load balancer or proxy. Legitimate traffic is huge and noisy, which lets malicious requests blend in. Finally, exploitation of public-facing applications (MITRE ATT&CK T1190) is consistently one of the top initial access vectors in breach reports, alongside stolen credentials and phishing. Mass exploitation of edge devices and web frameworks (Log4Shell, MOVEit, Citrix, Ivanti, Confluence, Exchange ProxyShell) has made this worse.

## 2. The attack landscape you are hunting for

It helps to organize web attacks by where they land and what they leave behind.

**Injection attacks.** These include SQL injection, OS command injection, LDAP/XPath injection, NoSQL injection, server-side template injection (SSTI), and expression language injection such as Log4Shell's JNDI lookups and Spring4Shell. They show up in request parameters, headers, cookies, and bodies. They often cause errors, abnormal response sizes, or unusual response times.

**Client-side attacks.** Cross-site scripting (reflected, stored, DOM-based), CSRF, clickjacking, and web skimming (Magecart) belong here. Skimming is especially sneaky because the malicious code runs in the victim's browser. Your server logs may show nothing except a modified JavaScript file.

**File and path attacks.** These include path traversal, local and remote file inclusion (LFI/RFI), unrestricted file upload, and XXE (XML external entities). They are the usual precursors to webshells.

**Server-side request forgery (SSRF).** The attacker makes your server fetch URLs on their behalf. Common targets are cloud metadata services (169.254.169.254), internal admin panels, and localhost-only services.

**Deserialization and RCE in frameworks.** Java, .NET ViewState, PHP, Python pickle, and Ruby deserialization bugs, plus framework CVEs, lead straight to code execution.

**Webshells and persistence (T1505.003).** This is the most important post-exploitation artifact to hunt. A webshell is a script (ASPX, JSP, PHP, and so on) dropped on the server that gives the attacker a command interface over HTTP. Variants include one-liners like China Chopper, full-featured shells like Godzilla, Behinder, and AntSword with encrypted traffic, and memory-resident shells injected as servlet filters or IIS modules that never touch disk.

**Authentication and session attacks.** These include credential stuffing, password spraying, brute force, MFA fatigue, session hijacking, token theft, JWT tampering (alg=none, weak secrets, key confusion), and OAuth misconfiguration abuse.

**API and business logic abuse.** Broken object-level authorization (BOLA/IDOR) is the top API risk. Others are mass assignment, excessive data exposure, rate-limit bypass, coupon and gift card abuse, inventory hoarding, and scraping. These are hard to catch because each individual request looks legitimate.

**Reconnaissance and automated scanning.** Directory brute forcing, vulnerability scanners, and fingerprinting are noisy but useful. A scan followed by a single quiet, successful request is a classic pattern.

**Denial of service at layer 7.** Slowloris, expensive search queries, and ReDoS fall here. They are sometimes used as distractions.

The OWASP Top 10 and the OWASP API Security Top 10 are the standard references for this taxonomy.

## 3. Data sources: what to collect

Hunting succeeds or fails on visibility. In rough order of value:

**Web server access logs** (IIS W3C, Apache/Nginx combined, Tomcat) are the backbone. Make sure you log timestamp with timezone, client IP, the true client IP from X-Forwarded-For if behind a proxy, HTTP method, full URI including query string, status code, bytes sent and received, response time, user agent, referrer, host header, and ideally a session or user identifier. Default formats often omit response time and request size, which are extremely useful, so add them.

**Reverse proxy, load balancer, and CDN logs** (AWS ALB/CloudFront, Azure Front Door/App Gateway, Cloudflare, Akamai, F5) are often the only place where you see the real client IP, TLS details, and requests blocked before they reach the origin.

**WAF logs** (ModSecurity with the OWASP Core Rule Set, AWS WAF, Cloudflare, Imperva) contain rule hits, anomaly scores, and sometimes request bodies. Blocked requests are useful for understanding intent. Allowed requests that scored just below the blocking threshold are gold for hunting.

**Application logs** record authentication events, authorization failures, business events like password resets, orders, and exports, stack traces, and exceptions. Stack traces mentioning SQL syntax, deserialization, or template engines are strong signals.

**Endpoint telemetry on web servers** (EDR, Sysmon for Windows and Linux, auditd, osquery) is arguably the single highest-value source for catching successful exploitation. It shows the web server process spawning a shell, file writes into the web root, and outbound connections.

**Network data** comes from Zeek (http.log, conn.log, ssl.log, files.log), Suricata/Snort, full PCAP where possible, and TLS fingerprints (JA3/JA3S, the newer JA4+ suite). Egress traffic from web servers is particularly valuable, because web servers should have very predictable outbound behavior.

**DNS logs from web servers** catch out-of-band exfiltration and callback tests (Burp Collaborator/interactsh-style domains, Log4Shell callbacks).

**Database audit logs** reveal unusual query patterns, UNION queries, access to information_schema or system tables, and large result sets.

**Cloud control-plane logs** (CloudTrail, Azure Activity, GCP Audit) matter because stolen instance credentials obtained via SSRF get used here, often from an IP that is not the instance itself.

**File integrity monitoring and deployment records** let you distinguish a legitimate new file in the web root from a dropped webshell.

**Browser-side telemetry** includes Content Security Policy violation reports and subresource integrity failures. These are the main way to catch client-side skimming.

A practical note: request bodies are usually not logged, so POST-based attacks are often invisible in access logs. The URI, size, frequency, and endpoint behavior have to carry the weight.

## 4. Frameworks and methodology

**The hunting loop.** Form a hypothesis, investigate with tools and data, uncover patterns, then inform and enrich by creating detections and documenting findings. This is the classic Sqrrl model.

**PEAK (Prepare, Execute, Act with Knowledge)** from Splunk's SURGe team distinguishes three hunt types. Hypothesis-driven hunts test a specific idea. Baseline or exploratory hunts characterize normal to find outliers. Model-assisted hunts use ML or statistical models to surface anomalies.

**TaHiTI** is a threat-intelligence-driven methodology from the Dutch financial sector. It works well when a new CVE or campaign report triggers the hunt.

**MITRE ATT&CK** gives you the vocabulary. Relevant techniques include T1190 (Exploit Public-Facing Application), T1505.003 (Web Shell), T1059 (Command and Scripting Interpreter), T1071.001 (Web Protocols for C2), T1110 (Brute Force, including .003 spraying and .004 stuffing), T1078 (Valid Accounts), T1552.005 (Cloud Instance Metadata API), T1595 (Active Scanning), T1083 (File and Directory Discovery), and T1567/T1041 (exfiltration).

**The Pyramid of Pain** reminds you to hunt behaviors (TTPs) rather than just IPs and hashes. An attacker can change their IP in seconds. It is much harder for them to avoid the web server process spawning `whoami`.

**The Hunting Maturity Model (HMM0 to HMM4)** runs from relying only on alerts, through using threat intel IOCs, following published procedures, creating your own procedures, and finally automating successful hunts into detections.

A good web hunt hypothesis is specific and testable. For example: "An attacker has exploited a vulnerability in our internet-facing Java application and deployed a JSP webshell, which would cause the Tomcat process to spawn shell interpreters and would appear as a rarely accessed URI receiving POST requests from a small number of IPs."

## 5. Core analytic techniques

**Stacking (frequency analysis).** Count occurrences of a field and examine the rare end. Rare URIs, rare user agents, rare parent-child process pairs, and rare file extensions in upload directories are all productive. Attackers are usually the long tail.

**Baselining.** Establish what normal looks like per application: typical status code distribution, typical request sizes per endpoint, normal outbound destinations, normal child processes. Then look for deviation.

**Normalization and decoding.** Attackers use URL encoding, double encoding, Unicode, mixed case, comments inside SQL (`UN/**/ION`), and string concatenation to evade signatures. Decode (repeatedly) and lowercase before pattern matching, or you will miss most of what matters.

**Entropy and length analysis.** Encrypted webshell traffic and encoded payloads produce parameters with high Shannon entropy or unusual length. Very long query strings and base64-looking blobs are worth a look.

**Sessionization.** Group requests by IP, session, or user into time-bounded sessions. Then look at sequences, such as a burst of 404s followed by one 200, or a login followed immediately by access to an admin endpoint the user never touches.

**Response-side analysis.** Status codes and response sizes tell you whether an attack worked. A SQLi probe that returned 200 with a far larger response than usual is more interesting than a thousand that returned 403.

**Timing analysis.** Response times that cluster around 5 or 10 seconds on one endpoint suggest time-based blind SQL injection (`SLEEP()`, `WAITFOR DELAY`, `pg_sleep`).

**Beaconing detection.** For outbound traffic from web servers, compute the interval between connections to a destination. Low variance (low standard deviation relative to the mean) suggests automated C2. Tools like RITA do this on Zeek data.

**Fingerprinting.** Use JA3/JA4 TLS fingerprints, HTTP header order, and user agent consistency to identify automation. A "Chrome" user agent with a Python requests TLS fingerprint is a liar.

**Graph and relationship analysis.** Map IPs to usernames to sessions. Credential stuffing shows many usernames per IP. Distributed stuffing shows many IPs per username, or many IPs sharing one fingerprint.

## 6. Hunt playbooks with signals and example queries

The queries below are illustrative. Field names vary by environment, so adapt them to your schema.

### Hunt 1: Web server processes spawning shells (webshell or RCE)

This is the highest-yield web hunt there is. Web server worker processes (w3wp.exe, httpd, nginx, php-fpm, java/tomcat, node, python/gunicorn) should almost never spawn command interpreters or reconnaissance tools. When they do, it is either a strange legitimate application feature, which you document and baseline, or an attacker.

Look for children such as cmd.exe, powershell.exe, whoami, net.exe, nltest, certutil, bitsadmin, rundll32, csc.exe (for runtime compilation), and on Linux sh, bash, curl, wget, nc, python, perl, id, uname. Also look at command lines for encoded PowerShell, downloads, or reconnaissance.

KQL for Microsoft Defender:

```kql
DeviceProcessEvents
| where Timestamp > ago(30d)
| where InitiatingProcessFileName in~ ("w3wp.exe","httpd.exe","nginx.exe","php-cgi.exe","tomcat9.exe","java.exe","node.exe")
| where FileName in~ ("cmd.exe","powershell.exe","pwsh.exe","whoami.exe","net.exe","net1.exe",
                      "nltest.exe","certutil.exe","bitsadmin.exe","rundll32.exe","csc.exe","systeminfo.exe")
| summarize count(), make_set(ProcessCommandLine, 20), min(Timestamp), max(Timestamp)
    by DeviceName, InitiatingProcessFileName, FileName
| order by count_ asc
```

Sorting ascending surfaces the rare combinations first. Linux equivalents come from auditd `execve` records or Sysmon for Linux Event ID 1, filtering on a parent of apache2, httpd, nginx, php-fpm, or java.

### Hunt 2: Webshell artifacts on disk and in logs

On disk, look for new or modified script files in web-accessible directories that do not match a deployment, script files in upload or image directories (a `.aspx` or `.php` in `/uploads/` is almost always bad), files with timestamps that were stomped to look old, and content indicators like `eval(`, `assert(`, `base64_decode(`, `System.Reflection.Assembly.Load`, `Runtime.getRuntime().exec`, `ProcessBuilder`, and obfuscated or high-entropy code. YARA rulesets such as Florian Roth's signature-base contain many webshell rules, and scanners like THOR/LOKI apply them. Sysmon Event ID 11 (file create) with the web server process as the creator and a script extension as the target is an excellent detection.

In access logs, webshells tend to look like URIs that are accessed by very few distinct IPs, receive mostly POST requests, return 200, have no referrer, and were first seen recently. A long-tail query in Splunk:

```spl
index=web sourcetype=access_combined status=200
| stats count, dc(src_ip) AS distinct_ips, values(http_method) AS methods,
        earliest(_time) AS first_seen, latest(_time) AS last_seen
        by uri_path
| where distinct_ips <= 3 AND match(uri_path, "(?i)\.(aspx|ashx|asmx|jsp|jspx|php|phtml|cfm)$")
| convert ctime(first_seen) ctime(last_seen)
| sort distinct_ips, count
```

Then compare the results against your list of legitimate application files.

Memory-resident webshells (Java filter or servlet injection, IIS native modules, .NET assembly loads) won't be caught by file scanning. Hunt for unusual .NET assemblies loaded into w3wp, unsigned IIS modules (`appcmd list modules`), and Java agent attachments or unexpected classes, using tools like Velociraptor artifacts or memory analysis.

### Hunt 3: Injection attempts, and especially successful ones

Pattern matching on decoded URIs catches the noisy attempts. Common indicators include `union select`, `' or 1=1`, `information_schema`, `sleep(`, `benchmark(`, `waitfor delay`, `xp_cmdshell`, `<script`, `onerror=`, `javascript:`, `{{7*7}}` and `${7*7}` (template injection probes), `${jndi:` and its obfuscations like `${${lower:j}ndi:`, `;id`, `|whoami`, `` `...` `` and `$(...)` (command injection).

A quick triage pass on raw logs:

```bash
grep -Eai "(union.{1,20}select|information_schema|sleep\(|waitfor%20delay|xp_cmdshell|<script|onerror=|\\\$\{jndi:|%24%7Bjndi|\.\./|%2e%2e|/etc/passwd|win\.ini|169\.254\.169\.254)" access.log \
  | awk '{print $1, $9, $7}' | sort | uniq -c | sort -rn | head -50
```

This is a starting point, not a detection strategy, because encoding variations defeat simple grep. The real hunting value is separating attempts from successes. Filter the matches to status 200, compare the response size to the endpoint's normal size, and look for response time clustering. An IP that sends two hundred probes and then one request with an abnormally large response deserves immediate attention. Database error messages in application logs (for example "You have an error in your SQL syntax," "ORA-01756," "unclosed quotation mark") paired with a specific source IP are also strong evidence.

### Hunt 4: Path traversal and file inclusion

Look for `../`, `..\`, `%2e%2e%2f`, `%252e%252e` (double-encoded), `..%c0%af` (overlong UTF-8), null bytes (`%00`), and targets like `/etc/passwd`, `/proc/self/environ`, `web.config`, `WEB-INF/web.xml`, `win.ini`, `.env`, and `.git/config`. Responses of 200 with sizes that match those files are successes. RFI shows up as parameters containing `http://` or `php://`, `data://`, `expect://`, or `file://` wrappers.

### Hunt 5: SSRF and cloud credential theft

Look in access logs for parameters containing internal addresses: `169.254.169.254`, `metadata.google.internal`, `localhost`, `127.0.0.1` and its alternate forms (`0x7f000001`, `2130706433`, `[::1]`), RFC1918 ranges, and `gopher://` or `dict://` schemes.

The stronger hunt is on the network and cloud side. Look for outbound connections from web servers to the metadata service by processes other than the expected agents. In AWS, look for instance role credentials used from an IP address outside your environment. GuardDuty's `InstanceCredentialExfiltration` findings cover this. Enforcing IMDSv2 dramatically reduces SSRF impact, so hunting for IMDSv1 usage is also worthwhile as a posture check.

### Hunt 6: Reconnaissance followed by exploitation

Scanners generate bursts of 404s and 403s, predictable wordlist paths (`/admin`, `/.env`, `/wp-login.php`, `/phpmyadmin`, `/actuator`, `/.git/HEAD`, `/server-status`), and telltale user agents (sqlmap, Nikto, Nuclei, gobuster, ffuf, WPScan, masscan, zgrab). Most of this is background internet noise, so don't chase it all. The productive question is: which scanning sources later made successful, unusual requests? Or, which sources hit exactly the paths associated with a newly published CVE, before or shortly after disclosure?

```spl
index=web
| eval is_err=if(status>=400 AND status<500,1,0)
| stats sum(is_err) AS errors, count AS total, dc(uri_path) AS unique_paths,
        values(eval(if(status=200, uri_path, null()))) AS successful_paths
        by src_ip
| where errors > 100 AND unique_paths > 50
| sort -errors
```

Then examine `successful_paths` for anything outside normal site navigation.

### Hunt 7: Credential stuffing, spraying, and brute force

The key signals are high volumes of login POSTs, low success rates, and relationships between IPs and accounts. Stuffing from a single source shows many distinct usernames per IP. Distributed stuffing through residential proxies shows each IP making only a few attempts, so you pivot on shared attributes like user agent, JA3/JA4 fingerprint, header ordering, ASN, or timing. Password spraying shows one or a few passwords tried across many accounts, slowly.

```spl
index=web uri_path="/api/login" http_method=POST
| eval success=if(status=200 OR status=302, 1, 0)
| stats count AS attempts, dc(username) AS distinct_users, sum(success) AS successes by src_ip
| eval success_rate=round(successes/attempts, 3)
| where distinct_users > 10 AND success_rate < 0.05
| sort -attempts
```

The critical follow-up: for accounts that did log in successfully from suspicious sources, what did the session do next? Password changes, email or MFA changes, payment method additions, data exports, and gift card redemptions are the common monetization steps.

### Hunt 8: Session hijacking and token abuse

The same session ID or refresh token used from multiple IPs, countries, ASNs, or user agents within a short window suggests theft, often via infostealer malware or adversary-in-the-middle phishing kits. Also look for JWTs with `alg` set to `none` or `HS256` where you expect `RS256`, tokens with expiry times far in the future, and privilege claims that don't match the user's actual role.

### Hunt 9: API abuse and BOLA

For each authenticated user, count the distinct object IDs accessed on endpoints like `/api/orders/{id}` or `/api/users/{id}`. Legitimate users touch a small number of their own objects. An account that walks sequentially through thousands of IDs, especially with a mix of 200 and 403 responses, is enumerating. Also watch for unexpected parameters in requests (mass assignment attempts like `"role":"admin"` or `"isAdmin":true`), use of deprecated API versions, and endpoints accessed that never appear in your documented API spec (shadow APIs).

### Hunt 10: Egress anomalies and C2 from web servers

Web servers usually talk to a short list of destinations: databases, caches, a few APIs, update servers. Stack outbound destinations per server and investigate anything new or rare, especially connections initiated by the web server process itself, connections to paste sites, file sharing, or tunneling services (ngrok, Cloudflare tunnels abused by attackers), DNS queries to out-of-band testing domains (`*.oast.*`, `*.interact.sh`, `*.burpcollaborator.net`, dnslog services), and beaconing intervals. New listening ports on web servers can indicate bind shells or tunnels.

### Hunt 11: Data exfiltration through the web tier

Look for unusually large responses on endpoints that normally return small ones, bulk export or report endpoints used by unusual accounts or at unusual times, archive files (`.zip`, `.rar`, `.7z`, `.tar.gz`) appearing in web directories and then being downloaded (attackers stage data this way), and database dumps.

### Hunt 12: Client-side skimming (Magecart-style)

Server logs rarely help here. Instead, hunt by monitoring integrity of JavaScript served on checkout and login pages (hash comparison against known-good builds), reviewing CSP violation reports for new external domains, diffing third-party script inventories, and watching for scripts that attach listeners to form fields and send data to domains that imitate legitimate analytics or CDN names.

## 7. Turning a hunt into a detection: a Sigma example

Sigma is a vendor-neutral rule format that converts to Splunk, KQL, Elastic, and others. A simplified webshell process rule:

```yaml
title: Web Server Process Spawning Suspicious Child
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  parent:
    ParentImage|endswith:
      - '\w3wp.exe'
      - '\httpd.exe'
      - '\nginx.exe'
      - '\php-cgi.exe'
      - '\tomcat9.exe'
  child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\whoami.exe'
      - '\net.exe'
      - '\certutil.exe'
  condition: parent and child
falsepositives:
  - Applications that legitimately shell out (document and tune per host)
level: high
tags:
  - attack.persistence
  - attack.t1505.003
```

The SigmaHQ repository contains many community rules for web server logs, proxy logs, and webshell behavior that are worth reviewing.

## 8. Evasion techniques and pitfalls

**Encoding tricks.** Double URL encoding, Unicode normalization, case variation, SQL comments, and string concatenation all defeat naive matching. Normalize before you search.

**Encrypted webshell traffic.** Godzilla, Behinder, and similar shells encrypt their request and response bodies. You won't see commands in logs. You must rely on endpoint telemetry, URI rarity, request timing, and body size patterns.

**Body-only attacks.** Many attacks live in POST bodies, JSON, or headers that are never logged. Consider logging bodies for high-risk endpoints, with care around sensitive data.

**IP spoofing via headers.** If your application trusts X-Forwarded-For without checking that the request came from a known proxy, attackers can forge their source IP in your logs. Know which header is authoritative at each hop.

**Living off the land.** Attackers increasingly avoid spawning obvious processes and instead use in-process capabilities (.NET reflection, Java classloaders) or legitimate admin features.

**Log gaps.** Logs that are rotated too quickly, truncated at a maximum line length, or not centralized will sink your investigation. Attackers with access sometimes delete or edit local logs, which is why shipping them off-host promptly matters.

**Timezone confusion.** IIS logs in UTC by default, while other sources may log in local time. Correlating across sources with mismatched times produces false conclusions.

**Noise fatigue.** The internet is constantly scanned. Don't hunt every blocked probe. Prioritize evidence of success and post-exploitation behavior.

**Legitimate tools that look malicious.** Your own vulnerability scanners, penetration testers, uptime monitors, and SEO crawlers will trigger many hunts. Maintain an allowlist with owners and expiry dates.

## 9. Tooling

For log analytics, the common platforms are Splunk, Microsoft Sentinel, Elastic, Google SecOps (Chronicle), and open-source options like OpenSearch and Wazuh. Jupyter notebooks with pandas are excellent for ad hoc statistics on exported logs. GoAccess gives quick visual summaries of raw access logs.

For network visibility, Zeek, Suricata, Arkime (full packet capture), and RITA (beaconing analysis) are standard.

For endpoint visibility on servers, use your EDR, Sysmon (Windows and Linux), auditd, osquery, and Velociraptor for scalable forensic collection across fleets.

For webshell and file scanning, YARA with signature-base rules, THOR or LOKI, and file integrity tools like AIDE or Wazuh FIM are useful.

For WAF and detection content, ModSecurity with the OWASP Core Rule Set, Sigma rules, and the Elastic and Splunk public detection repositories are good sources.

For threat intelligence, CISA's Known Exploited Vulnerabilities catalog is the single most useful list for prioritizing which web CVEs to hunt for, along with vendor advisories and GreyNoise, which helps distinguish targeted activity from background scanning.

## 10. When you find something

Treat a hunting finding as a potential incident. Preserve evidence before remediation by collecting the suspicious files, memory from the web server (critical for fileless shells), and logs. Avoid tipping off the attacker; for example, deleting a webshell immediately may prompt them to use a second one you haven't found. Scope broadly, because attackers usually drop multiple webshells on multiple servers and quickly move laterally or steal credentials. Check whether credentials stored on or accessible to the server (database connection strings, cloud roles, service accounts, API keys) need rotating. Identify the root cause vulnerability, since removing the shell without patching the entry point means reinfection.

## 11. Making hunting a program rather than a one-off

Document each hunt: the hypothesis, data sources, queries, findings, and gaps discovered. A hunt that finds nothing is still valuable if it confirms visibility or reveals a missing log source. Convert successful logic into scheduled detections. Track metrics such as the number of detections created from hunts, visibility gaps closed, and dwell time for incidents found through hunting versus alerts. Tie hunts to threat intelligence, so that when a new actively exploited web CVE drops, you run a retrospective hunt across historical logs for exploitation that predates your patch.

## 12. Where to learn more

The OWASP Top 10, OWASP API Security Top 10, and OWASP Testing Guide explain the attacks in depth. MITRE ATT&CK technique pages for T1190 and T1505.003 list real-world procedures. The joint NSA and Australian Signals Directorate guidance on detecting and preventing web shell malware is a practical, still-relevant reference. SANS courses on threat hunting and incident response (FOR508, FOR572 for network forensics, and the cloud-focused courses) cover these techniques hands-on. Splunk's PEAK framework paper and the ThreatHunter-Playbook project are good methodological resources. Practicing against deliberately vulnerable apps like DVWA or OWASP Juice Shop, while logging everything, is one of the best ways to learn what attacks actually look like in your telemetry.

