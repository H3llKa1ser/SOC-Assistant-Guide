# Threat Hunting with a WAF

## 1. What WAF hunting is, and how it differs from WAF operation

A Web Application Firewall inspects HTTP(S) traffic at Layer 7, between clients and your applications. Most teams treat it as a preventive control: turn on managed rules, tune false positives, and look at the dashboard when something breaks. Threat hunting treats the WAF as a sensor instead. It is one of the richest telemetry sources you have for internet-facing attack surface, because it sees every request (or a sample of them), including what it blocked, what it let through, and what it only flagged.

The central idea is this: blocked requests are the least interesting thing in your WAF logs. A block is an attack that failed, and the WAF already handled it. Hunting targets what the rules missed, meaning attacks that were allowed, attacks that bypassed inspection, and attackers whose behavior only becomes visible when you connect many individually harmless requests. The questions shift from "what did the WAF stop?" to "what did it let through that it shouldn't have?", "who is probing us patiently?", and "did any of those probes succeed?"

Hunting is hypothesis-driven and assumes compromise. You start with a proposition, such as "an attacker has found an SQL injection the managed rules don't catch" or "someone is running credential stuffing through residential proxies below our rate limits." Then you query the data to prove or disprove it. The outputs are either an incident, a new detection or WAF rule, or a documented negative result that improves your baseline.

In MITRE ATT&CK terms, WAF telemetry mainly covers:

- **T1595** Active Scanning and **T1592/T1594** reconnaissance
- **T1190** Exploit Public-Facing Application
- **T1110** Brute Force, including credential stuffing (T1110.004) and password spraying (T1110.003)
- **T1505.003** Web Shell
- **T1071.001** web-protocol C2
- **T1498/T1499** application-layer DoS
- Data collection and exfiltration through application endpoints

## 2. The data: what WAF logs contain and why each field matters

Across vendors, a good WAF log record gives you roughly the following.

**Identity of the source:**

- Client IP and the forwarding chain (X-Forwarded-For, True-Client-IP, CF-Connecting-IP)
- Geolocation and ASN
- TLS client fingerprints (JA3, and increasingly JA4, which is more robust to ordering tricks)
- User-Agent and sometimes header order
- Bot scores
- Session cookies or authentication tokens, if logged

**The request itself:**

- Host, method, URI path, query string, HTTP version
- Headers, and sometimes a truncated body
- Content-Type and request size

**The WAF's decision:**

- Action: allow, block, challenge, count/log, or rate-limit
- The terminating rule ID
- Any non-terminating rules that matched
- Anomaly score or ML attack scores
- Labels applied by rule groups

**The outcome:**

- Response status code and response size, which are critical and often missing
- Origin response time

**Correlation keys:**

- Request ID and a timestamp for joining with other sources

The outcome fields deserve emphasis. A request the WAF allowed that returned a 200 with an unusually large body is far more interesting than one that returned a 404. Some WAFs don't log response data at all. AWS WAF logs, for example, don't include the response status. So you often need to join WAF logs with CDN, load balancer, or application logs to learn whether an attack worked.

### Vendor specifics worth knowing

**Cloudflare**

- Security Events cover WAF, bot, rate-limit, and firewall rule actions.
- HTTP Request logs via Logpush (Enterprise) include fields such as `SecurityAction`, `SecurityRuleID`, `EdgeResponseStatus`, `OriginResponseStatus`, `BotScore`, `JA3Hash`, `JA4`, and the ML attack scores (`WAFAttackScore`, plus separate SQLi, XSS, and RCE scores).
- Attack scores run from 1 to 99, and lower means more likely malicious.
- One of the best hunts on Cloudflare is "low attack score, but the action was allow or none."

**AWS WAF**

- Logs go to CloudWatch Logs, S3, or Kinesis Data Firehose and are typically queried with Athena or a SIEM.
- Useful fields include `action`, `terminatingRuleId`, `ruleGroupList`, `nonTerminatingMatchingRules`, `labels`, `httpRequest.clientIp`, `httpRequest.country`, `httpRequest.uri`, `httpRequest.args`, headers, and JA3/JA4 fingerprints.
- The console's "sampled requests" view is a sample only. Hunting requires full logging to be enabled.
- There is a body inspection size limit, configurable in newer versions for CloudFront and some other resources. Anything beyond it is not inspected, which matters for bypass hunting.

**Azure WAF (Application Gateway and Front Door)**

- Logs go to Log Analytics.
- They appear either in `AzureDiagnostics` (category `ApplicationGatewayFirewallLog` or `FrontDoorWebApplicationFirewallLog`) or in resource-specific tables such as `AGWFirewallLogs`, and are queried with KQL.
- Detection versus prevention mode matters: in detection mode, everything "matched" was still allowed through.

**ModSecurity/Coraza with the OWASP Core Rule Set**

- The audit log is very detailed.
- CRS uses anomaly scoring and paranoia levels. Each rule adds points, and a block happens only when the total crosses a threshold (default inbound 5).
- This creates a classic hunt: requests scoring 3 or 4, just under the threshold, especially clustered by source.

**Others**

- F5 Advanced WAF/ASM, Imperva, Akamai App & API Protector, Fastly Next-Gen WAF (formerly Signal Sciences), Barracuda, and Fortinet FortiWeb all expose comparable data via SIEM connectors.
- Each has its own violation and signal taxonomy worth learning.

## 3. Prerequisites before hunting is possible

You need full, not sampled, logs retained long enough to hunt backward. Ninety days is a reasonable minimum, and longer is better for retro-hunting new CVEs. Logs should land in something you can query at scale, such as a SIEM, a data lake with Athena/BigQuery/Databricks, or ClickHouse.

You need to know the true client IP. If your WAF sits behind a CDN or load balancer, or in front of one, confirm which field holds the real client. X-Forwarded-For is attacker-controllable unless you trust only the entries added by your own infrastructure.

You need a baseline:

- Normal request volume per endpoint
- Normal geographies and ASNs
- Normal user agents and fingerprints
- Normal error rates
- A list of the endpoints that actually exist

That last one matters because many hunts are about requests to things that don't exist, or to new things that suddenly get traffic.

You need joins to other data:

- Application logs, which show authentication outcomes, user IDs, and business events
- Load balancer and CDN logs
- EDR or host telemetry on web servers
- Identity provider logs
- Threat intelligence

Finally, make sure traffic can't bypass the WAF. If the origin is reachable directly, a skilled attacker simply goes around the WAF, and your logs show nothing.

## 4. Hunting hypotheses and playbooks

This is the core of WAF hunting. Each hunt below states the idea, what to look for, and how to reason about it.

### Blocked, then successful

An attacker who gets blocked usually doesn't give up. They mutate the payload until something passes.

Hunt for sources (IP, subnet, JA4 fingerprint, or session) that triggered blocks and then produced allowed requests to the same endpoint or parameter shortly afterward. It's strongest when the allowed requests have odd characters, encodings, or high entropy, and when they return 200 with non-trivial response sizes. This is one of the highest-yield hunts there is, because it directly targets WAF bypass.

### Near-miss and log-only matches

Look at rules running in count or log mode, non-terminating matches, CRS anomaly scores just below the blocking threshold, and ML attack scores in the "likely attack" range where the action was still allow.

These are the requests the WAF found suspicious but didn't stop. Stack them by source and endpoint. A single near-miss is noise. Fifty near-misses from one fingerprint against one parameter is a person working on an exploit.

### Evasion and inspection-gap hunting

WAFs are parsers, and attackers exploit differences between how the WAF parses a request and how the application does. Hunt for:

- **Encoding tricks:** double URL encoding (`%252e`), overlong UTF-8, Unicode normalization tricks, and mixed case in keywords.
- **SQL evasion:** SQL comments splitting keywords (`UN/**/ION`), and whitespace alternatives such as tabs, newlines, or `%0b`.
- **HTTP parameter pollution:** the same parameter repeated with different values.
- **Content-Type confusion:** a JSON or XML body sent with a form Content-Type, or multipart boundaries crafted to confuse parsers.
- **Oversized bodies:** payloads placed beyond the WAF's body inspection limit. Look for requests with padding followed by payload, or bodies consistently just over the limit.
- **Smuggling and protocol oddities:** unusual transfer encodings, chunked requests, HTTP/2-specific oddities, and header anomalies suggestive of request smuggling (both Content-Length and Transfer-Encoding, or obfuscated `Transfer-Encoding` variants).
- **Unusual methods:** methods such as PUT, PATCH, DELETE, TRACE, or custom verbs against endpoints that normally only see GET and POST.

### Recon-to-exploitation progression

Scanners are background noise. Every internet-facing asset is hit constantly by mass scanners, and most of it doesn't matter. What matters is a source that moves from broad scanning to focused interest.

The pattern:

1. Many 404s across generic paths (`/.env`, `/.git/config`, `/wp-admin`, `/actuator`, `/phpmyadmin`).
2. Then narrowing to paths that returned 200 or 403.
3. Then parameter fuzzing on a specific endpoint.
4. Then exploit-shaped payloads.

Use services such as GreyNoise to tag and deprioritize known mass scanners. Focus on sources that aren't known scanners but behave with intent, and on activity targeting your specific technology rather than generic lists.

### Retro-hunting new CVEs

When a critical vulnerability drops in something you run, or in something widely deployed, search your historical WAF logs for its exploitation pattern before your WAF vendor shipped a signature.

This is how organizations discovered they had been hit before disclosure with bugs like:

- Log4Shell: `${jndi:` and obfuscated variants such as `${${lower:j}ndi:`
- Spring4Shell: `class.module.classLoader`
- MOVEit, Citrix Bleed, Ivanti, Confluence OGNL injection

The key is having retention long enough to look back to before the disclosure date, and searching the fields the WAF didn't normally inspect, such as headers like User-Agent, Referer, and X-Api-Version.

### Out-of-band (OAST) callback indicators

Modern exploitation tooling tests for blind vulnerabilities by embedding callback domains in payloads. Search all request fields, including headers, for domains such as:

- `interact.sh` and `oast.fun`/`oast.pro`/`oast.live`/`oast.site`/`oast.online`/`oast.me`
- `burpcollaborator.net` and `oastify.com`
- `dnslog.cn` and `ceye.io`
- `requestbin` variants and `webhook.site`
- Random-looking subdomains of attacker-controlled domains

A hit is a strong signal that someone is actively testing for SSRF, blind injection, XXE, or deserialization. Then check DNS and egress logs to see whether any of your servers actually resolved or contacted those domains, which would indicate the vulnerability is real.

### SSRF

Look for parameters containing URLs, especially:

- Cloud metadata endpoints (`169.254.169.254`, `metadata.google.internal`, `fd00:ec2::254`)
- Internal RFC1918 addresses, `localhost`, `0.0.0.0`
- Decimal, octal, or hex-encoded IPs (`2130706433`, `0x7f000001`)
- `file://`, `gopher://`, or `dict://` schemes

Correlate with egress logs from app servers.

### Web shells and post-exploitation

If an attacker has already landed, WAF logs often show the web shell being used. Hunt for:

- Requests to script extensions (`.php`, `.jsp`, `.aspx`, `.ashx`) in upload, static, or image directories.
- Newly seen file paths that suddenly receive POST requests.
- Paths requested by only one or two sources ever. Long-tail analysis matters here: legitimate pages are requested by many clients, and web shells by very few.
- Parameters like `cmd=`, `exec=`, `c=`, and base64-looking POST bodies.
- Consistent small, periodic requests, which suggest scripted interaction.

Once you find a suspicious path, pivot to host telemetry on that server to confirm file creation and child processes spawned by the web server.

### Credential stuffing, password spraying, and account takeover

Focus on authentication endpoints (login, token, password reset, MFA). Signals include:

- A high failure ratio per source.
- Many distinct usernames per source (stuffing) or many sources per username (distributed brute force).
- Distributed attacks using residential proxies, where each IP makes only a handful of attempts. Here the IP is useless, and you pivot on JA3/JA4 fingerprints, header order, user-agent consistency, and timing.
- A single TLS fingerprint across thousands of IPs with the same unusual user agent is a botnet signature.

The critical follow-up is identifying successes: which accounts had a successful login from that infrastructure. Those accounts are potentially compromised and need resets.

### Scraping, bots, and fingerprint mismatches

A client claiming to be Chrome on Windows but presenting a JA4 fingerprint typical of Python requests, Go, or curl is lying. Other signals:

- Headless browser markers
- Missing headers that real browsers always send (Accept-Language, sec-ch-ua)
- Unusual header ordering
- Perfectly regular timing
- Bot scores in the automated range hitting high-value endpoints: pricing, search, account data, inventory, odds, and results

### API abuse and broken object-level authorization

APIs are where WAF signatures are weakest, because the attack is often syntactically normal. Hunt for:

- **ID enumeration:** sequential or systematically varied object IDs from one client (`/api/users/1001`, `/1002`, `/1003`...). If responses are 200 with consistent sizes, that's a BOLA/IDOR data harvest.
- **GraphQL abuse:** introspection queries (`__schema`, `__type`) in production, very deep or batched queries, and aliasing abuse.
- **Undocumented endpoints:** calls to endpoints not in your API specification, or to deprecated versions (`/v1/` when everyone uses `/v3/`).
- **Mass assignment attempts:** unexpected fields in JSON bodies such as `isAdmin` or `role`.

### Response-size and data-exfiltration anomalies

Where you have response sizes, look for a client whose responses are far larger than normal for that endpoint. That can indicate successful SQL injection (a `UNION SELECT` dumping a table), path traversal returning a file, or bulk scraping. Also look for sustained high cumulative bytes to one client from data-returning endpoints.

### Business-logic abuse

Some of the most damaging abuse is invisible to signatures:

- Promotion, coupon, or bonus abuse
- Automated account creation
- Inventory hoarding
- Gift-card and stored-value balance checking
- Payment-card testing on checkout, which looks like many small authorizations with high decline rates

These require knowing what normal business flows look like and hunting for sequences and volumes that don't match them.

### Origin bypass

Compare origin server or load balancer logs with WAF logs. Requests arriving at the origin that don't correspond to WAF-proxied traffic mean someone found the origin IP, through historical DNS, certificate transparency, email headers, or misconfigured subdomains, and is bypassing your protection entirely. This is sometimes the single most important finding a WAF hunt produces.

### Targeted interest in sensitive surfaces

Look at admin panels, internal tools, CI/CD dashboards, backup files (`.bak`, `.zip`, `.sql`), source-control artifacts, and debug or actuator endpoints. Watch for access from unexpected geographies, hosting ASNs, or Tor exit nodes. Also look for configuration and secret files being requested successfully.

## 5. Analytical techniques

**Stack counting (frequency analysis).** Group by a field and look at both extremes. The most frequent values show dominant traffic and noisy attackers. The least frequent values (the long tail) are where web shells, rare exploits, and targeted probes hide.

**Pivoting.** Start from one suspicious request and expand along each dimension: all requests from that IP, that /24, that ASN, that JA4, that user agent, that session, that target path. Attackers rotate IPs cheaply, but their tooling fingerprint changes less often.

**Time-series analysis.**

- Spikes and drops.
- Beaconing, meaning regular intervals, which suggests automation or C2 via a web shell.
- Activity at hours when the legitimate user base is asleep.
- Low-and-slow patterns that stay under rate limits but persist for weeks.

**Entropy and shape analysis.**

- Parameter values with high character entropy, many special characters, or unusual length relative to that parameter's baseline.
- Base64-looking or hex-looking values in parameters that normally hold short identifiers.

**Clustering.** Group requests by fingerprint features (JA4, header set, UA, path pattern, timing) to reveal campaigns spread across many IPs.

**Diffing against a baseline.** New paths, new parameters, new countries, new ASNs, and new user agents this week versus last month.

**Enrichment.**

- IP reputation and threat intelligence
- ASN type (hosting versus residential versus mobile)
- Tor and VPN or proxy lists
- GreyNoise classification (benign scanner, malicious, unknown)
- Known-good crawler verification via reverse DNS for Googlebot, Bingbot, and similar

## 6. Example queries

**AWS WAF via Athena: sources that were blocked and then allowed on the same URI.** Timestamps in AWS WAF logs are epoch milliseconds.

```sql
WITH blocked AS (
  SELECT httprequest.clientip AS ip,
         httprequest.uri      AS uri,
         min(timestamp)       AS first_block
  FROM waf_logs
  WHERE action = 'BLOCK'
  GROUP BY 1, 2
)
SELECT w.httprequest.clientip AS ip,
       w.httprequest.uri      AS uri,
       count(*)               AS allowed_after_block,
       min(from_unixtime(w.timestamp / 1000)) AS first_allowed
FROM waf_logs w
JOIN blocked b
  ON w.httprequest.clientip = b.ip
 AND w.httprequest.uri      = b.uri
WHERE w.action = 'ALLOW'
  AND w.timestamp > b.first_block
GROUP BY 1, 2
ORDER BY allowed_after_block DESC
LIMIT 100;
```

**Azure Application Gateway WAF (KQL): matches that were only detected, grouped by source and rule.**

```kql
AzureDiagnostics
| where Category == "ApplicationGatewayFirewallLog"
| where action_s in ("Detected", "Matched")
| summarize hits = count(),
            rules = make_set(ruleId_s, 20),
            uris = make_set(requestUri_s, 20),
            first = min(TimeGenerated), last = max(TimeGenerated)
            by clientIp_s
| where hits > 20
| order by hits desc
```

**Long-tail paths (generic SQL): candidate web shells and rare endpoints.** Paths hit by very few distinct clients but with POST requests.

```sql
SELECT uri,
       count(DISTINCT client_ip) AS distinct_clients,
       count(*) AS requests,
       sum(CASE WHEN method = 'POST' THEN 1 ELSE 0 END) AS posts
FROM waf_requests
WHERE ts > now() - INTERVAL '14' DAY
  AND regexp_like(uri, '\.(php|jsp|jspx|aspx|ashx|cfm)$')
GROUP BY uri
HAVING count(DISTINCT client_ip) <= 2 AND sum(CASE WHEN method = 'POST' THEN 1 ELSE 0 END) > 0
ORDER BY requests DESC;
```

**Splunk: distributed credential stuffing pivoting on TLS fingerprint rather than IP.**

```spl
index=waf uri_path="/api/login" method=POST
| stats dc(src_ip) AS ips, dc(username) AS users, count AS attempts,
        values(user_agent) AS uas by ja4
| where ips > 50 AND users > 100
| sort - attempts
```

**OAST indicators across the whole request.** Search the full request, not just the query string, because payloads often ride in headers.

```spl
index=waf ("interact.sh" OR "oast.fun" OR "oast.pro" OR "oast.live" OR "oast.me" OR "oastify.com"
          OR "burpcollaborator" OR "dnslog.cn" OR "ceye.io" OR "${jndi:")
| stats count values(uri) values(action) by src_ip, ja4
```

**Cloudflare: likely attacks the WAF didn't act on.** Query the Logpush data in your SIEM.

```sql
SELECT ClientIP, ClientRequestPath, WAFAttackScore, SecurityAction, EdgeResponseStatus, count(*) AS n
FROM cloudflare_http_requests
WHERE WAFAttackScore <= 20
  AND (SecurityAction IS NULL OR SecurityAction IN ('allow', 'log', 'skip'))
GROUP BY 1, 2, 3, 4, 5
ORDER BY n DESC;
```

Field names vary by how your pipeline normalizes logs, so treat these as templates.

## 7. From hunt to durable defense

A hunt that finds something should end with more than an incident ticket. Convert each finding into several things:

- **A preventive WAF rule:** a custom rule, rate limit, fingerprint block, or tightened managed-rule setting.
- **A SIEM detection:** so the pattern alerts automatically next time.
- **An application fix:** the WAF is a compensating control, and a bypassed SQL injection means the code still needs parameterized queries.
- **A documented hunt:** hypothesis, queries, results, and data gaps, so it can be rerun on a schedule.

Negative results are valuable too. Knowing you have no evidence of Log4Shell exploitation across 180 days of logs, and being able to prove it, is a real outcome.

Map hunts to ATT&CK and to the OWASP Top 10 and OWASP API Security Top 10, which helps show coverage and find gaps. Feed discoveries back into tuning. Hunting often reveals both false negatives (rules to tighten) and false positives (rules blocking real customers, which pushes teams to disable protection).

## 8. Common pitfalls

**Wrong or spoofed client IPs.** This happens when you trust X-Forwarded-For blindly or mis-order proxy chains.

**Sampled or incomplete logs.** Dashboards often sample. Bodies are usually not logged or are truncated. Response codes may be missing entirely.

**Retention too short.** You can't retro-hunt a CVE that was exploited before your retention window began.

**Mistaking noise for signal.** The internet is full of benign and malicious mass scanning. Chasing every block wastes time. Deprioritize known scanners and focus on intent, persistence, and success.

**Ignoring detection or log-only mode.** Teams sometimes forget that "detected" means "allowed."

**Blind spots in encrypted or alternative paths.** WebSockets, gRPC, some API gateways, mobile app backends on separate hostnames, and legacy endpoints may bypass the WAF or be inspected poorly.

**Origin exposure.** As covered above.

**Privacy and compliance.** WAF logs contain IPs, cookies, tokens, and sometimes credentials or personal data in bodies. Redact authorization headers and passwords where possible, control access to the logs, and align retention with GDPR and your other obligations.

**Cost.** Full request logging at high volume is expensive. Tiered storage, pushing raw logs to object storage and querying with Athena or a lakehouse, keeps long retention affordable while the SIEM holds shorter, hotter data.

## 9. Building it into a program

A practical maturity path:

1. **Get the data right.** Full logs, correct client IP, retention, joins to response and app data.
2. **Build baselines.** Endpoints, volumes, geographies, fingerprints.
3. **Run a core set of recurring hunts** on a weekly or monthly cadence:
   - Blocked-then-allowed
   - Near-misses
   - Long-tail paths
   - Credential abuse
   - OAST indicators
   - Origin bypass
   - Fingerprint mismatches
4. **Add event-driven hunts** whenever a relevant CVE or threat report appears.
5. **Automate what works** into detections and dashboards.
6. **Measure outcomes:** findings per hunt, detections created, dwell time reduced, and bypasses fixed.

The WAF team, SOC, AppSec, and application owners should all be involved, because the most valuable findings sit at the boundary between "what the WAF saw" and "what the application actually did."

