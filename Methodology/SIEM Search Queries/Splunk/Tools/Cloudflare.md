# Cloudflare

## Alerts

### 1) Successful login with leaked credentials

This is a high-fidelity account-takeover signal.

    index=cloudflare sourcetype=cloudflare:json earliest=-15m ClientRequestMethod=POST ClientRequestPath="/api/login*"
      LeakedCredentialCheckResult="usernamePasswordLeaked"
    | eval Outcome=case(SecurityAction="block" OR like(SecurityAction, "%challenge%"), "mitigated", EdgeResponseStatus=200, "SUCCESS", EdgeResponseStatus=401, "failed", true(), "other ".EdgeResponseStatus)
    | table _time, ClientRequestHost, Outcome, ClientIP, ClientCountry, ClientASN, JA4, BotScore, ClientRequestUserAgent, RayID
    | sort - _time

Alert on any SUCCESS row. Every row is still worth a look, because it means someone is trying a real breached credential pair.

## Threat Detection

### 1) Top blocked IPs

    index=cloudflare sourcetype=cloudflare:json ClientRequestHost="domain.com" SecurityAction="block"
    | stats count AS BlockCount, values(SecurityRuleID) AS Rules, values(ClientRequestPath) AS Paths
            BY ClientIP, ClientCountry, ClientASN
    | eval Paths=mvindex(Paths, 0, 9)
    | sort - BlockCount
    | head 20

### 2) Repeated 4xx responses per IP

    index=cloudflare sourcetype=cloudflare:json ClientRequestHost="domain.com" EdgeResponseStatus>=400 EdgeResponseStatus<500
    | stats count AS Requests, values(SecurityAction) AS CloudflareActions BY ClientIP, ClientCountry, EdgeResponseStatus
    | sort - Requests

An empty CloudflareActions means the 4xx came from the origin, not from a Cloudflare rule.

### 3) Brute force: high block rate from one IP

Adjust Attempts number accordingly

    index=cloudflare sourcetype=cloudflare:json ClientRequestHost="domain.com" SecurityAction="block"
    | bin _time span=5m
    | stats count AS Attempts, values(SecurityRuleID) AS Rules BY _time, ClientIP, ClientCountry
    | where Attempts > 150
    | sort - Attempts

### 4) Brute force with bot signals

Adjust the threshold in the second-to-last line.

    index=cloudflare sourcetype=cloudflare:json ClientRequestHost="domain.com" EdgeResponseStatus>=400
    | bin _time span=5m
    | stats count AS Attempts, dc(ClientRequestPath) AS UniquePaths, dc(ClientRequestUserAgent) AS UniqueUAs,
            min(BotScore) AS MinBotScore, values(BotScoreSrc) AS ScoreSources, values(VerifiedBotCategory) AS VerifiedBot,
            values(EdgeResponseStatus) AS ResponseCodes, values(SecurityAction) AS Actions, values(ClientRequestUserAgent) AS UserAgents
      BY _time, ClientIP, ClientCountry, ClientASN, JA4
    | eval RequestsPerSecond=round(Attempts/300, 2)
    | eval BotIndicator=case(
        isnotnull(VerifiedBot) AND VerifiedBot!="",            "Verified bot",
        MinBotScore<=1,                                         "Automated (score 1)",
        MinBotScore<30 AND RequestsPerSecond>1,                 "Likely bot",
        RequestsPerSecond>2 AND UniquePaths>20,                 "Suspicious volume",
        true(),                                                 "Likely human")
    | eval UserAgents=mvindex(UserAgents, 0, 2)
    | where Attempts > 50
    | sort - Attempts
    | table _time, ClientIP, ClientCountry, ClientASN, JA4, Attempts, RequestsPerSecond, UniquePaths, UniqueUAs, MinBotScore, BotIndicator, ResponseCodes, Actions, UserAgents

### 5) Credential stuffing: per source

Change the paths as needed. This counts failed logins (401 from the origin) and Cloudflare mitigations together. The old version grouped by eleven fields, which split each attacker into tiny groups that rarely crossed the threshold.

    index=cloudflare sourcetype=cloudflare:json ClientRequestMethod=POST (ClientRequestPath="/api/login*" OR ClientRequestPath="/quick-login*")
    | eval Outcome=case(isnotnull(SecurityAction) AND SecurityAction!="", "mitigated: ".SecurityAction,
                        EdgeResponseStatus=401, "failed login", EdgeResponseStatus<400, "success", true(), "other ".EdgeResponseStatus)
    | stats count AS Attempts, count(eval(Outcome="failed login")) AS Failed, count(eval(like(Outcome, "mitigated%"))) AS Mitigated,
            dc(ClientRequestHost) AS Sites, min(BotScore) AS MinBotScore, values(LeakedCredentialCheckResult) AS LeakedCreds,
            earliest(_time) AS FirstSeen, latest(_time) AS LastSeen
      BY ClientIP, ClientCountry, ClientASN, JA4
    | where Attempts > 40
    | eval FirstSeen=strftime(FirstSeen, "%F %T"), LastSeen=strftime(LastSeen, "%F %T")
    | sort - Failed

### 6) Credential stuffing: distributed (one tool, many IPs)

    index=cloudflare sourcetype=cloudflare:json ClientRequestMethod=POST ClientRequestPath="/api/login*"
    | bin _time span=1h
    | stats count AS Attempts, dc(ClientIP) AS UniqueIPs, count(eval(EdgeResponseStatus=401)) AS Failed,
            median(BotScore) AS MedianBotScore, values(ClientRequestHost) AS Sites BY _time, JA4
    | eval FailRate=round(Failed/Attempts*100, 1)
    | where UniqueIPs > 20 AND FailRate > 50
    | sort - Attempts

### 7) Unusual HTTP Methods

    index=cloudflare sourcetype=cloudflare:json ClientRequestHost="domain.com"
      ClientRequestMethod IN ("DELETE", "PUT", "TRACE", "OPTIONS", "PATCH", "CONNECT")
    | stats count, values(ClientRequestPath) AS Paths BY ClientRequestMethod, ClientIP, ClientCountry, SecurityAction
    | eval Paths=mvindex(Paths, 0, 9)
    | sort - count

OPTIONS can be legitimate CORS preflight from your own front ends. Check Paths before treating it as hostile.

### 8) High request volume by IP

    index=cloudflare sourcetype=cloudflare:json ClientRequestHost="domain.com"
    | bin _time span=1m
    | stats count AS RequestCount BY _time, ClientIP, ClientCountry, JA4
    | where RequestCount > 200
    | sort - RequestCount

### 9) Block Spike Detection

    index=cloudflare sourcetype=cloudflare:json ClientRequestHost="domain.com" SecurityAction="block"
    | bin _time span=1h
    | stats count AS BlockCount BY _time
    | eventstats avg(BlockCount) AS AvgBlocks, stdev(BlockCount) AS StdDevBlocks
    | eval Threshold=round(AvgBlocks + 3*StdDevBlocks, 0)
    | where BlockCount > Threshold
    | table _time, BlockCount, AvgBlocks, Threshold

### 10) Injection and path traversal attempts

This searches the full URI including the query string, and adds Cloudflare's WAF attack score (1–99; a lower score means more likely an attack).

    index=cloudflare sourcetype=cloudflare:json ClientRequestHost="domain.com"
      (ClientRequestURI="*../*" OR ClientRequestURI="*%2e%2e*" OR ClientRequestURI="*select+*" OR ClientRequestURI="*union+*"
       OR ClientRequestURI="*<script>*" OR ClientRequestURI="*%3Cscript%3E*" OR ClientRequestURI="*etc/passwd*" OR WAFAttackScore<=20)
    | table _time, ClientIP, ClientCountry, ClientRequestMethod, ClientRequestURI, WAFAttackScore, SecurityAction, SecurityRuleID, EdgeResponseStatus, RayID
    | sort - _time

### 11) 403 responses: Cloudflare or origin

    index=cloudflare sourcetype=cloudflare:json ClientRequestHost="domain.com" EdgeResponseStatus=403
    | eval BlockedBy=if(isnotnull(SecurityAction) AND SecurityAction!="", "Cloudflare (".SecurityAction.")", "Origin")
    | stats count BY ClientIP, ClientCountry, ClientRequestPath, BlockedBy, SecurityRuleID
    | sort - count

### 12) Ray ID investigation

    index=cloudflare sourcetype=cloudflare:json RayID="<INSERT_RAY_ID>"
    | table _time, ClientRequestHost, ClientIP, ClientCountry, ClientASN, ClientRequestMethod, ClientRequestURI, ClientRequestUserAgent,
            EdgeResponseStatus, OriginResponseStatus, SecurityAction, SecurityRuleID, SecuritySources, BotScore, BotScoreSrc, JA4, VerifiedBotCategory, JSDetectionPassed

The host filter is dropped, because a Ray ID is unique on its own.

### 13) Blocks by country

    index=cloudflare sourcetype=cloudflare:json ClientRequestHost="domain.com" SecurityAction="block"
    | stats count BY ClientCountry
    | sort - count
    | head 15

### 14) Spoofed search-engine crawlers

Crawler user agents that Cloudflare hasn't verified.

    index=cloudflare sourcetype=cloudflare:json earliest=-24h ClientRequestUserAgent="*bot*"
    | where match(ClientRequestUserAgent, "(?i)(googlebot|bingbot|adsbot|applebot|yandexbot|baiduspider|duckduckbot)")
        AND (isnull(VerifiedBotCategory) OR VerifiedBotCategory="")
    | stats count AS Requests, dc(ClientIP) AS UniqueIPs, values(ClientASN) AS ASNs, values(ClientRequestPath) AS Paths
      BY ClientRequestHost, ClientRequestUserAgent
    | eval Paths=mvindex(Paths, 0, 9)
    | sort - Requests

Hits on /api/login or registration paths should be most likely hostile.

### 15) Residential-proxy rotation on login

The same client, with an identical fingerprint and user agent, appearing from many networks within an hour and mostly failing.

    index=cloudflare sourcetype=cloudflare:json earliest=-24h ClientRequestMethod=POST ClientRequestPath="/api/login*"
    | bin _time span=1h
    | stats count AS Attempts, count(eval(EdgeResponseStatus=401)) AS Failed, dc(ClientIP) AS IPs,
            dc(ClientASN) AS ASNs, dc(ClientCountry) AS Countries BY _time, JA4, ClientRequestUserAgent
    | eval FailRate=round(Failed/Attempts*100, 1)
    | where ASNs>=20 AND FailRate>=60
    | sort - Failed

### 16) New login tooling: fingerprints first seen in the last 24 hours

    index=cloudflare sourcetype=cloudflare:json earliest=-7d ClientRequestMethod=POST ClientRequestPath="/api/login*" JA4=*
    | stats earliest(_time) AS FirstSeen, count AS Requests, dc(ClientIP) AS IPs,
            count(eval(EdgeResponseStatus=401)) AS Failed, values(ClientRequestUserAgent) AS UAs BY JA4
    | where FirstSeen>=relative_time(now(), "-24h") AND Requests>=20
    | eval FailRate=round(Failed/Requests*100, 1), FirstSeen=strftime(FirstSeen, "%F %T"), UAs=mvindex(UAs, 0, 2)
    | sort - Requests

### 17) Logins from hosting networks and Tor that got through

    index=cloudflare sourcetype=cloudflare:json earliest=-24h ClientRequestMethod=POST ClientRequestPath="/api/login*" EdgeResponseStatus=200
      (ClientCountry="t1" OR ClientASN IN (8075, 15169, 16509, 14618, 16276, 51167, 8560, 20860, 21859, 207990, 151592, 141968, 140389))
    | stats count AS SuccessfulLogins, dc(ClientIP) AS IPs, values(ClientRequestHost) AS Sites, min(BotScore) AS MinScore,
            values(LeakedCredentialCheckResult) AS LeakedCreds BY ClientASN, ClientCountry, JA4
    | sort - SuccessfulLogins

### 18) Registration enumeration

Bursts of email or username availability checks from one source.

    index=cloudflare sourcetype=cloudflare:json earliest=-24h ClientRequestPath="*/registration/verification/*"
    | eval Check=case(like(ClientRequestPath, "%/email%"), "email", like(ClientRequestPath, "%/username%"), "username", true(), "other")
    | bin _time span=10m
    | stats count AS Checks, min(BotScore) AS MinScore, values(EdgeResponseStatus) AS Statuses, values(SecurityAction) AS Actions
      BY _time, ClientRequestHost, Check, ClientIP, JA4
    | where Checks>=20
    | sort - Checks

### 19) Address-lookup abuse

Address lookups go to a paid third-party service, so scripted lookups carry a direct cost.

    index=cloudflare sourcetype=cloudflare:json earliest=-24h ClientRequestPath="*/v1/address*"
    | bin _time span=1h
    | stats count AS Lookups, dc(ClientRequestPath) AS DistinctAddresses, min(BotScore) AS MinScore
      BY _time, ClientRequestHost, ClientIP, ClientASN, JA4
    | where Lookups>=60
    | sort - Lookups

Daily cost trend per site

    index=cloudflare sourcetype=cloudflare:json earliest=-30d ClientRequestPath="*/v1/address*"
    | timechart span=1d count BY ClientRequestHost limit=0

### 20) Sensitive-file and admin-panel probing

    index=cloudflare sourcetype=cloudflare:json earliest=-24h
      (ClientRequestPath="*/.env*" OR ClientRequestPath="*/.git/*" OR ClientRequestPath="*/.aws/*" OR ClientRequestPath="*/wp-login.php*"
       OR ClientRequestPath="*/wp-admin*" OR ClientRequestPath="*/phpmyadmin*" OR ClientRequestPath="*/actuator*"
       OR ClientRequestPath="*/server-status*" OR ClientRequestPath="*/config.json*" OR ClientRequestPath="*/backup*")
    | stats count AS Probes, dc(ClientRequestPath) AS DistinctPaths, values(EdgeResponseStatus) AS Statuses,
            values(SecurityAction) AS Actions BY ClientIP, ClientCountry, ClientASN, ClientRequestHost
    | eval Exposed=if(isnotnull(mvfind(Statuses, "^200$")), "CHECK: 200 returned", "")
    | sort - DistinctPaths

### 21) Vulnerability scanners by user agent

    index=cloudflare sourcetype=cloudflare:json earliest=-24h
    | where match(ClientRequestUserAgent, "(?i)(nuclei|sqlmap|nikto|nmap|masscan|zgrab|httpx|gobuster|dirbuster|feroxbuster|ffuf|wfuzz|wpscan|acunetix|nessus|openvas|burp|zap|whatweb|arachni|qualys)")
    | stats count AS Requests, dc(ClientRequestPath) AS DistinctPaths, values(ClientRequestHost) AS Sites,
            values(EdgeResponseStatus) AS Statuses, values(SecurityAction) AS Actions BY ClientIP, ClientASN, ClientCountry, ClientRequestUserAgent
    | sort - DistinctPaths

Authorised scanners (Invicti, Tenable) will show up here too. Recognise them by their source IPs before escalating.

### 22) Directory brute-forcing: high 404 rate from one source

    index=cloudflare sourcetype=cloudflare:json earliest=-24h
    | bin _time span=10m
    | stats count AS Requests, count(eval(EdgeResponseStatus=404)) AS NotFound, dc(ClientRequestPath) AS DistinctPaths
      BY _time, ClientIP, ClientASN, ClientRequestHost, JA4
    | eval NotFoundPct=round(NotFound/Requests*100, 1)
    | where DistinctPaths>=100 AND NotFoundPct>=60
    | sort - DistinctPaths

## Troubleshooting

### 1) Actions taken on a domain

    index=cloudflare sourcetype=cloudflare:json ClientRequestHost="domain.com"
    | fillnull value="none (allowed)" SecurityAction
    | stats count BY SecurityAction
    | sort - count

### 2) Field presence check

This confirms the bot fields are actually in the Logpush job. A count of 0 means the field needs adding to the job.

    index=cloudflare sourcetype=cloudflare:json earliest=-15m
    | head 5000
    | fieldsummary maxvals=3
    | search field IN ("SecurityAction", "SecurityActions", "SecurityRuleIDs", "BotScore", "BotScoreSrc", "JA4", "JSDetectionPassed", "VerifiedBotCategory", "LeakedCredentialCheckResult", "WAFAttackScore", "ClientCountry", "ClientASN")
    | table field, count, distinct_count, values

### 3) Hourly baseline: allowed, challenged, blocked

    index=cloudflare sourcetype=cloudflare:json ClientRequestHost="domain.com"
    | bin _time span=1h
    | stats count AS Total, count(eval(SecurityAction="block")) AS Blocked,
            count(eval(like(SecurityAction, "%challenge%"))) AS Challenged BY _time
    | eval Allowed=Total-Blocked-Challenged, BlockPercentage=round(Blocked/Total*100, 2)
    | table _time, Allowed, Challenged, Blocked, BlockPercentage

### 4) 4xx and 5xx over time

    index=cloudflare sourcetype=cloudflare:json ClientRequestHost="domain.com" EdgeResponseStatus>=400
    | timechart span=15m count BY EdgeResponseStatus

### 5) 5xx errors: Cloudflare edge or origin

    index=cloudflare sourcetype=cloudflare:json ClientRequestHost="domain.com" EdgeResponseStatus>=500 EdgeResponseStatus<=599
    | eval Source=if(OriginResponseStatus>=500, "Origin", "Cloudflare edge")
    | stats count AS ErrorCount BY ClientRequestPath, EdgeResponseStatus, Source
    | sort - ErrorCount
    | head 20
