# Cloudflare

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
