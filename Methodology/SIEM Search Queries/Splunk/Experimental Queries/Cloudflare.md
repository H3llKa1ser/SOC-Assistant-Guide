# Cloudflare (Logpush capabilities)

### 1) Monitor blocked attempts based on their volume to detect potential credential stuffing attacks

Change the number of attempts and ClientRequestPaths to fine-tune according to your environment and baselines.

       index=cloudflare source=http:cloudflare sourcetype="cloudflare:http" SecurityAction=block ClientRequestMethod=POST (ClientRequestPath="/login" OR ClientRequestPath="/api" OR ClientRequestPath="/api/login*")
       | iplocation ClientIP
       | eval DateTime=strftime(_time, "%Y-%m-%d %H:%M:%S")
       | stats 
           count AS Attempts, 
           dc(ClientIP) AS UniqueIPs, 
           earliest(DateTime) AS FirstSeen, 
           latest(DateTime) AS LastSeen,
           values(WAFAttackScore) AS WAFAttackScores,
           max(WAFAttackScore) AS MaxWAFAttackScore
         BY ClientRequestPath, ClientRequestMethod, EdgeResponseStatus, SecurityAction, 
            Country, ClientIP, ClientRequestHost, ClientRequestUserAgent, 
            SecurityRuleID, VerifiedBotCategory
       | where Attempts > 40
       | sort -Attempts
