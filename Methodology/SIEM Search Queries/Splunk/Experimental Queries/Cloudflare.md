# Cloudflare (Logpush capabilities)

### 1) Comprehensive Blocked Request Detection — All Cloudflare Security Services

Catches blocks from WAF, Firewall Rules, Rate Limiting, Bot Management, API Shield, DDoS, IP Access Rules, and more.

       source=http:cloudflare
        ClientRequestHost="domain.com"
        Action IN ("block", "challenge", "js_challenge", "managed_challenge", "drop", "force_connection_close")
    | eval block_source = case(
        Source="waf", "WAF Managed Rules",
        Source="firewallrules", "Firewall Rules (Custom)",
        Source="firewallCustom", "Custom WAF Rules",
        Source="firewallManaged", "Managed Ruleset",
        Source="ratelimit", "Rate Limiting",
        Source="bic", "Bot Management (BIC)",
        Source="hot", "Bot Management (HOT)",
        Source="jchallenge", "JS Challenge",
        Source="macro", "Super Bot Fight Mode",
        Source="validate", "API Shield Validation",
        Source="apiShield", "API Shield",
        Source="dlp", "Data Loss Prevention",
        Source="l7ddos", "L7 DDoS Protection",
        Source="sanitycheck", "Sanity Check",
        Source="asn", "ASN Block",
        Source="country", "Country Block",
        Source="ip", "IP Access Rule",
        Source="iprange", "IP Range Block",
        Source="securitylevel", "Security Level",
        Source="uablock", "User Agent Block",
        Source="zonelockdown", "Zone Lockdown",
        Source="tornodeblock", "Tor Node Block",
        true(), "Unknown"
      )
    | eval action_label = case(
        Action="block", "Blocked",
        Action="drop", "Dropped",
        Action="force_connection_close", "Connection Killed",
        Action="managed_challenge", "Managed Challenge",
        Action="challenge", "CAPTCHA Challenge",
        Action="js_challenge", "JS Challenge",
        true(), Action
      )
    | stats
        count AS TotalBlocks,
        dc(ClientRequestPath) AS UniquePaths,
        dc(RuleId) AS RulesTriggered,
        values(action_label) AS ActionsTaken,
        values(block_source) AS SecurityServices,
        values(ClientRequestHost) AS TargetedHosts,
        latest(_time) AS LastSeen,
        earliest(_time) AS FirstSeen
        BY ClientIP, ClientASNDescription, EdgeColoCode
    | iplocation ClientIP
    | eval LastSeen = strftime(LastSeen, "%Y-%m-%d %H:%M:%S")
    | eval FirstSeen = strftime(FirstSeen, "%Y-%m-%d %H:%M:%S")
    | eval ActionsTaken = mvjoin(ActionsTaken, ", ")
    | eval SecurityServices = mvjoin(SecurityServices, ", ")
    | eval TargetedHosts = mvjoin(TargetedHosts, ", ")
    | eval AttackerProfile = ClientIP . " (" . coalesce(ClientASNDescription, "Unknown ASN") . " - " . coalesce(Country, "Unknown") . ", " . coalesce(City, "Unknown") . ")"
    | sort -TotalBlocks
    | table
        AttackerProfile,
        TotalBlocks,
        UniquePaths,
        RulesTriggered,
        ActionsTaken,
        SecurityServices,
        TargetedHosts,
        EdgeColoCode,
        Country,
        City,
        FirstSeen,
        LastSeen
