# Cloudflare (Logpush capabilities)

### 1) Comprehensive Blocked Request Detection — All Cloudflare Security Services

Catches blocks from WAF, Firewall Rules, Rate Limiting, Bot Management, API Shield, DDoS, IP Access Rules, and more.

    index=cloudflare sourcetype="cloudflare:logpush:firewall_events"
        ClientRequestHost="yourdomain.com" OR ClientRequestHost="*.yourdomain.com"
        Action IN ("block", "challenge", "js_challenge", "managed_challenge", "drop", "force_connection_close")
    | eval block_source = case(
        Source="waf", "🛡️ WAF Managed Rules",
        Source="firewallrules", "🔥 Firewall Rules (Custom)",
        Source="firewallCustom", "🔥 Custom WAF Rules",
        Source="firewallManaged", "🛡️ Managed Ruleset",
        Source="ratelimit", "⏱️ Rate Limiting",
        Source="bic", "🤖 Bot Management (BIC)",
        Source="hot", "🤖 Bot Management (HOT)",
        Source="jchallenge", "🤖 JS Challenge",
        Source="macro", "🤖 Super Bot Fight Mode",
        Source="validate", "🔒 API Shield Validation",
        Source="apiShield", "🔒 API Shield",
        Source="dlp", "📄 Data Loss Prevention",
        Source="l7ddos", "💥 L7 DDoS Protection",
        Source="sanitycheck", "🧹 Sanity Check",
        Source="asn", "🌐 ASN Block",
        Source="country", "🌍 Country Block",
        Source="ip", "📍 IP Access Rule",
        Source="iprange", "📍 IP Range Block",
        Source="securitylevel", "🔐 Security Level",
        Source="uablock", "🚫 User Agent Block",
        Source="zonelockdown", "🔒 Zone Lockdown",
        Source="tornodeblock", "🧅 Tor Node Block",
        true(), "❓ Unknown (" . Source . ")"
      )
    | eval action_severity = case(
        Action="block", "🔴 Blocked",
        Action="drop", "🔴 Dropped",
        Action="force_connection_close", "🔴 Connection Killed",
        Action="managed_challenge", "🟡 Managed Challenge",
        Action="challenge", "🟡 CAPTCHA Challenge",
        Action="js_challenge", "🟡 JS Challenge",
        true(), "⚪ " . Action
      )
    | eval friendly_time = strftime(_time, "%Y-%m-%d %H:%M:%S")
    | eval request_uri = ClientRequestPath . if(isnotnull(ClientRequestQuery) AND ClientRequestQuery!="", "?" . ClientRequestQuery, "")
    | eval threat_context = case(
        isnotnull(RuleMessage) AND RuleMessage!="", RuleMessage,
        isnotnull(Description) AND Description!="", Description,
        isnotnull(RuleId) AND RuleId!="", "Rule ID: " . RuleId,
        true(), "No description available"
      )
    | stats
        count AS total_blocks,
        dc(ClientIP) AS unique_ips,
        dc(ClientRequestHost) AS unique_subdomains,
        dc(ClientRequestPath) AS unique_paths,
        dc(RuleId) AS unique_rules_triggered,
        values(Action) AS actions_taken,
        values(block_source) AS security_services,
        values(ClientRequestHost) AS targeted_hosts,
        latest(friendly_time) AS last_seen,
        earliest(friendly_time) AS first_seen
        by ClientIP, ClientASNDescription, EdgeColoCode
    | iplocation ClientIP
    | eval attacker_profile = ClientIP . " (" . ClientASNDescription . " — " . Country . ", " . City . ")"
    | sort -total_blocks
    | rename ClientIP AS "Attacker IP", attacker_profile AS "Attacker Profile",
        total_blocks AS "Total Blocks", unique_ips AS "Unique IPs",
        unique_paths AS "Unique Paths Targeted", unique_rules_triggered AS "Rules Triggered",
        security_services AS "Cloudflare Services", actions_taken AS "Actions Taken",
        targeted_hosts AS "Targeted Subdomains",
        EdgeColoCode AS "CF Edge PoP", first_seen AS "First Seen", last_seen AS "Last Seen",
        Country AS "Country", City AS "City"

