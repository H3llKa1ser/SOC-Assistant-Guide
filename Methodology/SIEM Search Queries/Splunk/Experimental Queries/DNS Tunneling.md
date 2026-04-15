# DNS Tunneling with Entropy and Subdomani Analysis

Detects data exfiltration via DNS using Shannon entropy to catch encoded payloads.

    index=dns_logs query_type IN ("A", "AAAA", "TXT", "CNAME", "MX")
    | eval query_length = len(query)
    | eval subdomain_count = mvcount(split(query, ".")) - 2
    | eval label_parts = split(query, ".")
    | eval longest_label = max(mvmap(label_parts, len(mvindex(label_parts, 0))))
    | rex field=query "^(?<subdomain>[^\.]+)\."
    | eval subdomain_len = len(subdomain)
    | eval has_hex_pattern = if(match(subdomain, "^[a-f0-9]{16,}$"), 1, 0)
    | eval has_base64_pattern = if(match(subdomain, "^[A-Za-z0-9+/=]{20,}$"), 1, 0)
    | eval is_suspicious_tld = if(match(query, "\.(top|xyz|tk|ml|ga|cf|pw|buzz|work)$"), 1, 0)
    | bucket _time span=5m
    | stats
        count AS total_queries,
        avg(query_length) AS avg_query_len,
        max(query_length) AS max_query_len,
        dc(query) AS unique_queries,
        avg(subdomain_count) AS avg_subdomain_depth,
        sum(has_hex_pattern) AS hex_pattern_queries,
        sum(has_base64_pattern) AS base64_pattern_queries,
        sum(is_suspicious_tld) AS suspicious_tld_count,
        values(query) AS sample_queries
        by _time, src_ip
    | eval encoding_ratio = round((hex_pattern_queries + base64_pattern_queries) / total_queries * 100, 1)
    | eval unique_ratio = round(unique_queries / total_queries * 100, 1)
    | where
        (total_queries > 100 AND avg_query_len > 45 AND encoding_ratio > 30) OR
        (unique_ratio > 90 AND total_queries > 50 AND avg_query_len > 40) OR
        (hex_pattern_queries > 30)
    | eval tunnel_confidence = case(
        encoding_ratio > 60 AND total_queries > 200, "🔴 Critical — Active DNS Tunnel",
        encoding_ratio > 40, "🟠 High — Probable DNS Tunnel",
        unique_ratio > 90 AND avg_query_len > 50, "🟡 Medium — Suspicious DNS Pattern",
        true(), "⚪ Low"
      )
    | eval estimated_exfil_bytes = round(total_queries * (avg_query_len - 20), 0)
    | eval estimated_exfil_kb = round(estimated_exfil_bytes / 1024, 2)
    | sort -encoding_ratio
    | rename src_ip AS "Source IP", total_queries AS "Total Queries",
        avg_query_len AS "Avg Query Length", encoding_ratio AS "Encoded Query %",
        unique_ratio AS "Unique Query %", estimated_exfil_kb AS "Est. Exfil (KB)",
        tunnel_confidence AS "Confidence Level"
    
