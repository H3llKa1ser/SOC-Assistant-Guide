# Pass-the-Hash / Overpass-the-Hash with Network Mapping

Detects credential reuse across internal hosts with full lateral path reconstruction.

    index=windows_security EventCode=4624
    | where Logon_Type IN (3, 9, 10) AND Authentication_Package IN ("NTLM", "Negotiate")
    | eval is_service_account = if(match(Account_Name, "(?i)^(svc_|service_|admin_|sa_)"), 1, 0)
    | bucket _time span=30m
    | stats
        dc(ComputerName) AS hosts_accessed,
        values(ComputerName) AS host_list,
        dc(src_ip) AS source_ips,
        count AS auth_events,
        values(Logon_Type) AS logon_types,
        values(Authentication_Package) AS auth_packages,
        max(is_service_account) AS uses_service_acct
        by _time, Account_Name, src_ip
    | where hosts_accessed > 4 AND src_ip!="127.0.0.1" AND src_ip!="::1"
    | eval lateral_path = mvjoin(host_list, " ➡️ ")
    | eval suspicion_score = round(
        (hosts_accessed * 10) + 
        (auth_events * 2) + 
        (if(match(auth_packages, "NTLM"), 20, 0)) +
        (uses_service_acct * 30),
      0)
    | eval attack_phase = case(
        hosts_accessed > 15, "🔴 Full Network Compromise",
        hosts_accessed > 8, "🟠 Active Lateral Spread",
        hosts_accessed > 4, "🟡 Initial Lateral Movement",
        true(), "⚪ Normal"
      )
    | sort -suspicion_score
    | rename Account_Name AS "Account", src_ip AS "Pivot Point IP",
        hosts_accessed AS "Hosts Reached", auth_events AS "Total Auth Events",
        lateral_path AS "Lateral Movement Path",
        attack_phase AS "Attack Phase", suspicion_score AS "Suspicion Score"
