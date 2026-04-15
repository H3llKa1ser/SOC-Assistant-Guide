# Golden Ticket / Diamond Ticket with Full Kerberos Anomaly Profiling

Detects forged Kerberos tickets including newer Diamond Ticket attacks with comprehensive TGT/TGS analysis.

    index=windows_security EventCode IN (4768, 4769, 4770, 4771)
    | eval kerberos_anomaly = case(
        EventCode=4769 AND Ticket_Encryption_Type="0x17", "RC4 TGS Encryption (Golden Ticket Indicator)",
        EventCode=4769 AND Ticket_Encryption_Type="0x18", "AES256 TGS — Potential Diamond Ticket",
        EventCode=4769 AND Failure_Code="0x1f", "PAC Validation Failure (Forged Ticket)",
        EventCode=4769 AND Failure_Code="0x20", "Ticket Expired Then Reused (Replay Attack)",
        EventCode=4768 AND Ticket_Encryption_Type="0x17" AND Status="0x0", "RC4 TGT — Possible Overpass-the-Hash",
        EventCode=4768 AND Status!="0x0", "Failed TGT Request — Enumeration/Spraying",
        EventCode=4771 AND Failure_Code="0x18", "Pre-Auth Failed — Wrong Password (Kerberoasting Pre-Check)",
        EventCode=4770, "TGT Renewal — Possible Persistence",
        true(), null()
      )
    | where isnotnull(kerberos_anomaly)
    | eval is_rc4 = if(Ticket_Encryption_Type="0x17", 1, 0)
    | eval is_pac_fail = if(Failure_Code="0x1f", 1, 0)
    | eval is_renewal = if(EventCode=4770, 1, 0)
    | eval mitre_technique = case(
        match(kerberos_anomaly, "Golden Ticket|RC4 TGS"), "T1558.001 (Golden Ticket)",
        match(kerberos_anomaly, "Diamond"), "T1558.001 (Golden Ticket — Diamond Variant)",
        match(kerberos_anomaly, "PAC Validation"), "T1550.003 (Pass the Ticket)",
        match(kerberos_anomaly, "Overpass"), "T1550.002 (Pass the Hash)",
        match(kerberos_anomaly, "Replay"), "T1550.003 (Pass the Ticket — Replay)",
        match(kerberos_anomaly, "Kerberoasting"), "T1558.003 (Kerberoasting)",
        match(kerberos_anomaly, "Renewal"), "T1550.003 (Ticket Persistence)",
        true(), "T1558 (Steal or Forge Kerberos Tickets)"
      )
    | stats
        count AS total_events,
        values(kerberos_anomaly) AS anomalies_detected,
        dc(kerberos_anomaly) AS anomaly_types,
        values(Service_Name) AS services_targeted,
        dc(Service_Name) AS unique_services,
        sum(is_rc4) AS rc4_events,
        sum(is_pac_fail) AS pac_failures,
        sum(is_renewal) AS tgt_renewals,
        values(mitre_technique) AS mitre_techniques,
        values(Ticket_Encryption_Type) AS encryption_types,
        earliest(_time) AS attack_start,
        latest(_time) AS attack_end
        by Account_Name, src_ip, Client_Address
    | eval attack_duration_min = round((attack_end - attack_start) / 60, 1)
    | eval severity = case(
        pac_failures > 0 AND rc4_events > 0, "🔴 CRITICAL — Golden Ticket with PAC Bypass",
        pac_failures > 0, "🔴 CRITICAL — Forged Ticket (PAC Validation Failed)",
        rc4_events > 5 AND unique_services > 3, "🔴 HIGH — RC4 Downgrade Across Multiple Services",
        rc4_events > 0 AND tgt_renewals > 3, "🟠 HIGH — RC4 + Persistent TGT Renewal",
        anomaly_types > 2, "🟠 HIGH — Multi-Anomaly Kerberos Activity",
        rc4_events > 0, "🟡 MEDIUM — RC4 Encryption Detected",
        tgt_renewals > 5, "🟡 MEDIUM — Excessive TGT Renewals",
        true(), "⚪ LOW — Review"
      )
    | eval attack_start = strftime(attack_start, "%Y-%m-%d %H:%M:%S")
    | eval attack_end = strftime(attack_end, "%Y-%m-%d %H:%M:%S")
    | where severity != "⚪ LOW — Review"
    | sort -pac_failures, -rc4_events, -total_events
    | rename Account_Name AS "Account", src_ip AS "Source IP",
        total_events AS "Total Kerberos Events", anomaly_types AS "Anomaly Types",
        rc4_events AS "RC4 Events", pac_failures AS "PAC Failures",
        tgt_renewals AS "TGT Renewals", unique_services AS "Services Targeted",
        severity AS "Severity", mitre_techniques AS "MITRE ATT&CK",
        attack_duration_min AS "Duration (min)"
