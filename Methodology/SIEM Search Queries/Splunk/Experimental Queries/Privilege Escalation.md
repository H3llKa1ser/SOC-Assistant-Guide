# Privilege Escalation — AD Abuse with DCSync & AdminSDHolder Detection

Detects advanced AD attacks including DCSync replication requests from non-DC sources.

    index=windows_security EventCode IN (4662, 4728, 4732, 4756, 4672, 4738, 5136)
    | eval attack_technique = case(
        EventCode=4662 AND match(Properties, "(?i)1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"), 
            "DCSync — Replicating Directory Changes",
        EventCode=4662 AND match(Properties, "(?i)1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"), 
            "DCSync — Replicating Directory Changes All",
        EventCode=4662 AND match(Properties, "(?i)89e95b76-444d-4c62-991a-0facbeda640c"), 
            "DCSync — DS-Replication-Get-Changes-In-Filtered-Set",
        EventCode=5136 AND match(AttributeLDAPDisplayName, "(?i)adminCount|adminSDHolder"),
            "AdminSDHolder Persistence",
        EventCode=4738 AND match(AttributeValue, "(?i)1"),
            "Account Manipulation — adminCount Modified",
        EventCode IN (4728, 4732, 4756),
            "Group Membership Change",
        EventCode=4672,
            "Special Privileges Assigned",
        true(), null()
      )
    | where isnotnull(attack_technique)
    | eval is_dcsync = if(match(attack_technique, "DCSync"), 1, 0)
    | eval event_meaning = case(
        EventCode=4728, "Added to Global Security Group",
        EventCode=4732, "Added to Local Security Group",
        EventCode=4756, "Added to Universal Security Group",
        EventCode=4672, "Special Privileges Assigned at Logon",
        EventCode=4662, "Directory Service Access",
        EventCode=4738, "User Account Modified",
        EventCode=5136, "Directory Object Modified",
        true(), "Unknown"
      )
    | stats
        count AS total_events,
        values(attack_technique) AS techniques_detected,
        values(event_meaning) AS event_types,
        values(Group_Name) AS groups_modified,
        values(ObjectDN) AS targeted_objects,
        dc(ComputerName) AS systems_involved,
        sum(is_dcsync) AS dcsync_events,
        earliest(_time) AS attack_start,
        latest(_time) AS attack_end
        by Account_Name, SubjectUserName, src_ip
    | eval techniques_count = mvcount(techniques_detected)
    | eval severity = case(
        dcsync_events > 0, "🔴 CRITICAL — DCSync Attack (Full Credential Harvest)",
        match(techniques_detected, "AdminSDHolder"), "🔴 CRITICAL — AdminSDHolder Persistence",
        techniques_count > 2, "🟠 HIGH — Multi-Technique Privilege Escalation",
        match(groups_modified, "(?i)domain admin|enterprise admin|schema admin"), "🟠 HIGH — Tier-0 Group Modified",
        total_events > 5, "🟡 MEDIUM — Suspicious Privilege Activity",
        true(), "⚪ LOW"
      )
    | eval mitre_ids = case(
        dcsync_events > 0, "T1003.006 (DCSync)",
        match(techniques_detected, "AdminSDHolder"), "T1098 (Account Manipulation)",
        match(techniques_detected, "Group Membership"), "T1078.002 (Valid Accounts: Domain)",
        true(), "T1078 (Privilege Escalation)"
      )
    | eval attack_start = strftime(attack_start, "%Y-%m-%d %H:%M:%S")
    | eval attack_end = strftime(attack_end, "%Y-%m-%d %H:%M:%S")
    | where severity != "⚪ LOW"
    | sort -dcsync_events, -total_events
    | rename Account_Name AS "Target Account", SubjectUserName AS "Performed By",
        src_ip AS "Source IP", total_events AS "Total Events",
        dcsync_events AS "DCSync Events", techniques_count AS "Techniques Used",
        severity AS "Severity", mitre_ids AS "MITRE ATT&CK"
