# Ransomware — Multi-Stage Detection with Canary File Monitoring

Detects ransomware across three phases: reconnaissance, encryption, and ransom note deployment.

    index=endpoint_logs event_type IN ("file_modification", "file_creation", "file_deletion", "process_creation")
    | eval phase = case(
        event_type="process_creation" AND match(process_name, "(?i)vssadmin|wmic|bcdedit|wbadmin|diskshadow"),
        "1_shadow_deletion",
        event_type="process_creation" AND match(process_args, "(?i)delete\s+shadows|shadowcopy\s+delete|recoveryenabled\s+no|catalog\s+-quiet"),
        "1_shadow_deletion",
        event_type="file_modification" AND match(file_name, "\.(locked|encrypted|enc|crypt|ryk|WNCRY|zepto|cerber|locky|dharma|phobos|lockbit|blackcat|royal|akira|rhysida|play|medusa)$"),
        "2_encryption",
        event_type="file_creation" AND match(file_name, "(?i)(readme|how.?to.?decrypt|restore.?files|ransom|decrypt.?instruction|help.?recover|!!.?read.?me|note).*\.(txt|html|hta)"),
        "3_ransom_note",
        event_type="file_modification" AND NOT match(file_name, "\.(tmp|log|etl)$"),
        "2_file_activity",
        true(), "0_other"
      )
    | where phase != "0_other"
    | bucket _time span=2m
    | stats
        count AS events,
        dc(file_path) AS unique_paths,
        dc(file_name) AS unique_files,
        values(phase) AS detected_phases,
        values(process_name) AS processes,
        values(process_args) AS process_arguments,
        values(file_name) AS sample_files,
        dc(eval(if(phase="1_shadow_deletion", process_name, null()))) AS shadow_cmds,
        count(eval(phase="2_encryption")) AS encryption_events,
        count(eval(phase="3_ransom_note")) AS ransom_notes
        by _time, host, user
    | eval phases_detected = mvcount(detected_phases)
    | eval severity = case(
        ransom_notes > 0 AND encryption_events > 0, "🔴 CRITICAL — Active Ransomware with Ransom Notes",
        shadow_cmds > 0 AND encryption_events > 0, "🔴 CRITICAL — Shadow Deletion + Encryption",
        encryption_events > 50, "🔴 HIGH — Mass Encryption in Progress",
        shadow_cmds > 0, "🟠 HIGH — Shadow Copy Deletion (Pre-Ransomware)",
        encryption_events > 10, "🟡 MEDIUM — File Encryption Detected",
        events > 500, "🟡 MEDIUM — Abnormal File Activity Spike",
        true(), "⚪ LOW — Monitor"
      )
    | eval kill_chain_progress = case(
        phases_detected >= 3, "██████████ 100% — Full Kill Chain",
        phases_detected = 2, "██████░░░░ 60% — Active Attack",
        phases_detected = 1, "███░░░░░░░ 30% — Early Stage",
        true(), "░░░░░░░░░░ 0%"
      )
    | where severity != "⚪ LOW — Monitor"
    | sort -encryption_events, -ransom_notes
    | rename host AS "Affected Host", user AS "User Account",
        events AS "Total Events", encryption_events AS "Encryption Events",
        ransom_notes AS "Ransom Notes Found", shadow_cmds AS "Shadow Delete Commands",
        severity AS "Severity", kill_chain_progress AS "Kill Chain Stage"

#### : Full ransomware lifecycle — LockBit, BlackCat/ALPHV, Royal, Akira, Rhysida, Play, Medusa — from shadow deletion through encryption to ransom note drop.
