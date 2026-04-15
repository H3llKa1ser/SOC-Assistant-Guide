# Living off the Land (LOLBin) — Full Chain with Parent-Child Process Analysis

Detects LOLBin abuse with parent-child process context and MITRE ATT&CK mapping.

    index=endpoint_logs event_type=process_creation
    | eval lolbin_category = case(
        match(process_name, "(?i)certutil") AND match(process_args, "(?i)urlcache|decode|encode|verifyctl"),
            "Download/Decode",
        match(process_name, "(?i)bitsadmin") AND match(process_args, "(?i)transfer|create|addfile|resume"),
            "Download via BITS",
        match(process_name, "(?i)mshta") AND match(process_args, "(?i)http|javascript|vbscript"),
            "Script Execution via MSHTA",
        match(process_name, "(?i)(wscript|cscript)") AND match(process_args, "(?i)http|\\\\|temp|appdata"),
            "Script Host Abuse",
        match(process_name, "(?i)regsvr32") AND match(process_args, "(?i)/s|/i:http|scrobj"),
            "Squiblydoo (COM Scriptlet)",
        match(process_name, "(?i)rundll32") AND match(process_args, "(?i)javascript|http|shell32|advpack|ieadvpack|setupapi|syssetup|url\.dll|pcwutl"),
            "DLL Proxy Execution",
        match(process_name, "(?i)msiexec") AND match(process_args, "(?i)/q|http|ftp"),
            "Remote MSI Install",
        match(process_name, "(?i)installutil") AND match(process_args, "(?i)/logfile=|/logtoconsole=false"),
            "InstallUtil CLM Bypass",
        match(process_name, "(?i)wmic") AND match(process_args, "(?i)process\s+call|/node:|/format:"),
            "WMIC Remote/Format Abuse",
        match(process_name, "(?i)powershell|pwsh") AND match(process_args, "(?i)encodedcommand|bypass|hidden|noprofile|invoke-expression|iex|downloadstring|downloadfile|frombase64|reflection\.assembly|net\.webclient|start-bitstransfer"),
            "PowerShell Abuse",
        match(process_name, "(?i)cmd") AND match(process_args, "(?i)/c.*powershell|/c.*certutil|/c.*bitsadmin|/c.*curl|/c.*wget|echo.*\|"),
            "CMD Chaining to LOLBin",
        match(process_name, "(?i)msdt") AND match(process_args, "(?i)ms-msdt|IT_BrowseForFile"),
            "MSDT / Follina Exploit",
        match(process_name, "(?i)msbuild") AND match(process_args, "(?i)\.xml|\.csproj|\.targets"),
            "MSBuild Inline Task Execution",
        match(process_name, "(?i)forfiles|pcalua|explorer\.exe|control\.exe") AND match(process_args, "(?i)/c|/p|http"),
            "Indirect Command Execution",
        true(), null()
      )
    | where isnotnull(lolbin_category)
    | eval mitre_technique = case(
        lolbin_category="Download/Decode", "T1140 (Deobfuscate) + T1105 (Ingress Tool Transfer)",
        lolbin_category="Download via BITS", "T1197 (BITS Jobs)",
        lolbin_category="Script Execution via MSHTA", "T1218.005 (Mshta)",
        lolbin_category="Script Host Abuse", "T1059.005 (Visual Basic)",
        lolbin_category="Squiblydoo (COM Scriptlet)", "T1218.010 (Regsvr32)",
        lolbin_category="DLL Proxy Execution", "T1218.011 (Rundll32)",
        lolbin_category="PowerShell Abuse", "T1059.001 (PowerShell)",
        lolbin_category="WMIC Remote/Format Abuse", "T1047 (WMI)",
        lolbin_category="MSBuild Inline Task Execution", "T1127.001 (MSBuild)",
        lolbin_category="MSDT / Follina Exploit", "T1218 (System Binary Proxy Execution)",
        lolbin_category="CMD Chaining to LOLBin", "T1059.003 (Windows Command Shell)",
        true(), "T1218 (Signed Binary Proxy Execution)"
      )
    | eval suspicious_parent = case(
        match(parent_process, "(?i)winword|excel|powerpnt|outlook|onenote"), "🔴 Office Application (Likely Macro/Exploit)",
        match(parent_process, "(?i)wmiprvse"), "🟠 WMI Provider (Remote Execution)",
        match(parent_process, "(?i)svchost"), "🟡 Service Host (Possibly Hijacked)",
        match(parent_process, "(?i)taskeng|taskhost"), "🟡 Scheduled Task",
        match(parent_process, "(?i)explorer"), "⚪ Explorer (User-Initiated — Verify)",
        true(), "ℹ️ " . parent_process
      )
    | stats
        count AS executions,
        values(process_args) AS argument_samples,
        values(parent_process) AS parent_processes,
        values(suspicious_parent) AS parent_context,
        values(mitre_technique) AS mitre_techniques,
        dc(host) AS hosts_affected,
        values(host) AS affected_hosts,
        dc(user) AS unique_users
        by process_name, lolbin_category, user
    | eval severity = case(
        match(parent_context, "🔴"), "🔴 CRITICAL — Office-Spawned LOLBin",
        executions > 20 AND hosts_affected > 3, "🔴 HIGH — Widespread LOLBin Abuse",
        match(lolbin_category, "MSDT|Follina"), "🔴 CRITICAL — Known Exploit Chain",
        executions > 5, "🟠 MEDIUM — Repeated LOLBin Activity",
        true(), "🟡 LOW — Single Execution (Investigate)"
      )
    | sort -executions
    | rename process_name AS "LOLBin Used", lolbin_category AS "Attack Category",
        user AS "User", executions AS "Execution Count",
        hosts_affected AS "Hosts Affected", severity AS "Severity",
        mitre_techniques AS "MITRE ATT&CK"
