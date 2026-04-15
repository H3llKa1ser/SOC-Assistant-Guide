# Password Spraying with Lockout Evasion and Timing Analysis

Detects low-and-slow spraying campaigns that deliberately stay under lockout thresholds.

    index=auth_logs action=failure
    | bucket _time span=5m
    | stats
        dc(user) AS unique_users,
        count AS attempts,
        values(user) AS targeted_accounts,
        earliest(_time) AS spray_start,
        latest(_time) AS spray_end
        by _time, src_ip
    | eval spray_duration_sec = spray_end - spray_start
    | eval attempts_per_user = round(attempts / unique_users, 2)
    | eval attempts_per_second = round(attempts / (spray_duration_sec + 1), 3)
    | where unique_users > 15 AND attempts_per_user < 3
    | eval evasion_technique = case(
        attempts_per_second < 0.5, "🕵️ Low-and-Slow (Throttled)",
        attempts_per_second < 2, "⚡ Moderate Speed",
        true(), "🔥 Fast Spray (Likely Automated)"
      )
    | eval confidence = case(
        unique_users > 50 AND attempts_per_user < 2, "🔴 Very High",
        unique_users > 30, "🟠 High",
        unique_users > 15, "🟡 Medium",
        true(), "⚪ Low"
      )
    | eval spray_start = strftime(spray_start, "%Y-%m-%d %H:%M:%S")
    | eval spray_end = strftime(spray_end, "%Y-%m-%d %H:%M:%S")
    | sort -unique_users
    | rename src_ip AS "Source IP", unique_users AS "Unique Accounts Targeted",
        attempts AS "Total Attempts", attempts_per_user AS "Attempts/User",
        attempts_per_second AS "Attempts/Second",
        evasion_technique AS "Evasion Technique", confidence AS "Confidence"
