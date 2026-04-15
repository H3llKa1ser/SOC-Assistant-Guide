# Credential Stuffing / Brute Force with Geo-Anomaly Detection

Detects brute force with geographic impossibility — logins from two distant countries within minutes.

    index=auth_logs action IN ("failure", "success")
    | iplocation src_ip
    | bucket _time span=10m
    | stats
        count(eval(action="failure")) AS failures,
        count(eval(action="success")) AS successes,
        dc(Country) AS unique_countries,
        values(Country) AS countries,
        values(City) AS cities,
        earliest(_time) AS first_seen,
        latest(_time) AS last_seen
        by src_ip, user
    | eval time_window_sec = last_seen - first_seen
    | where (failures > 20 AND successes >= 1) OR (unique_countries > 1 AND time_window_sec < 600)
    | eval attack_type = case(
        unique_countries > 1 AND successes >= 1, "🔴 Impossible Travel + Credential Stuffing",
        unique_countries > 1, "🟠 Impossible Travel Detected",
        failures > 50 AND successes >= 1, "🔴 Confirmed Credential Stuffing",
        failures > 20 AND successes >= 1, "🟡 Probable Brute Force with Success",
        true(), "⚪ Suspicious"
      )
    | eval risk_score = round((failures * 2) + (successes * 20) + (unique_countries * 50), 0)
    | eval first_seen = strftime(first_seen, "%Y-%m-%d %H:%M:%S")
    | eval last_seen = strftime(last_seen, "%Y-%m-%d %H:%M:%S")
    | sort -risk_score
    | rename src_ip AS "Source IP", user AS "Targeted User",
        failures AS "Failed Attempts", successes AS "Successful Logins",
        countries AS "Countries", cities AS "Cities",
        risk_score AS "Risk Score", attack_type AS "Detection Type",
        first_seen AS "First Seen", last_seen AS "Last Seen"
