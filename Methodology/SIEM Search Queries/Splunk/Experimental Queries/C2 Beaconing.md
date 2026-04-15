# C2 Beaconing with Jitter Detection

Detects C2 callbacks even when attackers add jitter (random timing variation) to evade simple interval checks.

    index=network_logs direction=outbound
    | where NOT cidrmatch("10.0.0.0/8", dest_ip) AND NOT cidrmatch("172.16.0.0/12", dest_ip) AND NOT cidrmatch("192.168.0.0/16", dest_ip)
    | sort 0 src_ip, dest_ip, _time
    | streamstats
        current=f
        window=2
        last(_time) AS prev_time
        by src_ip, dest_ip
    | eval interval = _time - prev_time
    | where interval > 0
    | stats
        count AS beacon_count,
        avg(interval) AS avg_interval,
        stdev(interval) AS stdev_interval,
        min(interval) AS min_interval,
        max(interval) AS max_interval,
        dc(dest_port) AS unique_ports,
        values(dest_port) AS ports_used,
        sum(bytes_out) AS total_bytes_out,
        earliest(_time) AS first_beacon,
        latest(_time) AS last_beacon
        by src_ip, dest_ip
    | where beacon_count > 20 AND avg_interval > 10 AND avg_interval < 7200
    | eval coefficient_of_variation = round((stdev_interval / avg_interval) * 100, 2)
    | eval jitter_percent = round(((max_interval - min_interval) / avg_interval) * 100, 1)
    | eval beacon_regularity = round(avg_interval / (stdev_interval + 0.001), 2)
    | eval beacon_duration_hours = round((last_beacon - first_beacon) / 3600, 2)
    | where beacon_regularity > 3 OR (beacon_count > 50 AND coefficient_of_variation < 40)
    | eval c2_profile = case(
        avg_interval < 30 AND beacon_regularity > 15, "🔴 Fast Beacon — Likely Interactive C2",
        avg_interval < 300 AND beacon_regularity > 8, "🟠 Standard C2 Beacon (Cobalt Strike Default)",
        avg_interval < 3600 AND beacon_regularity > 5, "🟡 Slow Beacon — Long Sleep C2",
        jitter_percent < 15 AND beacon_count > 30, "🟠 Low-Jitter Beacon — Poorly Configured C2",
        coefficient_of_variation < 25, "🟡 Consistent Interval — Suspicious",
        true(), "⚪ Needs Review"
      )
    | eval avg_interval_friendly = tostring(round(avg_interval, 0), "duration")
    | eval total_mb_out = round(total_bytes_out / 1024 / 1024, 2)
    | eval first_beacon = strftime(first_beacon, "%Y-%m-%d %H:%M:%S")
    | eval last_beacon = strftime(last_beacon, "%Y-%m-%d %H:%M:%S")
    | iplocation dest_ip
    | sort -beacon_regularity
    | rename src_ip AS "Internal Host", dest_ip AS "External C2 IP",
        beacon_count AS "Beacon Count", avg_interval_friendly AS "Avg Interval",
        coefficient_of_variation AS "CV%", jitter_percent AS "Jitter%",
        beacon_regularity AS "Regularity Score", c2_profile AS "C2 Profile",
        beacon_duration_hours AS "Duration (hrs)", total_mb_out AS "Data Sent (MB)",
        Country AS "Destination Country"

