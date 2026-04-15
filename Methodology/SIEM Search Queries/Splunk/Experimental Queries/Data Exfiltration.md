# Data Exfiltration — Multi-Channel Detection (Network, Cloud, DNS, USB)

Detects exfiltration across all common channels — not just network.

    index=network_logs direction=outbound
    | append
        [search index=cloud_logs event_type IN ("file_upload", "file_share") 
         | eval dest_ip=dest_host, bytes_out=file_size, channel="☁️ Cloud Upload"]
    | append
        [search index=endpoint_logs event_type="usb_write"
         | eval dest_ip="USB:" . device_id, bytes_out=bytes_written, channel="🔌 USB Transfer"]
    | append
        [search index=dns_logs
         | where len(query) > 52
         | eval dest_ip=query, bytes_out=len(query) * 2, channel="📡 DNS Tunnel (Est.)"]
    | eval channel = if(isnull(channel), "🌐 Network", channel)
    | eval bytes_mb = round(bytes_out / 1024 / 1024, 2)
    | bucket _time span=1h
    | stats
        sum(bytes_mb) AS total_mb,
        count AS transfer_count,
        dc(dest_ip) AS unique_destinations,
        values(dest_ip) AS destinations,
        values(channel) AS exfil_channels,
        dc(channel) AS channel_count,
        earliest(_time) AS exfil_start,
        latest(_time) AS exfil_end
        by _time, src_ip, host, user
    | eval exfil_duration_min = round((exfil_end - exfil_start) / 60, 1)
    | eval mb_per_minute = round(total_mb / (exfil_duration_min + 0.1), 2)
    | where total_mb > 100 OR (channel_count > 1 AND total_mb > 50)
    | iplocation dest_ip
    | eval risk_level = case(
        channel_count > 2 AND total_mb > 500, "🔴 CRITICAL — Multi-Channel Mass Exfiltration",
        channel_count > 1, "🔴 HIGH — Multi-Channel Exfiltration",
        total_mb > 5000, "🔴 CRITICAL — Mass Data Transfer",
        total_mb > 1000, "🟠 HIGH — Large Exfiltration",
        total_mb > 500, "🟡 MEDIUM — Significant Transfer",
        total_mb > 100, "⚪ LOW — Elevated Transfer (Review)",
        true(), "⚪ Monitor"
      )
    | eval exfil_start = strftime(exfil_start, "%Y-%m-%d %H:%M:%S")
    | eval exfil_end = strftime(exfil_end, "%Y-%m-%d %H:%M:%S")
    | sort -total_mb
    | rename src_ip AS "Source IP", host AS "Internal Host", user AS "User",
        total_mb AS "Total MB Exfiltrated", transfer_count AS "Transfer Count",
        exfil_channels AS "Exfil Channels Used", channel_count AS "# Channels",
        mb_per_minute AS "MB/Minute", risk_level AS "Risk Level",
        Country AS "Destination Country"
