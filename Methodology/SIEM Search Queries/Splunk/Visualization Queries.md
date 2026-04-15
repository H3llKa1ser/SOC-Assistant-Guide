# Visualize Data with Splunk

## Commands

### 1) Stats - Aggregate and Summarize data

Used to compute statistics like counts, averages, sums, etc.

    index=web_logs
    | stats count by status_code, host
    | sort -count

### 2) Timechart - Trend Over Time

Perfect for line/area charts showing events over time.

    index=web_logs
    | timechart span=1h count by status_code

### 3) Chart - Custom Pivot Tables

Like stats but optimized for chart rendering.

    index=sales
    | chart sum(revenue) over region by product

### 4) Rename - Friendly Column Names

Replaces technical field names with readable labels.

    index=network_logs
    | stats count by src_ip, dest_ip
    | rename src_ip AS "Source IP", dest_ip AS "Destination IP", count AS "Event Count"

### 5) Eval - Calculated & Formatted Fields

Create new human-readable fields using expressions.

    index=transactions
    | eval response_time_ms = round(response_time * 1000, 2)
    | eval status = if(response_time > 2, "❌ Slow", "✅ OK")
    | table user, response_time_ms, status

### 6) Table - Clean Column Display

Select and order only the fields you want to show.

    index=auth_logs action=login
    | table _time, user, src_ip, action, result
    | rename _time AS "Timestamp", src_ip AS "IP Address", result AS "Login Result"

### 7) Top -  Quickly Find Most Common Values

    index=web_logs
    | top limit=10 uri_path

### 8) Rare - Find Least Common Values (Anomaly Detection)

    index=auth_logs
    | rare limit=5 user

### 9) Eventstats - Add Aggregates Without Collapsing Rows

    index=sales
    | eventstats avg(revenue) AS avg_revenue by region
    | eval vs_avg = if(revenue > avg_revenue, "Above Average", "Below Average")
    | table salesperson, region, revenue, vs_avg

### 10) iplocation + geostats – Geographic Visualization

    index=web_logs
    | iplocation src_ip
    | geostats count by Country

### 11) fieldformat – Format Display Without Changing Values

    index=transactions
    | stats sum(amount) AS total_revenue
    | fieldformat total_revenue = "$" + tostring(round(total_revenue, 2), "commas")

### 12) lookup – Replace Codes with Descriptions

    index=web_logs
    | lookup http_status_codes.csv status_code OUTPUT status_description
    | table _time, host, status_code, status_description

### 13) bucket – Group Time or Numbers into Ranges

    index=transactions
    | bucket response_time span=0.5
    | stats count by response_time
