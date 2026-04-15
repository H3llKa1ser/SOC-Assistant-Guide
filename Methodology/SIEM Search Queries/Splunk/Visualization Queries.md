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

### 14) appendcols – Merge Two Searches Side by Side

Combine results from different searches into one table.

    index=sales | stats sum(revenue) AS total_revenue by region
    | appendcols
        [search index=sales | stats count AS total_orders by region]
    | table region, total_revenue, total_orders

### 15) join – Combine Data from Different Indexes

Like a SQL JOIN — merge two datasets on a common field.

    index=users
    | join user_id
        [search index=orders | stats sum(amount) AS total_spent by user_id]
    | table user_id, username, email, total_spent
    | sort -total_spent

### 16) fillnull – Replace Nulls with Readable Defaults

Prevents confusing blank cells in your output.

    index=web_logs
    | stats count by user, status_code
    | fillnull value="N/A"

### 17) sort – Control Display Order

Make tables easier to scan by sorting meaningfully.

    index=auth_logs
    | stats count AS login_attempts by user
    | sort -login_attempts
    | head 20

### 18) where – Filter Results with Expressions

More powerful than simple keyword filtering.

    index=transactions
    | stats avg(response_time) AS avg_rt by endpoint
    | where avg_rt > 2.0
    | sort -avg_rt

### 19) case() inside eval – Multi-Condition Labels

More powerful than simple if() — like a switch statement.

    index=web_logs
    | eval severity = case(
        status_code >= 500, "🔴 Server Error",
        status_code >= 400, "🟡 Client Error",
        status_code >= 300, "🔵 Redirect",
        status_code >= 200, "🟢 Success",
        true(), "⚪ Unknown"
      )
    | stats count by severity

### 20) foreach – Apply Logic Across Multiple Fields

Avoid repetitive eval statements.

    index=sales
    | stats sum(q1_revenue) AS q1, sum(q2_revenue) AS q2, sum(q3_revenue) AS q3, sum(q4_revenue) AS q4 by region
    | foreach q* [eval <<FIELD>> = "$" + tostring('<<FIELD>>', "commas")]

