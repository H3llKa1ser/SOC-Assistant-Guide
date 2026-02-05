# Credential Stuffing

Detect credential stuffing attacks 

#### DO NOT FORGET TO REPLACE SOME OF THE VALUES ACCORDING TO YOUR ENVIRONMENT!!!!

Workflow

┌─────────────────────────────────────────────────────────────────┐
│                 CREDENTIAL STUFFING DETECTION WORKFLOW          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │   Layer 1    │───▶│   Layer 2    │───▶│   Layer 3    │      │
│  │  Detection   │    │  Correlation │    │   Response   │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│         │                   │                   │               │
│  • Volume-based      • Geo anomalies     • Block IP           │
│  • Velocity-based    • User-Agent        • Force MFA          │
│  • Pattern-based     • Success after     • Lock accounts      │
│  • IP reputation       failures          • Alert SOC          │
│                                                                 │
├─────────────────────────────────────────────────────────────────┤
│  SCHEDULED SEARCHES:                                            │
│  • Real-time: Every 5 minutes (Query #10)                      │
│  • Hourly: Distributed attack detection (Query #2)             │
│  • Daily: Geographic anomaly report (Query #4)                 │
└─────────────────────────────────────────────────────────────────┘


### 1) High volume failed logins form a single IP

    index=auth sourcetype=authentication action=failure
    | stats count as failed_attempts dc(user) as unique_users by src_ip
    | where failed_attempts > 50 AND unique_users > 10
    | sort -failed_attempts
    | table src_ip, failed_attempts, unique_users

### 2) Multiple failed logins followed by a successful one

    index=auth sourcetype=authentication
    | stats count(eval(action="failure")) as failures, 
            count(eval(action="success")) as successes,
            values(user) as targeted_users by src_ip
    | where failures > 20 AND successes >= 1
    | eval success_ratio = round(successes/(failures+successes)*100,2)
    | sort -failures
    | table src_ip, failures, successes, success_ratio, targeted_users

### 3) Rapid login attemts (Bots)

    index=auth sourcetype=authentication action=failure
    | streamstats current=f last(_time) as prev_time by src_ip
    | eval time_diff = _time - prev_time
    | where time_diff < 2 AND time_diff > 0
    | stats count as rapid_attempts avg(time_diff) as avg_interval by src_ip
    | where rapid_attempts > 20
    | table src_ip, rapid_attempts, avg_interval

### 4) Geographically impossible logins

    index=auth sourcetype=authentication action=success
    | iplocation src_ip
    | stats earliest(_time) as first_login, latest(_time) as last_login, 
            values(City) as cities, values(Country) as countries, 
            dc(Country) as country_count by user
    | where country_count > 1
    | eval time_window = last_login - first_login
    | where time_window < 3600
    | table user, cities, countries, time_window

### 5) Failed logins across multiple accounts from the same IP

    index=auth sourcetype=authentication action=failure
    | bin _time span=1h
    | stats dc(user) as unique_accounts, count as total_attempts by src_ip, _time
    | where unique_accounts > 25
    | sort -unique_accounts
    | table _time, src_ip, unique_accounts, total_attempts

### 6) User-agent (Bots)

    index=auth sourcetype=authentication action=failure
    | stats count by http_user_agent, src_ip
    | where count > 50
    | search http_user_agent IN ("python-requests/*", "curl/*", "wget/*", "Go-http-client/*", "-", "")
      OR match(http_user_agent, "(?i)(bot|crawler|spider|script)")
    | table src_ip, http_user_agent, count

### 7) Dashboard creation (reporting purposes)

    index=auth sourcetype=authentication
    | stats count(eval(action="failure")) as failures,
            count(eval(action="success")) as successes,
            dc(user) as unique_users,
            avg(eval(if(action="failure", 1, 0))) as failure_rate by src_ip
    | eval risk_score = (failures * 0.3) + (unique_users * 2) + (failure_rate * 50)
    | where risk_score > 100
    | sort -risk_score
    | table src_ip, failures, successes, unique_users, failure_rate, risk_score

### 8) Time-based pattern detection (Non-business hours attacks)

    index=auth sourcetype=authentication action=failure
    | eval hour=strftime(_time, "%H")
    | eval is_off_hours = if(hour < 6 OR hour > 22, 1, 0)
    | stats count as attempts sum(is_off_hours) as off_hour_attempts by src_ip
    | eval off_hour_pct = round(off_hour_attempts/attempts*100, 2)
    | where attempts > 50 AND off_hour_pct > 70
    | table src_ip, attempts, off_hour_attempts, off_hour_pct

### 9) Real-time credential stuffing detection alert

    index=auth sourcetype=authentication action=failure
    | bin _time span=5m
    | stats count as attempts dc(user) as unique_users by src_ip, _time
    | where attempts > 100 AND unique_users > 20
    | eval alert_msg = "Potential credential stuffing from " . src_ip . " - " . attempts . " attempts against " . unique_users . " users"
    | table _time, src_ip, attempts, unique_users, alert_msg

## Customization tips

| Parameter        | Adjust Based On                                                                 |
|------------------|---------------------------------------------------------------------------------|
| `index=auth`     | Your authentication log index                                                   |
| `sourcetype=authentication` | Your auth sourcetype (e.g., `WinEventLog:Security`, `linux_secure`)  |
| `action=failure/success` | Your field names for login status                                       |
| Thresholds (50, 100, etc.) | Your normal baseline traffic                                          |
