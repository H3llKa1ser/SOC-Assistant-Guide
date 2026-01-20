# Linux logs

Query various log files from a Linux system to conduct further investigation.

### 1) User account creation

    index=main | search "Account Created" OR "new user" OR "useradd" OR "account added" | table _time, _raw | sort _time

### 2) Successful privilege escalation as root

    index=main source="auth.log" | search (sudo OR su OR "root") AND ("COMMAND" OR "session opened" OR "authentication") | table _time, user, _raw | sort _time

### 3) Brute-force attack 

    index=main source="auth.log" *USER* process=sshd  | search "Accepted password" OR "Failed password"

### 4) Port connections

    index=main *port*

### 5) Persistence mechanisms

    index=main sourcetype=syslog ("CRON" OR "cron") |  search ("python" OR "perl" OR "ruby" OR ".sh" OR "bash" OR "nc")

### 6) Enumerate the count of sign-in attempts per user

    index="linux-alert" sourcetype="linux_secure" 10.10.242.248
    | rex field=_raw "^\d{4}-\d{2}-\d{2}T[^\s]+\s+(?<log_hostname>\S+)"
    | rex field=_raw "sshd\[\d+\]:\s*(?<action>Failed|Accepted)\s+\S+\s+for(?: invalid user)? (?<username>\S+) from (?<src_ip>\d{1,3}(?:\.\d{1,3}){3})"
    | eval process="sshd"
    | stats count values(src_ip) as src_ip values(log_hostname) as hostname values(process) as process by username
