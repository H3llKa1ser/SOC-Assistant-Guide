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
