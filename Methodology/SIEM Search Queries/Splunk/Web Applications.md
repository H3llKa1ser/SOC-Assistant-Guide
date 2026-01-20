# Web Applications

### 1) Brute Force activity

    index=* method=POST uri_path="/wp-login.php" | bin _time span=5m | stats values(referer_domain) as referer_domain values(status) as status values(useragent) as UserAgent values(uri_path) as uri_path count by clientip _time | where count > 25 | table referer_domain clientip UserAgent uri_path count status

### 2) Web Shell

    index=* | search status=200 AND uri_path IN(*.php, *.phtm, *.asp, *.aspx, *.jsp, *.exe) AND (method=POST AND method=GET) | stats values(status) as status values(useragent) as UserAgent values(method) as method  values(uri) as uri values(clientip) as clientip count by referer_domain | where count > 2 | table referer_domain count method status clientip UserAgent uri

### 3) DDoS

    index=* status=503 | bin _time span=10m | stats values(referer_domain) as referer_domain values(status) as status values(useragent) as UserAgent values(uri_path) as uri_path count by clientip _time | where count > 100000 | table _time referer_domain clientip UserAgent uri_path count status

### 4) Check the user-agent that a webshell uses for the requests

    index=web-alert clientip=MALICIOUS_IP uri_path="*b374k.php"
    | dedup useragent | table useragent
