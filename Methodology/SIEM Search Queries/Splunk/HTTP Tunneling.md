# HTTP Tunneling

TIP: "index" and "sourcetype" values may differ in your use case

### 1) Search in the HTTP logs

    index="data_exfil" sourcetype="http_logs"

### 2) Search for HTTP POST requests

    index="data_exfil" sourcetype="http_logs" method=POST

### 3) Look at the average amount of bytes sent out to various domains

    index="data_exfil" sourcetype="http_logs" method=POST | stats count avg(bytes_sent) max(bytes_sent) min(bytes_sent) by domain | sort - count

### 4) Search for POST requests with large payloads

    index="data_exfil" sourcetype="http_logs" method=POST bytes_sent > 600 | table _time src_ip uri domain dst_ip bytes_sent | sort - bytes_sent
