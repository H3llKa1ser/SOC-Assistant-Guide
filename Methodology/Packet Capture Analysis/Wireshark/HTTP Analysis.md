# HTTP Analysis

Investigate data exfiltration or Command and Control traffic using HTTP

### 1) Narrow down HTTP

    http

### 2) Filter based on HTTP Methods

Methods: GET, POST, PUT, etc

    http.request.method == "POST"

### 3) Filter payloads with large frame length

Adjust the number to reduce noise!

    http.request.method == "POST" and frame.len > 500

### 4) Filter HTTP response codes

Response codes: 200, 301, 302, 400, 401, 403, 404, 405, 408, 500, 503

    http.response.code == 200

### 5) Filter user-agent

Example

    http.user_agent contains "nmap"

Vulnerability scanners and fuzzers filter example

    (http.user_agent contains "sqlmap") or (http.user_agent contains "Nmap") or (http.user_agent contains "Wfuzz") or (http.user_agent contains "Nikto")

### 6) Filter request URI

Example

    http.request.uri contains "admin"

### 7) Filter full URI

Example

    http.request.full_uri contains "admin"

### 8) Filter hostname of the server

    http.host contains "keyword"

### 9) Filter server service name

    http.server contains "apache"
