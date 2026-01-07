# HTTP Data Exfiltration

Investigate data exfiltration via HTTP

### 1) Narrow down HTTP

    http

### 2) Filter based on HTTP Methods

Methods: GET, POST, PUT, etc

    http.request.method == "POST"

### 3) Filter payloads with large frame length

Adjust the number to reduce noise!

    http.request.method == "POST" and frame.len > 500

