# Web Applications

### 1) Check for POST requests of a specific IP address

    _index:weblogs and client.ip:SUSPICIOUS_IP and http.request.method:POST

### 2) Check for GET requests of a specific file (can be a webshell)

    _index:weblogs and client.ip:SUSPICIOUS_IP and http.request.method:GET and webshell.aspx

