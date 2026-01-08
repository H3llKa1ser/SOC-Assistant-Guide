# Web Servers

Investigate for web app attacks like SQLi, or RCE, and even detect webshells.

## Apache

Log file: /var/log/apache2/access.log

### 1) Identify potential malicious requests, like fuzzing, for example

    cat /var/log/apache2/access.log | grep "404"

### 2) Identify successful enumeration and/or successful file upload on the web server

    cat /var/log/apache2/access.log | grep "200"

### 3) Identify potentially successful login attempts on an online login form

    cat /var/log/apache2/access.log | grep "302"

### 4) Identify any potentially malicious file upload via POST request

    cat /var/log/apache2/access.log | grep "POST"

### 5) Check for any commands that the attacker ran with the uploaded webshell

Parameters can be different!

    cat /var/log/apache2/access.log | grep "cmd="
