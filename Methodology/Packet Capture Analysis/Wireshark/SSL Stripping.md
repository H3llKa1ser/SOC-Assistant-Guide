# SSL Stripping

It may appear after a successful DNS spoofing attack.

### 1) Narrow down to SSL/TLS traffic

    tls || ssl

### 2) Verify that our domain of interest communicates using TLS

    tls.handshake.type == 1 && tls.handshake.extensions_server_name == "domain.local"

### 3) Filter for DNS responses from the attacker, show that the victim was pointed to the attacker's IP

    dns.flags.response == 1 && ip.src == ATTACKER_IP && dns.qry.name == "domain.local"

### 4) Verify TLS removal

    http && ip.src == SERVER_IP && ip.dst == ATTACKER_IP

Then you can check for any plaintext credentials that the victim may have submitted.

## Attack Indicators

### 1) Initial Request vs. Response: 

The user's initial request may be for HTTPS (port 443), but the subsequent packets immediately shift to unencrypted HTTP (port 80) for the same domain.

### 2) Redirects/Link Rewriting: 

Monitoring for redirects (HTTP Status Codes 301, 302) that persistently direct an HTTPS request to an HTTP resource.

### 3) Certificate Errors: 

Although the attacker usually tries to hide this, the initial TLS/SSL Handshake may fail or display a self-signed certificate if the attacker uses a more direct proxying technique.
