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
