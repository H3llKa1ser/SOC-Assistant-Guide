## (Cited from: Effective threat investigation for SOC analysts)

# EMAIL AUTHENTICATION

### It's the process that ensures that the email sender's identity and domain are not spoofed by a malicious actor before the email message is delivered to the end user. An attacker can avoid this by impersonating trusted and well-known legitimate domains that he might have compromised or recently registered.

# EMAIL AUTHENTICATION PROTOCOLS

## 1) Sender Policy Framework (SPF)

## 2) DomainKeys Identified Mail (DKIM)

## 3) Domain-Based Message Authentication Reporting and Conformance (DMARC) 


### 1) SPF:  It's an email authentication protocol that provides a DNS TXT record in the domain’s DNS records that specifies which IP addresses or hostnames are authorized to send emails for and on behalf of this domain. Such an authentication mechanism allows the receiving email server to check whether the email is spoofed or not by looking up the sender domain’s SPF record and then comparing the IP or hostname that sent the email message with the IP or hostname that exists in the domain SPF record. If the two values match, the server passes the email message to the recipient’s mailbox. If they don’t, the email is blocked.  

#### SPF Record example: v=spf1 ip4:192.168.1.0/24 -all

#### 1) v=spf1 = SPF Version

#### 2) ip4:IP_ADDRESS/CIDR = Specifies the domain's email should be sent from an IP address in a specific range

#### 3) -all = Any mails failing the SPF check should be rejected outright

#### 4) ~all = Any mails failing the SPF check should be marked as spam, but not immediately rejected

#### 5) ?all = No preference. (Neutral option) 

#### 6) +all = Any sender is authorized to send emails on behalf of the domain (Insecure)

#### 7) - (Hyphen) = No policy defined (Neutral Option)

### 2) DKIM: is an encryption methodology or digital signature that’s added to email headers as an email authentication mechanism to prevent email spoofing attempts. To generate the digital signature, it hashes the email message body and encrypts it alongside a list of the email header parameters using the private key. Then, it publishes the public key in the DNS records of the signer’s domain as a DNS TXT record type. The recipient can then retrieve the signer’s public key from the sender’s DNS records for decryption and to verify whether the signature is valid.

#### DKIM Signature example: DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=yahoo.com; s=s2048; t=1664539473; bh=1Ttd55RGpBC1Cevt3Xgw1XO9lBgWZj04bmslL5Urark=; h=Date:From:To:Subject:References:From:Subject:Reply-To; b=kRlmdNKBXBZsJLZvTpVqlfojnQL2aqxmliyWmE0bFLOdjgQXhpwAKF4pwYYsaWSDfyCekboIcwcuIQB/KyuRmqgyJpFXHEhD0eM7ppUswo6fPbyGIrUJKEeujHmnvOn7izMcVXFfbZl17g61TSbQaA/nj3uzusVqbQmS8ww0Rncsg7m+9FUWmiQn673zdWTnMsOxgoG7+b4QVJ4QvjvUWGyrRjXHMkxn0wtkn+u4B/V5uEoh3+I8tjtCBLBlLEOpQBAuIllc87vi7BwI44HplmnPTwv9wkLV9kjikNbrr4cEz9Vxehif2eLZd+FU3hwU04nPhjYSOWS2w5Y44jZi6w==
