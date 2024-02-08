## (Cited from: Effective threat investigation for SOC analysts)

# EMAIL AUTHENTICATION

### It's the process that ensures that the email sender's identity and domain are not spoofed by a malicious actor before the email message is delivered to the end user. An attacker can avoid this by impersonating trusted and well-known legitimate domains that he might have compromised.

# EMAIL AUTHENTICATION PROTOCOLS

## 1) Sender Policy Framework (SPF)

## 2) DomainKeys Identified Mail (DKIM)

## 3) Domain-Based Message Authentication Reporting and Conformance (DMARC) 


### SPF:  It's an email authentication protocol that provides a DNS TXT record in the domain’s DNS records that specifies which IP addresses or hostnames are authorized to send emails for and on behalf of this domain. Such an authentication mechanism allows the receiving email server to check whether the email is spoofed or not by looking up the sender domain’s SPF record and then comparing the IP or hostname that sent the email message with the IP or hostname that exists in the domain SPF record. If the two values match, the server passes the email message to the recipient’s mailbox. If they don’t, the email is blocked.  
