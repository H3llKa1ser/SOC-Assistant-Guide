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
