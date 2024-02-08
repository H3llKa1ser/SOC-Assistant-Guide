## (Cited from: Effective threat investigation for SOC analysts)

# EMAIL AUTHENTICATION

### It's the process that ensures that the email sender's identity and domain are not spoofed by a malicious actor before the email message is delivered to the end user. An attacker can avoid this by impersonating trusted and well-known legitimate domains that he might have compromised or new domains that he recently registered.

# EMAIL AUTHENTICATION PROTOCOLS

## 1) Sender Policy Framework (SPF)

## 2) DomainKeys Identified Mail (DKIM)

## 3) Domain-Based Message Authentication Reporting and Conformance (DMARC) 


### 1) SPF:  It's an email authentication protocol that provides a DNS TXT record in the domain’s DNS records that specifies which IP addresses or hostnames are authorized to send emails for and on behalf of this domain. Such an authentication mechanism allows the receiving email server to check whether the email is spoofed or not by looking up the sender domain’s SPF record and then comparing the IP or hostname that sent the email message with the IP or hostname that exists in the domain SPF record. If the two values match, the server passes the email message to the recipient’s mailbox. If they don’t, the email is blocked.  

## SPF Record example: 

### v=spf1 ip4:192.168.1.0/24 -all

#### 1) v=spf1 = SPF Version

#### 2) ip4:IP_ADDRESS/CIDR = Specifies the domain's email should be sent from an IP address in a specific range

#### 3) -all = Any mails failing the SPF check should be rejected outright

#### 4) ~all = Any mails failing the SPF check should be marked as spam, but not immediately rejected

#### 5) ?all = No preference. (Neutral option) 

#### 6) +all = Any sender is authorized to send emails on behalf of the domain (Insecure)

#### 7) - (Hyphen) = No policy defined (Neutral Option)

### 2) DKIM: It's an encryption methodology or digital signature that’s added to email headers as an email authentication mechanism to prevent email spoofing attempts. To generate the digital signature, it hashes the email message body and encrypts it alongside a list of the email header parameters using the private key. Then, it publishes the public key in the DNS records of the signer’s domain as a DNS TXT record type. The recipient can then retrieve the signer’s public key from the sender’s DNS records for decryption and to verify whether the signature is valid.

## DKIM Signature example: 

### DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=yahoo.com; s=s2048; t=1664539473; bh=1Ttd55RGpBC1Cevt3Xgw1XO9lBgWZj04bmslL5Urark=; h=Date:From:To:Subject:References:From:Subject:Reply-To; b=kRlmdNKBXBZsJLZvTpVqlfojnQL2aqxmliyWmE0bFLOdjgQXhpwAKF4pwYYsaWSDfyCekboIcwcuIQB/KyuRmqgyJpFXHEhD0eM7ppUswo6fPbyGIrUJKEeujHmnvOn7izMcVXFfbZl17g61TSbQaA/nj3uzusVqbQmS8ww0Rncsg7m+9FUWmiQn673zdWTnMsOxgoG7+b4QVJ4QvjvUWGyrRjXHMkxn0wtkn+u4B/V5uEoh3+I8tjtCBLBlLEOpQBAuIllc87vi7BwI44HplmnPTwv9wkLV9kjikNbrr4cEz9Vxehif2eLZd+FU3hwU04nPhjYSOWS2w5Y44jZi6w==

#### 1) v = DKIM version

#### 2) a = Encryption and hashing algorithm

#### 3) c=header/body =  Canonicalization algorithm that determines how the body and header are prepared for the hashing algorithm.

#### Canonicalizations:

#### simple/simple = Only removes trailing white spaces from the header fields and doesn;t modify the message body before hashing.

#### relaxed/relaxed = Certain modifications can be made to the header and body of the email before the hashing process takes place, while still preserving the essential content of the message

#### 4) d = Domain that is claiming to be authorized to send an email.This domian is where the email servers search for the public key in its DNS records to verify the authenticity of the DKIM signature.

#### 5) s = Selector value used to define the value used in the DNS lookup to get the public key.

#### 6) t = Epoch timestamp

#### 7) bh = Base64-encoded strings of ther encoded message after it was canonicalized via method in c and then hashed via the hashing function in a

#### 8) h = Headers

#### 9) b = DKIM Signature

### 3) DMARC: It's an email authentication, policy, and reporting protocol that depends on the SPF and DKIM authentication results. If the authentication fails in any protocol, be it SPF, DKIM, or both, then DMARC applies the predefined policies by the sender domain owner and reports the violation to the sender domain owner. DMARC policies are published in the domain’s DNS as a TXT record containing the policy that should be applied when an email message fails to be authenticated and the email reports a violation.

## DMARC Record example: 

### v=DMARC1;p=reject;pct=100;rua=mailto:TEST@MAIL.com

#### 1) v = DMARC version

#### 2) p = Policy application in case the email fails the authentication process. 

#### Policies: 

#### Quarantine: Accepts the email but sends it to the junk folder for investigation

#### Reject: Email is rejected

#### None: No action taken

#### 3) pct = Percentage of email messages subjected to the policy (Range: 1-100) Example: p=reject;pct=50 means that 50% of the emails that fail authentication are rejected, and the other 50% fall back to the next lower policy in sequence (quarantine)

#### 4) rua = Specifies the URI of the mailbox what will receive DMARC aggregate reports

#### 4) 
