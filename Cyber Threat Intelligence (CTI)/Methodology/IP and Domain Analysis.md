# IP and Domain Analysis

## DNS 

### Sites to check for DNS information

#### 1) nslookup.io

https://www.nslookup.io/

#### 2) dnschecker.org

https://dnschecker.org/

#### 3) dnsdumspter.com

https://dnsdumpster.com/

#### 4) VirusTotal

https://www.virustotal.com/gui/home/search

### DNS records to use for analysis:

#### 1) A / AAAA Records: 

Map the domain to IPv4 and IPv6 addresses. If you see several A records that hop between different networks, raise suspicion of rapid rotation. In practice, copy the A record from nslookup.io or dnschecker.org and follow with pasting the IP into VirusTotal for a quick read.

#### 2) NS Records: 

Identify the nameservers controlling the domain. Unusual or recently changed NS entries can mark fresh set up. As L1 analysts, we should note the provider name rather than chasing low-level details.

#### 3) MX Records: 

Define which servers handle email. Attackers may configure MX records to deliver phishing campaigns directly. If the alert relates to web browsing, just record whether MX exists.

#### 4) TXT Records: 

Store SPF and DKIM rules or verification tags. Poorly configured or absent SPF can increase risk in mail cases.

#### 5) SOA Record: 

Points to the zone's primary authority and often includes contact information. It will be worth noting the primary host and serial, which will support a basic ownership picture.

#### 6) TTL (Time To Live): 

Tells resolvers how long to cache answers. Very low TTLs, seconds or minutes, can point to frequent changes, and should be treated as clues.

### Attacks using DNS

#### 1)Fast Flux Hosting: 

Adversaries rotate many IPs quickly with short cache times to avoid simple blocks. We need to record and escalate when we identify a domain that resolves to changing IPs within a short period and across different providers.

#### 2) CDN Abuse: 

Legitimate CDNs like Cloudflare or Akamai change IPs too, but done within their ASN ecosystem. If the A record points to a major CDN and other values are normal, take note and carry reputation and ownership checks,

#### 3) Typosquatting: 

Domains like paypa1[.]com or micros0ft[.]net trick users visually. If a name looks like a brand clone, treat it as high risk and escalate it.

#### 4) IDN (Internationalised Domain Names): 

Attackers exploit Unicode, creating look-alike domains. Decode Punycode, for example xn--ppaypal-3ya[.]com, and compare to known brands using simple online decoder.

## IP Enrichment

If you find a potentially suspicious IP for further analysis, gather information using RDAP

#### 1) Registration Data Access Protocol (RDAP)

https://about.rdap.org/

## Geolocation

GeoIP tools

#### 1) ipinfo.io

https://ipinfo.io/

#### 2) iplocation.net

https://www.iplocation.net/

## Service Analysis

### Check for exposed services of an IP/Domain

#### 1) shodan.io

https://www.shodan.io/

#### 2) censys.io

https://search.censys.io/

### TLS Certificate Transparency

#### 1) crt.sh

https://crt.sh/

## Reputation Checks

#### 1) VirusTotal

https://www.virustotal.com/gui/home/search

#### 2) Cisco Talos Intelligence

https://talosintelligence.com/reputation_center

#### 3) IP2Proxy

https://www.ip2proxy.com/
