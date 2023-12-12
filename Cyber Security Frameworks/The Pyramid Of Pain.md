# PYRAMID OF PAIN

### Pyramid of pain is a framework that measures the effectiveness of threat actors in a pyramid shape with different colors per level, from bottom to top, meaming the topmost is pretty much game over for an attacker if he is detected and vice versa.

### Categories:

### 1) Hash values (Level: Trivial, Color: Blue)

#### An attacker can easily modify his tools/programs etc. just enough to completely alter the hash output of the tool/program.

#### Hash lookup tools: VirusTotal, MetaDefender Cloud - OPSWAT

### 2) IP Addresses (Level: Easy, Color: Green)

#### An attacker can successfully carry out IP blocking by using the fast flux technique.

#### Defensive countermeasures: Block, drop or deny inbound requests from IP addresses on your parameter or external firewall. ( Also an attacker might use a new public IP address)

### 3) Domain Names (Level:Simple, Color: Turquoise)

#### An attacker will most likely need to purchase the domain, register it and modify DNS records.

#### Punycode attack: Punycode is a way of converting words that cannot be written in ASCII into a Unicode ASCII encoding.

#### Attackers also may hide the malicious domains inder URL shorteners.

#### URL Shortener: A tool that creates a short and unique URL that will redirect to the specific website specified during the initial step of setting up the URL shortener link.

#### Defenders can detect malicious domains by using proxy logs or web server logs.

## PROTIP: You can see the actual website the shortened link is redirecting you to by appending "+" to it. (Example: http://goo.gl/abcub+)

### 4) Host Artifacts (Level: Annoying, Color: Light Orange)

#### If a defender detects these kinds of attacks, the attacker would need to circle back at this detection level and change hsi attack tools and methodologies.

#### An attacker may leave traces or observables such as: attack patterns, IOCs (Indicators of Compromise), registry values, suspicious process execution, files dropped by malicious applications or anything exclusive to the current threat.

### 4.2) Network Artifacts

#### A network artifact can be a user-agent string, C2 information or URI patterns followed by the HTTP POST requests.

### 5) Tools (Level: Challenging, Color: Yellow)

#### A defender can use antivirus signatures, detection rules and YARA rules against attackers at this stage.

### Resources: MalwareBazaar, SOC Prime Threat, Detection Marketplace, malshare

#### An attacker has to use a completely new tool with the same capabilities as the one bring detected by defenders.

### 6) Tactics Techniques and Procedures TTPs (Level: Tough, Color: Red)

#### If a defender detects and responds to the TTPs quickly and efficiently, it's pretty much game over for the attacker.

### TTP Detection: The whole MITRE ATT&CK MATRIX https://attack.mitre.org/
