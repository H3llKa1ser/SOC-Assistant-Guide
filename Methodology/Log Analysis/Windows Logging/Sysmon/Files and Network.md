# Files and Network Monitoring

Important Event codes below

| Event ID | Security Log Alternative | Event Purpose |
|---------|--------------------------|---------------|
| 11 / 13 (File Create / Registry Value Set) | 4656 for file changes and 4657 for registry changes (both disabled by default) | Detect files dropped by malware or registry modifications used for persistence |
| 3 / 22 (Network Connection / DNS Query) | No direct alternative; requires additional firewall and DNS logging configuration | Detect network traffic from untrusted processes or connections to known malicious destinations |


