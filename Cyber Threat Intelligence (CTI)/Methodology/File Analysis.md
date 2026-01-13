# File Analysis

### 1) Get file SHA256 Hash

Certutil

    certutil -hashfile file.exe SHA256

Powershell

    Get-FileHash -Algorithm SHA256 file.exe

Linux

    sha256sum file.exe

### 2) Upload hash to VirusTotal

URL

https://www.virustotal.com/gui/home/search

What to check: (Inspired by TryHackMe)

| Section | Key Question | Red Flags | Analyst Considerations |
|-------|-------------|-----------|------------------------|
| Detection Score and Threat Labels | How many vendors detect this file as malicious? | Five or more solid vendors flag it<br>Conflicting classifications (e.g., "Trojan" vs "PUA")<br>No consensus among the top 3 vendors | New malware often has low initial detection<br>Recheck after 24h for updated results<br>Look at the classification of the malware family name or capability name |
| Upload Time | When was the file first submitted? | Uploaded seven days ago with more than 10 detections<br>Sudden detection spike after days/weeks | Vendors need 48–72 hours for full analysis<br>Historical detection growth indicates malware ageing |
| Signatures | Is the file properly signed? | Invalid or missing certificate<br>Certificate issued to an unrelated entity | Even valid certificates can be stolen or abused<br>Check certificate chain expiration dates |
| Properties | Are there anomalies in the file data? | Compile timestamp at odd hours (e.g., 3 AM)<br>High entropy (>7.5) in non-media files | Some legitimate packers (e.g., UPX) increase entropy<br>Compare with known-good versions |
| Relations | What infrastructure does the malware connect to? | Known-bad IPs in VirusTotal’s graph<br>DGA-like domains (e.g., xk8f92.xyz) | Legitimate CDNs may host malware<br>Check IPs in Shodan for open ports |
| Behavioral | What post-execution actions occur? | Modifies critical registry keys<br>Attempts process injection | Some admin tools modify registries legitimately<br>Correlate with endpoint logs |

### 3) Check MalwareBazaar

URL

https://bazaar.abuse.ch/

