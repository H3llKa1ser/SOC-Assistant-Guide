# Detection Tuning

The first time you enable a rule against real production traffic, one of three things may happen:

1) Too many alerts: the rule fires on legitimate activity that resembles the malicious pattern. Analysts experience alert fatigue and start ignoring or auto-closing alerts, sometimes including the real ones.

2) Too few alerts: the rule is so narrow that real attacks evade it. False negatives are silent failures: nothing tells you the rule missed something until the incident comes up.

3) Right number, wrong context: alerts fire on the right behavior but lack enough information for an analyst to act on them quickly, slowing down triage.

Detection tuning is the iterative process of adjusting rules to maximize true positive coverage while minimizing false positives, keeping alerts actionable and severity calibrated to actual risk.

## Detection Tuning Trade-off Matrix (By THM)

<img width="758" height="692" alt="image" src="https://github.com/user-attachments/assets/3a2ed047-3538-4aad-89c3-563c79827460" />

## Tuning Strategies

There are four core tuning techniques every detection engineer uses to bring a rule under control, and you should be aware of:

1) Allowlisting / Exclusions: Exclude known-good processes, service accounts, or expected IPs. If your vulnerability scanner generates 1,000 failed logons every Monday, exclude its source IP rather than letting it drown out real spray attempts.

2) Threshold Adjustment: Change the count, time window, or sensitivity. Firing on every failed logon is noise; firing on 15 failures in 5 minutes is a signal.

3) Field Enrichment: Add context fields to reduce ambiguity. A whoami.exe alert is low-confidence on its own, but enriched with parent process, logon ID, and source IP, it becomes triageable.

4) Full Rework: A rule was designed for a purpose that no longer holds, and incremental adjustments cannot fix it. The detection logic, scope, or rule type itself needs to be rebuilt from scratch with a new context and design. 

