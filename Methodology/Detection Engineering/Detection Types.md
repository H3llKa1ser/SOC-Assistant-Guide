# Detection Types

## Atomic Detections

An atomic detection triggers on a single event that is independently suspicious or malicious. There is no aggregation, no correlation across multiple events, and no time-based windowing. If the event matches the rule's query, an alert fires with one event, one signal.

Atomic detections are the simplest and fastest to build. They work best when a single log entry contains enough context to indicate malicious behavior on its own: the execution of a known offensive tool, the creation of a suspicious scheduled task, or the execution of commands commonly used by attackers.

Atomic detections are appropriate when:

1) A single event is inherently suspicious regardless of the surrounding context (e.g., mimikatz.exe executable in a process creation log).

2) The detection logic does not depend on event volume, frequency, or event sequencing.

3) Speed matters. For example, you want the lowest possible detection latency with no dependency on event accumulation.

### Trade-off

Atomic detections are prone to false positives when the targeted behavior also occurs during legitimate operations. A sysadmin running whoami is not an attacker, but your rule does not know that without additional context. That's when the research process you learned previously became a core step before deploying atomic detections.

## Stateful Detections

A stateful detection triggers when events accumulate past a defined threshold within a time window. Where an atomic detection asks "Did this event happen?", a stateful detection asks "Did this event happen enough times to be suspicious?"

Stateful detections are the primary tool for identifying patterns that are normal in isolation but malicious at scale: a single failed logon is routine, but 50 failed logons from the same source IP in 2 minutes is a strong indicator of a brute-force attack.

Stateful detections are appropriate when:

1) The individual events are benign or ambiguous on their own (failed logons, DNS queries, process starts).

2) Malicious intent only becomes apparent through repetition, velocity, or cardinality. Targeting many accounts from one source, for example.

### Trade-off 

Stateful detections introduce detection latency proportional to the time window required for event accumulation. An attacker who brute-forces slowly (one attempt per minute over hours) may stay below a threshold designed for rapid attacks.

## Correlation-Based Detections

A correlation-based detection identifies ordered sequences of events that, taken together, represent a multi-step attack pattern. No single event in the sequence is necessarily malicious; the detection logic depends on specific events happening in a defined order, often joined by a common entity (host, user, process) and constrained by a time window.

Correlation-based detections are appropriate when:

1) The individual events in the sequence are benign or low-confidence on their own, but the combination in order is high-confidence malicious.

2) The attack involves multiple distinct phases that produce different event types (process creation, authentication, network connection).

3) You need to reduce false positives by requiring multiple conditions to be met sequentially, rather than alerting on any single condition.

### Trade-off 

Correlation rules are more complex to write, test, and maintain. They also require that all events in the sequence are logged and ingested. If one step in the chain is not captured, the sequence breaks and the detection fails silently.

## Anomaly Detections

Anomaly detection identifies data points or patterns that deviate significantly from an established baseline. It is the primary implementation of behavioral detection in modern SIEM platforms.

### Types of anomalies

| Anomaly Type            | Description                                                                                                        | Example                                                                                                                                 |
|-------------------------|--------------------------------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------|
| **Global Anomaly**      | A single data point far outside the norm. This is the most common and simple type of anomaly used in detection rules. | A user who averages 5 failed logins per day suddenly generates 200 in an hour.                                                        |
| **Contextual Anomaly**  | A data point that is only abnormal in a specific context. Also known as rare events.                              | A sysadmin running PowerShell at 10:00 is routine; the same command at 03:00 on a Sunday is suspicious.                              |
| **Collective Anomaly**  | Individual events that are normal in isolation but form an anomalous pattern as a series.                         | A single Windows service installation is unremarkable; multiple installations on five servers within ten minutes is not.              |

The lifecycle has four phases:

Step 1 - Training Window: The model ingests historical data and learns what "normal" looks like. For authentication, this includes typical login times, source IPs, and session frequency per user over a training period (typically 2–4 weeks minimum).

Step 2 - Baseline Definition: The model sets upper and lower bounds around the baseline. A user averaging 10 logons/day might legitimately range between 5 and 18. Anything beyond those limits is flagged.

Step 3 - Real-Time Scoring: Incoming events are scored from 0 to 100 based on how far they deviate from the baseline. A score of 15 is minor variance; a score of 85 is a significant deviation that triggers an alert.

Step 4 - Continuous Learning: Baselines update as new data arrives, adapting to legitimate changes (role changes, new projects) while retaining sensitivity to genuine deviations.
