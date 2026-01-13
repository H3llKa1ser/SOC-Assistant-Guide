# Process Monitoring

Important event codes listed below

| Event Code | Purpose | Limitations |
|-----------|---------|-------------|
| 4688 (Security Log: Process Creation) | Logs an event every time a new process is launched, including command line and parent process details | Disabled by default; must be explicitly enabled following official Microsoft documentation |
| 1 (Sysmon: Process Creation) | Replaces Event ID 4688 and provides richer telemetry such as process hash and digital signature | Sysmon is an external tool and is not installed by default; requires deployment and configuration |

