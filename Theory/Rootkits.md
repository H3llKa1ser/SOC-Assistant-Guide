# ROOTKITS

### Rootkits use typosquatting to masquerade as other legitimate processes.

### Also they use networking tools like netcat (nc) to connect back to the attacker via a reverse shell.

## Countermeasures:

### Collect registry artifacts for analysis, find the networking tool's PID as well as the masquerading program's PID then use taskkill to kill the processes.

### Example: taskkill /F /pid NUM 

### We can also find registry keys and delete malicious entries.
