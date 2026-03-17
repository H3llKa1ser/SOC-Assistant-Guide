# Reconnaissance

### 1) Investigate Windows built-in commands

Sysmon

    index=win EventCode=1
    | search CommandLine IN ("*nltest*", "*net * user*", "*net * group*", "*net * view*", "*net * localgroup*")
    | table _time, host, User, Image, CommandLine, ParentImage
    | sort _time

### 2) Investigate PowerShell discovery commands

    index=win EventCode=4104
    | search Message IN ("*Get-ADUser*", "*Get-ADGroupMember*", "*Get-ADComputer*")
    | table _time, Message
    | sort _time



## AD Discovery commands

| Category | Command | What It Reveals |
|----------|---------|-----------------|
| Domain/Trust | `nltest /dclist:domain` | Domain controllers in the environment |
| Domain/Trust | `nltest /domain_trusts` | Trusted domains the attacker could pivot to |
| Accounts/Groups | `net user /domain` | All domain user accounts |
| Accounts/Groups | `net group "Domain Admins" /domain` | Members of the Domain Admins group |
| Accounts/Groups | `net group "Enterprise Admins" /domain` | Members of the Enterprise Admins group |
| Accounts/Groups | `net localgroup administrators` | Local admin accounts on the current machine |
| Systems | `net view` | Machines visible on the network |
| Systems | `net view \\THM-SHR-SRV /all` | Shares on a specific remote system |
| PowerShell | `Get-ADUser -Filter *` | AD user enumeration via PowerShell |
| PowerShell | `Get-ADGroupMember "Domain Admins"` | Admin group members via PowerShell |
| PowerShell | `Get-ADComputer -Filter *` | All computer accounts in the domain |
