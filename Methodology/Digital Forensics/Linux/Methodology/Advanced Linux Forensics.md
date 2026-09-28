# Advanced Linux Forensics

Linux forensics is its own discipline. Most commercial forensic training focuses on Windows, but Linux runs most web servers, cloud workloads, containers, firewalls, IoT devices, and much of the internet's infrastructure. When a server is breached, crypto-mined, or turned into a pivot point, you need to reconstruct what happened from logs, filesystem metadata, memory, and user artifacts. This guide follows your outline, from principles through log analysis, command-line acquisition, and Autopsy.

---

## 1. Introduction

### What Linux forensics covers

Linux forensics is the identification, preservation, acquisition, analysis, and reporting of digital evidence from Linux-based systems. In practice, you are usually answering some version of these questions: how did the attacker get in (initial access), what did they do (execution, privilege escalation, lateral movement), how did they stay (persistence), what did they touch or take (collection and exfiltration), and what did they try to hide (anti-forensics).

### Why Linux is different from Windows

Linux has no registry. Configuration lives in plain-text files, mostly under `/etc` and in hidden dotfiles in home directories. That makes the evidence easy to read but also easy for an attacker to edit.

Logging is decentralized and varies by distribution. Debian and Ubuntu write authentication events to `/var/log/auth.log`, while RHEL, CentOS, Rocky, and Fedora use `/var/log/secure`. Modern systems also use systemd-journald, which stores binary logs, and some (Debian 12 onward, for example) no longer install rsyslog by default, so the classic text logs may not exist at all.

Everything is a file. Processes, kernel state, and network connections are exposed through the virtual `/proc` and `/sys` filesystems, which is useful during live response.

Filesystems vary. You may meet ext4 (the most common), XFS (the RHEL default), Btrfs (openSUSE, Fedora Workstation), ZFS, plus LVM and LUKS encryption layered underneath. Each affects what you can recover.

Servers are often headless, remote, virtualized, or in the cloud, so "pull the plug and image the disk" is often impossible. Snapshots, remote acquisition, and live response become the norm.

### Core forensic principles

The order of volatility (RFC 3227) says to collect the most short-lived evidence first: CPU registers and cache, then memory (running processes, network connections, kernel modules), then temporary filesystems such as `/tmp`, `/dev/shm`, and `/run`, then disk, then remote logs and monitoring data, then physical configuration and backups. If you shut a compromised server down first, you lose memory-resident malware, active connections, and deleted-but-still-running binaries.

Integrity and hashing come next. Hash every piece of evidence (SHA-256 is standard, with MD5 sometimes added for legacy tool compatibility) at acquisition and again before analysis, and work only on verified copies.

Chain of custody means documenting who collected what, when, how, and where it has been stored since.

Minimize your footprint. Every command you run on a live system changes it: it updates access times, allocates memory, and writes to shell history. Use trusted, ideally statically compiled binaries from external media, write output to external storage or over the network, and document every command you run.

Write-blocking matters for dead-box acquisition. Use a hardware write blocker or at minimum set the device read-only in software.

### Linux filesystem hierarchy: where evidence lives

| Location | Forensic value |
|---|---|
| `/etc` | System configuration: `passwd`, `shadow`, `group`, `sudoers`, `crontab`, `ssh/sshd_config`, `hosts`, `ld.so.preload`, systemd units |
| `/var/log` | System, authentication, application, kernel, package, and web logs |
| `/home/<user>`, `/root` | Shell history, `.ssh/authorized_keys`, `.bashrc`/`.profile`, browser data, `.viminfo`, `.lesshst`, `.local/share/recently-used.xbel` |
| `/tmp`, `/var/tmp`, `/dev/shm` | Classic malware staging areas; `/dev/shm` is RAM-backed and gone at reboot |
| `/var/spool/cron`, `/etc/cron.*` | Scheduled-task persistence |
| `/etc/systemd/system`, `/lib/systemd/system` | Service-based persistence |
| `/var/www`, `/srv` | Web roots, where web shells hide |
| `/proc` | Live process, memory map, and network state (live systems only) |
| `/var/lib/dpkg`, `/var/lib/rpm` | Package databases, useful for integrity verification |
| `/var/cache/apt`, `/var/log/apt` | Installation history |

### Filesystem timestamps (MACB)

ext4 records four timestamps per inode, at nanosecond resolution. Modification time (mtime) changes when file content changes. Access time (atime) changes on reads, although most systems mount with `relatime`, which updates atime only if it is older than mtime or more than 24 hours old, so atime is unreliable. Change time (ctime) records inode metadata changes such as permissions, ownership, links, or renames. Birth or creation time (crtime) is set when the inode is created.

The key anti-forensics point: `touch` can forge mtime and atime, but it cannot set ctime directly, and changing mtime itself updates ctime. A file whose mtime is years old but whose ctime is last Tuesday deserves a closer look. Birth time appears in `stat` on modern coreutils and kernels, or you can pull it directly:

```bash
stat /usr/bin/suspicious
sudo debugfs -R 'stat <1234567>' /dev/sda1   # crtime straight from the inode
```

### ext4 internals relevant to recovery

An ext4 filesystem is divided into block groups, each containing a superblock copy (in some groups), group descriptors, block and inode bitmaps, an inode table, and data blocks. The journal (usually inode 8) records metadata changes and can sometimes be mined for older inode versions, which is how tools like `extundelete` and `ext4magic` recover files. When ext4 deletes a file, it zeroes the extent tree in the inode, so, unlike ext2, simply following the inode pointers usually fails. Recovery then depends on the journal or on file carving.

### Live vs. dead analysis

Live response collects volatile data from a running system: memory, processes, connections, open files. Dead-box analysis examines a powered-off disk or image. In real incidents you usually do both. First capture memory and volatile state, then image the disk or snapshot the VM, then analyze offline.

### The toolkit

| Category | Tools |
|---|---|
| Live collection | UAC (Unix-like Artifacts Collector), CatScale, custom scripts, busybox or static binaries |
| Memory acquisition | LiME, AVML, `/proc/kcore` (limited) |
| Memory analysis | Volatility 3 (needs ISF symbol files built with `dwarf2json`) |
| Disk imaging | `dd`, `dcfldd`, `dc3dd`, `ewfacquire` (libewf), `ddrescue`, Guymager |
| Filesystem analysis | The Sleuth Kit (`mmls`, `fsstat`, `fls`, `icat`, `istat`, `mactime`), `debugfs` |
| Carving and recovery | PhotoRec, foremost, scalpel, bulk_extractor, extundelete, ext4magic |
| Timelining | Plaso (`log2timeline`, `psort`), `mactime`, Timesketch |
| Log analysis | `grep`/`awk`/`sed`, `journalctl`, `ausearch`/`aureport`, `last`/`utmpdump`, Chainsaw-style tools, SIEMs |
| GUI suites | Autopsy, plus commercial tools such as X-Ways, Magnet AXIOM, EnCase |
| Detection | YARA, chkrootkit, rkhunter, Loki, `debsums`, `rpm -Va` |

---

## 2. Linux Log File Analysis (Part 1): Syslog and Authentication Logs

### How Linux logging works

Two logging systems coexist on most modern distributions. The syslog family (rsyslog, syslog-ng) writes text files under `/var/log`, configured in `/etc/rsyslog.conf` and `/etc/rsyslog.d/`. systemd-journald collects everything (kernel, services, stdout/stderr of units, syslog calls) into a structured binary journal at `/var/log/journal/` (persistent) or `/run/log/journal/` (volatile, lost at reboot). Often journald forwards to rsyslog, so you get both.

Always check the rsyslog configuration during an investigation. It tells you where logs should be going, and an attacker may have modified it to stop logging or redirect messages. Also look for remote forwarding lines such as `*.* @@loghost:514`, because a remote log server holds a copy the attacker could not easily tamper with, and may be your best evidence.

Syslog classifies messages by facility (auth, authpriv, kern, cron, daemon, mail, user, local0 through local7, and others) and severity (0 emerg, 1 alert, 2 crit, 3 err, 4 warning, 5 notice, 6 info, 7 debug). A rule like `authpriv.* /var/log/secure` routes all authpriv messages to that file.

### Key text log files

| Debian/Ubuntu | RHEL family | Contents |
|---|---|---|
| `/var/log/auth.log` | `/var/log/secure` | SSH logins, sudo, su, PAM, user and group changes |
| `/var/log/syslog` | `/var/log/messages` | General system messages |
| `/var/log/kern.log` | (in `messages`) | Kernel messages: module loads, USB devices, segfaults, firewall hits |
| `/var/log/cron.log` (if enabled) | `/var/log/cron` | Cron job execution |
| `/var/log/dpkg.log`, `/var/log/apt/history.log` | `/var/log/dnf.log`, `/var/log/yum.log`, `/var/log/dnf.rpm.log` | Package installs and removals |
| `/var/log/ufw.log` | firewalld logs to journal | Firewall events |
| `/var/log/mail.log` | `/var/log/maillog` | Mail server activity |
| `/var/log/boot.log` | `/var/log/boot.log` | Boot-time service messages |

A typical syslog line looks like this:

```
Sep 27 03:14:22 web01 sshd[21873]: Failed password for invalid user admin from 203.0.113.45 port 51122 ssh2
```

It contains a timestamp (classic format has no year and no time zone, which matters for timelines), the hostname, the process with its PID, and the message. Newer rsyslog configurations may use RFC 5424 or high-precision ISO 8601 timestamps.

### Log rotation

`logrotate` (configured in `/etc/logrotate.conf` and `/etc/logrotate.d/`) renames old logs to `auth.log.1`, `auth.log.2.gz`, and so on. Always search the rotated and compressed files too, because the initial compromise is often weeks old:

```bash
ls -la /var/log/auth.log*
zgrep "Accepted" /var/log/auth.log*          # searches .gz and plain files alike
zcat /var/log/auth.log.*.gz | cat - /var/log/auth.log.1 /var/log/auth.log | less
```

### Analyzing SSH activity

SSH is the most common entry point on internet-facing Linux servers, so the authentication log is usually where you start.

Successful logins, showing the auth method (password or publickey), user, and source IP:

```bash
grep "Accepted" /var/log/auth.log
# Sep 27 03:41:09 web01 sshd[22301]: Accepted password for deploy from 203.0.113.45 port 53310 ssh2
```

Failed attempts, ranked by source IP. In both the "invalid user" and valid-user variants, the IP is the fourth field from the end:

```bash
grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr | head -20
```

Usernames being tried (a brute-force signature):

```bash
grep "Invalid user" /var/log/auth.log | awk '{print $8}' | sort | uniq -c | sort -nr | head
```

The classic compromise pattern is a flood of failures from one IP followed by an "Accepted" from the same IP. Check it directly:

```bash
IP=203.0.113.45
grep "$IP" /var/log/auth.log | grep -E "Failed|Accepted" | tail -20
```

Session lifecycle, which tells you how long the attacker stayed:

```bash
grep -E "session opened|session closed" /var/log/auth.log
```

Also watch for publickey logins you do not expect, since an attacker who plants a key in `authorized_keys` will show up as `Accepted publickey`, often with a key fingerprint you can match against the planted key:

```bash
grep "Accepted publickey" /var/log/auth.log
ssh-keygen -lf /home/deploy/.ssh/authorized_keys   # compare fingerprints
```

### Privilege escalation and account changes

sudo usage, including the exact command, working directory, and target user:

```bash
grep "sudo:" /var/log/auth.log | grep "COMMAND"
# sudo: deploy : TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash
```

A `PWD=/tmp` or a `COMMAND=/bin/bash` or `/bin/su` from a service account is a red flag. Failed sudo attempts show up as "incorrect password attempts" or "user NOT in sudoers".

su usage:

```bash
grep -E "su:|su\[" /var/log/auth.log
```

Account creation and modification, a common persistence technique:

```bash
grep -E "useradd|usermod|groupadd|passwd|chpasswd|new user|new group" /var/log/auth.log
```

Cross-check against `/etc/passwd`. Watch especially for any account with UID 0 other than root:

```bash
awk -F: '$3 == 0 {print}' /etc/passwd
```

### General system logs

The syslog or messages file captures service starts and stops, crashes, and many application messages. Useful searches include services being stopped (attackers often stop logging or security agents), new services appearing, and segfaults that may indicate exploitation attempts:

```bash
grep -iE "stopped|started|segfault|oom-killer" /var/log/syslog
grep -iE "rsyslog|auditd|falcon|osquery" /var/log/syslog   # tampering with logging/EDR
```

---

## 3. Linux Log File Analysis (Part 2): Binary Login Records, journald, Kernel, Cron, and Packages

### Binary login records: utmp, wtmp, btmp, lastlog

These are not text, so `cat` produces garbage. Use the right tool:

| File | Contents | Reader |
|---|---|---|
| `/var/run/utmp` (or `/run/utmp`) | Currently logged-in users | `who`, `w`, `utmpdump` |
| `/var/log/wtmp` | Historical logins, logouts, reboots, shutdowns | `last`, `utmpdump` |
| `/var/log/btmp` | Failed login attempts | `lastb`, `utmpdump` |
| `/var/log/lastlog` | Last login per user (sparse file indexed by UID) | `lastlog` |

On live systems:

```bash
who -a
w
last -F -i                  # full timestamps, IPs instead of hostnames
last -x                     # include shutdowns and runlevel changes
last reboot
sudo lastb -F -i | head -50
lastlog | grep -v "Never logged in"
```

On a mounted image, point the tools at the evidence copies rather than the analysis machine's own files:

```bash
last -F -i -f /mnt/evidence/var/log/wtmp
lastb -F -i -f /mnt/evidence/var/log/btmp
utmpdump /mnt/evidence/var/log/wtmp > wtmp.txt
```

Tamper detection: tools like `wtmpclean` or crude log wipers either remove records or zero them. `utmpdump` exposes the raw structure, so look for records with null usernames and zeroed timestamps (`1970-01-01`), gaps in the sequence of sessions, reboots without matching shutdowns, or a wtmp file far smaller than its rotation history suggests. Correlate wtmp with `auth.log`. An "Accepted password" in `auth.log` with no matching wtmp entry means one of them has been edited.

Note that newer distributions are moving away from utmp/wtmp (because of the 2038 timestamp problem) toward `wtmpdb` and systemd's own session tracking, so on very recent systems check `wtmpdb last` and the journal.

### systemd-journald

The journal is structured and indexed, and each entry carries trusted fields added by journald itself (prefixed with an underscore, such as `_PID`, `_UID`, `_COMM`, `_EXE`, `_CMDLINE`, `_SYSTEMD_UNIT`, `_BOOT_ID`) that a logging process cannot forge. That makes it richer than syslog for attribution.

Essential journalctl usage:

```bash
journalctl --list-boots                     # boot history with IDs and time ranges
journalctl -b -1                            # previous boot
journalctl --since "2026-09-26 00:00" --until "2026-09-27 06:00"
journalctl -u ssh.service                   # sshd on Debian/Ubuntu (sshd.service on RHEL)
journalctl _COMM=sudo
journalctl _UID=1001                        # everything from one user
journalctl _EXE=/usr/bin/bash
journalctl -k                               # kernel messages only
journalctl -p err..emerg                    # errors and worse
journalctl -o verbose                       # every field, including trusted ones
journalctl -o json-pretty > journal.json    # export for tooling
journalctl -o short-iso-precise             # timestamps with year, zone, microseconds
```

For offline analysis of an image, never use the analysis host's own journal:

```bash
journalctl --directory=/mnt/evidence/var/log/journal/ --since "2026-09-26"
journalctl --file=/mnt/evidence/var/log/journal/<machine-id>/system.journal
journalctl --directory=/mnt/evidence/var/log/journal/ --verify
```

`--verify` checks internal consistency, and if Forward Secure Sealing (`journalctl --setup-keys`) was configured beforehand, it can cryptographically prove whether entries were altered. Corrupted journal files (`system.journal~`) often appear after crashes but also after tampering, so note them. Also check `/etc/systemd/journald.conf`: `Storage=volatile` or `Storage=none` means persistent evidence was never kept, and a suspicious recent change there is itself evidence.

Attackers sometimes run `journalctl --vacuum-time=1s` or `--rotate` followed by vacuuming to wipe the journal. Look for that in shell history, and look for the journal's earliest entry being suspiciously recent.

### Kernel logs

`dmesg`, `/var/log/kern.log`, and `journalctl -k` show kernel events. Forensically valuable entries include USB device connections (vendor, product, and serial number, useful in insider or data theft cases), kernel module loads (rootkits are often loadable kernel modules), taint warnings, and exploit side effects:

```bash
grep -iE "usb|new high-speed|SerialNumber|Product:" /var/log/kern.log
grep -iE "taint|module verification failed|loading out-of-tree" /var/log/kern.log
journalctl -k | grep -iE "segfault|general protection|BUG:"
```

"module verification failed: signature and/or required key missing - tainting kernel" is a strong indicator that an unsigned, possibly malicious module was loaded.

### Cron logs

Cron is one of the most common persistence and cryptominer launch mechanisms:

```bash
grep CRON /var/log/syslog          # Debian/Ubuntu
cat /var/log/cron                  # RHEL
journalctl -u cron -u crond
```

Look for jobs running from `/tmp`, `/dev/shm`, or hidden directories, jobs that pipe `curl` or `wget` output into `sh`, and jobs running every minute. Cross-check the logs with the actual cron configuration (covered in the acquisition sections).

### Package manager logs

These show what software was installed, removed, or upgraded, and when. Attackers install tools like `nmap`, `masscan`, `socat`, `gcc` (to compile exploits), or remove security tools:

```bash
grep -E " install | remove | purge " /var/log/dpkg.log*
zcat -f /var/log/apt/history.log* | grep -A3 "Start-Date"   # includes the command line and user
cat /var/log/dnf.log /var/log/yum.log 2>/dev/null
rpm -qa --last | head -30          # most recently installed packages (RHEL)
```

`apt/history.log` is especially valuable because it records `Requested-By:` (the user) and the full `Commandline:`.

---

## 4. Linux Log File Analysis (Part 3): auditd, Web Logs, Shell History, Tampering, and Timelines

### The Linux Audit Framework (auditd)

If auditd was running with a good rule set, it is the richest log source on a Linux host, closer to Windows Sysmon than anything else. It logs system calls, file access, command execution, and authentication at the kernel level, in `/var/log/audit/audit.log`.

Rules live in `/etc/audit/rules.d/*.rules` (compiled into `/etc/audit/audit.rules`). Check what was being monitored:

```bash
cat /etc/audit/rules.d/*.rules
auditctl -l          # live system: currently loaded rules
```

Typical rules you will see or want to deploy:

```
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k privesc
-w /root/.ssh/ -p wa -k root_ssh
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b64 -S init_module,finit_module,delete_module -k modules
```

`-w` watches a path, `-p wa` means on write or attribute change, and `-k` attaches a searchable key. Community baselines such as the Neo23x0 or Florian Roth auditd rules are common starting points.

Raw audit.log is hard to read. A single event spans several records (SYSCALL, EXECVE, CWD, PATH, PROCTITLE) sharing an event ID like `msg=audit(1727407422.123:4567)`, with a Unix epoch timestamp. The `auid` field (audit UID, or "login UID") is critical: it survives `sudo` and `su`, so even when a command runs as root, auid tells you which user originally logged in. Values are often hex-encoded (the PROCTITLE field especially). Let the tools decode everything:

```bash
ausearch -k identity -i                         # -i interprets UIDs, syscalls, hex
ausearch -m EXECVE -ts 09/26/2026 00:00:00 -te 09/27/2026 06:00:00 -i
ausearch -ua 1001 -i                            # everything by auid/uid 1001
ausearch -x /usr/bin/wget -i                    # executions of a specific binary
ausearch -m USER_LOGIN,USER_AUTH --success no -i
aureport --summary
aureport --auth -i                              # authentication report
aureport --login --failed -i
aureport -x --summary                           # executables ranked by count
aureport -m                                     # account modifications
aureport --anomaly
```

For an offline image: `ausearch -if /mnt/evidence/var/log/audit/audit.log -k exec -i`.

Signs of audit tampering include `auditctl -D` (delete all rules) or `auditctl -e 0` (disable auditing) in history, CONFIG_CHANGE records, DAEMON_END records, or auditd simply stopping in the journal. If rules were made immutable with `-e 2`, changing them requires a reboot, which leaves its own trace.

### Web server logs

Web applications are the other main entry point. Apache logs are typically in `/var/log/apache2/` (Debian) or `/var/log/httpd/` (RHEL), and Nginx in `/var/log/nginx/`. The combined log format is:

```
203.0.113.45 - - [27/Sep/2026:03:10:02 +0000] "POST /wp-content/uploads/2026/09/img.php HTTP/1.1" 200 312 "-" "curl/8.5.0"
```

That gives client IP, identity, authenticated user, timestamp (with time zone), request line, status code, response size, referrer, and user agent.

Useful triage:

```bash
LOG=/var/log/apache2/access.log
awk '{print $1}' $LOG | sort | uniq -c | sort -nr | head            # top talkers
awk '{print $9}' $LOG | sort | uniq -c | sort -nr                   # status code distribution
awk -F'"' '{print $6}' $LOG | sort | uniq -c | sort -nr | head      # user agents
grep -E "sqlmap|nikto|nmap|gobuster|dirbuster|wpscan|nuclei|masscan" -i $LOG
```

Attack pattern searches:

```bash
grep -iE "union(\s|%20|\+)+select|information_schema|sleep\(|benchmark\(" $LOG   # SQL injection
grep -E "\.\./|%2e%2e|/etc/passwd|php://|file://" $LOG                           # traversal / LFI
grep -iE "cmd=|exec=|system\(|passthru|shell_exec|base64_decode|eval\(" $LOG      # command injection / shells
grep -E "\\$\{jndi:" $LOG                                                        # Log4Shell-style
grep "POST" $LOG | grep -E "/uploads/|/tmp/|/images/" | grep "\.php"             # possible web shell hits
```

Web shells tend to show up as a rarely accessed script that suddenly receives many POST requests with a 200 status from one IP, often in an upload directory. Once you find it, pivot three ways: find the file on disk and check its timestamps, find the first request to it (usually just after an upload request, which reveals the vulnerability used), and check the error log (`error.log`) for PHP warnings that leak the commands being run.

Find recently modified scripts in the web root:

```bash
find /var/www -name "*.php" -newermt "2026-09-20" -ls
grep -rlE "eval\(|base64_decode\(|assert\(|gzinflate\(|str_rot13\(" /var/www
```

Note that web logs record only the URL and query string, not POST bodies, so the actual commands sent to a shell are often invisible in the access log. Memory, process accounting, or auditd execve records (showing `www-data` spawning `sh`) fill that gap.

### Shell history

Shell history is technically a user artifact rather than a log, but it is often the single most revealing file:

```bash
cat /home/*/.bash_history /root/.bash_history
cat /home/*/.zsh_history /home/*/.local/share/fish/fish_history 2>/dev/null
cat /home/*/.python_history /home/*/.mysql_history /home/*/.psql_history /home/*/.viminfo /home/*/.lesshst 2>/dev/null
```

Limitations to understand: bash writes history only when the shell exits cleanly (so a killed session may leave nothing), there are no timestamps unless `HISTTIMEFORMAT` was set (in which case lines starting with `#` followed by an epoch precede each command), and the current session's history lives only in memory (Volatility's `linux.bash` plugin can recover it from a memory image).

Anti-forensics indicators in or around history files: `unset HISTFILE`, `export HISTFILE=/dev/null`, `HISTSIZE=0`, `history -c`, `set +o history`, a `.bash_history` that is a symlink to `/dev/null` (`ls -la` shows this), an empty history for an account that clearly logged in, a command preceded by a space (ignored if `HISTCONTROL=ignorespace`), and commands like `shred`, `wipe`, `rm -rf /var/log/*`, or `> /var/log/auth.log`.

### Detecting log tampering

Attackers delete, truncate, or selectively edit logs. Things to check:

1. Time gaps. A server that logs every few minutes but has a four-hour silence is suspicious. A quick way to see gaps is to count lines per hour:
   ```bash
   awk '{print $1, $2, substr($3,1,2)}' /var/log/auth.log | uniq -c
   ```
2. Size and timestamp anomalies: a zero-byte `auth.log` with an old rotated file beside it, or a log whose mtime is older than its latest entry should allow.
3. Cross-source inconsistencies. The same event often appears in several places: an SSH login lands in `auth.log`, wtmp, the journal, auditd, and possibly lastlog. Attackers rarely clean all of them.
4. Remote copies from a log server or SIEM, which the attacker usually cannot reach.
5. Deleted log content can often be carved from unallocated space, because text logs are easy to find with keyword searches (for example, `grep -a` on the raw image, or bulk_extractor, or Autopsy keyword search).
6. Journal verification and wtmp null-record inspection, as described above.

### Building a timeline

Individual logs tell fragments; a timeline tells the story. Normalize everything to UTC first. Classic syslog timestamps lack a year and zone, so confirm the host's configured time zone (`/etc/timezone`, `/etc/localtime`, `timedatectl`) and year from context.

Plaso automates parsing of dozens of Linux sources (syslog, auth, wtmp/utmp, journal, bash history with timestamps, apt/dpkg, Apache, Docker, filesystem metadata) into one super-timeline:

```bash
log2timeline.py --storage-file case.plaso /mnt/evidence/        # or the image file directly
psort.py -o l2tcsv -w timeline.csv case.plaso "date > '2026-09-25 00:00:00' AND date < '2026-09-28 00:00:00'"
```

Load the result into Timeline Explorer, Timesketch, or a spreadsheet, then filter around your known-bad pivot points (the first successful attacker login, the web shell upload, the malware file's birth time).

Also check other logs worth collecting: Docker and container logs (`/var/lib/docker/containers/*/*-json.log`), database logs, VPN logs, `/var/log/wtmp` for reboots, `/var/log/sa/` (sysstat, which shows CPU spikes consistent with cryptomining), and cloud provider logs (AWS CloudTrail, VPC Flow Logs, GCP and Azure audit logs), which live outside the host entirely.

---

## 5. Linux Evidence Acquisition with Commands (Part 1): Live Response and Memory

### Preparing for live response

Before touching the suspect machine, prepare a USB drive or network share containing statically compiled trusted binaries (busybox, or tools from a clean system with the same architecture), because an attacker with root may have replaced `ps`, `ls`, `netstat`, or `ss` with trojaned versions, or loaded a rootkit that hides processes and files. Write every output to external media or send it over the network, never to the suspect disk. Record the start time and your actions.

A common convention:

```bash
mkdir -p /mnt/usb/case01 && cd /mnt/usb/case01
script -a -t 2>timing.log session.log      # records everything you type and see
export PATH=/mnt/usb/bin:$PATH             # prefer trusted binaries
```

Run each command, save output, and hash it:

```bash
run() { echo "### $* ($(date -u +%FT%TZ))" | tee -a collection.log; "$@" 2>&1 | tee "$1_$(date +%s).txt"; }
sha256sum *.txt > hashes.sha256
```

Alternatively, use a proven collector. UAC (Unix-like Artifacts Collector) is widely used, supports Linux, macOS, BSD, Solaris, AIX, and ESXi, and collects volatile data, logs, configuration, user artifacts, and hash lists according to profiles:

```bash
./uac -p ir_triage /mnt/usb/case01
./uac -a memory_dump/avml,live_response/*,logs/* /mnt/usb/case01   # custom artifact selection
```

### Step 1: Capture memory first

Memory holds running malware (including fileless and deleted binaries), decrypted data, encryption keys, command history of open shells, network connections, and injected code. Capture it before anything else that would disturb it.

AVML (Acquire Volatile Memory for Linux, from Microsoft) is a single static binary that works without kernel headers or compilation, making it the easiest option:

```bash
sudo /mnt/usb/avml /mnt/usb/case01/memory.lime
sudo /mnt/usb/avml --compress /mnt/usb/case01/memory.lime.compressed
sha256sum /mnt/usb/case01/memory.lime > /mnt/usb/case01/memory.sha256
```

LiME (Linux Memory Extractor) is a loadable kernel module and the traditional choice. It must be compiled against the exact kernel version of the target. Compile it on a clean machine running the same kernel and distribution rather than on the suspect host, because installing compilers and headers there destroys evidence:

```bash
# On a matching clean build machine:
git clone https://github.com/504ensicsLabs/LiME && cd LiME/src && make
# produces lime-<kernel-version>.ko

# On the target:
sudo insmod /mnt/usb/lime-$(uname -r).ko "path=/mnt/usb/case01/memory.lime format=lime"
sudo rmmod lime

# Or stream over the network to avoid writing locally:
sudo insmod lime.ko "path=tcp:4444 format=lime"
# on the analyst machine:
nc <target-ip> 4444 > memory.lime
```

Secure Boot with kernel lockdown can block unsigned modules, in which case AVML (which reads through `/dev/crash`, `/proc/kcore`, or `/dev/mem`, depending on what is available) may be your only option.

For virtual machines, you can often snapshot the VM from the hypervisor with memory included (VMware `.vmem`, KVM `virsh dump --memory-only`), which avoids running anything inside the guest at all. For cloud instances, check the provider's options; some support memory capture through their tooling, otherwise use AVML.

### Analyzing Linux memory with Volatility 3

Volatility 3 needs a symbol table (ISF JSON) matching the exact kernel. You build it with `dwarf2json` from the kernel's debug symbols (the `vmlinux` with DWARF info, from packages like `linux-image-*-dbgsym` on Ubuntu or `kernel-debuginfo` on RHEL), then place it in `volatility3/symbols/linux/`:

```bash
./dwarf2json linux --elf /usr/lib/debug/boot/vmlinux-6.8.0-45-generic > ubuntu-6.8.0-45.json
```

Useful plugins:

```bash
vol -f memory.lime banners.Banners            # identify the exact kernel to find symbols
vol -f memory.lime linux.pslist
vol -f memory.lime linux.pstree
vol -f memory.lime linux.psaux                # full command lines
vol -f memory.lime linux.bash                 # bash history recovered from process memory
vol -f memory.lime linux.lsof
vol -f memory.lime linux.sockstat             # network sockets (recent Volatility 3 versions)
vol -f memory.lime linux.lsmod
vol -f memory.lime linux.hidden_modules       # modules unlinked from the module list
vol -f memory.lime linux.check_syscall        # hooked syscall table entries (rootkits)
vol -f memory.lime linux.check_modules
vol -f memory.lime linux.malfind              # suspicious executable memory regions
vol -f memory.lime linux.elfs --pid 1337 --dump
vol -f memory.lime linux.envars
```

Compare `pslist` with what `ps` reported during live response. Processes visible in memory but missing from `ps` suggest a userland or kernel rootkit.

### Step 2: System identity and time

```bash
date -u; date                     # UTC and local; note the offset
timedatectl                       # time zone and NTP sync status
hostname; hostnamectl
uname -a
cat /etc/os-release
uptime                            # how long since boot (a recent reboot may have wiped volatile evidence)
cat /proc/cmdline                 # kernel boot parameters
```

Record the difference between system time and a reliable clock, because every log timestamp depends on it.

### Step 3: Users and sessions

```bash
w
who -a
last -F -i | head -50
id; sudo -l 2>/dev/null
cat /etc/passwd /etc/group
sudo cat /etc/shadow              # password change dates (field 3), locked accounts
```

### Step 4: Processes

```bash
ps auxwwf                         # full command lines as a tree
ps -eo pid,ppid,user,lstart,etime,cmd --sort=start_time    # exact start times
pstree -alp
top -b -n 1                       # snapshot of CPU usage (cryptominers stand out)
```

The `/proc` filesystem gives ground truth for each process, and it survives even if `ps` has been trojaned (though not if a kernel rootkit is filtering `/proc`):

```bash
ls -la /proc/<PID>/exe            # real path of the binary
cat /proc/<PID>/cmdline | tr '\0' ' '
cat /proc/<PID>/environ | tr '\0' '\n'
ls -la /proc/<PID>/cwd            # working directory
ls -la /proc/<PID>/fd             # open file descriptors
cat /proc/<PID>/maps              # loaded libraries and memory regions
cat /proc/<PID>/status
```

A crucial technique: malware often deletes its own binary after launching. The kernel keeps the file alive while the process runs, and you can recover it:

```bash
ls -la /proc/*/exe 2>/dev/null | grep deleted
# lrwxrwxrwx 1 root root 0 Sep 27 03:45 /proc/4821/exe -> /tmp/.x/kworkerd (deleted)
cp /proc/4821/exe /mnt/usb/case01/recovered_4821.bin
sha256sum /mnt/usb/case01/recovered_4821.bin
```

Also watch for processes masquerading as kernel threads. Real kernel threads have names in square brackets and no executable (`/proc/<PID>/exe` is empty), are children of `kthreadd` (PID 2), and have no command line. A "kworker" with a real executable in `/tmp` is malware.

A quick check for hidden processes compares PIDs present in `/proc` against what `ps` shows:

```bash
ps -eo pid --no-headers | sort -n > ps_pids.txt
ls /proc | grep -E '^[0-9]+$' | sort -n > proc_pids.txt
diff ps_pids.txt proc_pids.txt
```

(Short-lived processes cause some noise; persistent differences matter.)

### Step 5: Network state

```bash
ss -tulpan                        # listening and established TCP/UDP with owning process
ss -tanp state established
netstat -antup 2>/dev/null        # older systems
lsof -i -n -P                     # network files by process
ip addr; ip route; ip neigh       # interfaces, routes, ARP cache
cat /etc/resolv.conf /etc/hosts   # DNS hijacking or blocking of security vendors
iptables-save; nft list ruleset   # firewall rules (attackers open ports or block EDR telemetry)
cat /proc/net/tcp /proc/net/tcp6  # raw kernel view (hex IP:port), useful if tools are trojaned
```

Look for connections to unusual ports (4444, 1337, mining pool ports like 3333 and 14444), unexpected listeners, interfaces in promiscuous mode (`ip link` shows `PROMISC`, indicating sniffing), and processes with network sockets that should not have any.

### Step 6: Open files, modules, and mounts

```bash
lsof -n -P > lsof.txt
lsof +L1                          # open files with link count 0 (deleted but open)
lsmod; cat /proc/modules
cat /proc/mounts; df -h; findmnt
cat /etc/ld.so.preload 2>/dev/null   # userland rootkit hook: should normally not exist
```

For any unfamiliar module, check `modinfo <module>` and whether it is signed. A module that `lsmod` does not show but memory analysis finds indicates a rootkit that has hidden itself.

### Step 7: Quick persistence snapshot while live

```bash
crontab -l; sudo ls -la /var/spool/cron/crontabs/ /var/spool/cron/ 2>/dev/null
ls -la /etc/cron.* /etc/crontab
systemctl list-units --type=service --all
systemctl list-timers --all
ls -la /etc/systemd/system/ /usr/lib/systemd/system/ | sort -k6,7
```

This part is often done in more depth on the disk image, which Part 2 covers.

---

## 6. Linux Evidence Acquisition with Commands (Part 2): Disk Imaging, Mounting, and Artifact Collection

### Identifying the storage

```bash
lsblk -f                          # tree of disks, partitions, filesystems, mount points
sudo fdisk -l
sudo blkid
sudo parted -l
sudo hdparm -I /dev/sdb           # model, serial number, HPA/DCO features
sudo smartctl -a /dev/sdb         # health and serial (for documentation)
```

Document the model and serial number of every physical drive. Check for a Host Protected Area (HPA) or Device Configuration Overlay (DCO), which hide sectors from the operating system; `hdparm -N /dev/sdb` shows whether the visible max sector differs from the native max.

If you are acquiring an attached suspect disk on your forensic workstation, use a hardware write blocker whenever possible. At minimum, prevent auto-mounting and set the device read-only:

```bash
sudo blockdev --setro /dev/sdb
sudo blockdev --getro /dev/sdb    # 1 = read-only
```

(Software read-only settings are a reasonable safeguard but are not a substitute for a hardware blocker in cases likely to go to court.)

### Imaging with dd

`dd` is universal but has no built-in hashing or logging:

```bash
sudo dd if=/dev/sdb of=/evidence/case01/sdb.dd bs=4M conv=noerror,sync status=progress
sudo sha256sum /dev/sdb /evidence/case01/sdb.dd
```

`conv=noerror,sync` continues past read errors and pads unreadable blocks with zeros so offsets stay correct. With a large block size, one bad sector can blank out 4 MB, so for damaged media use `ddrescue` instead.

### Forensic dd variants

`dcfldd` (from the US DoD Computer Forensics Lab) adds on-the-fly hashing, piecewise hashing, and split output:

```bash
sudo dcfldd if=/dev/sdb of=/evidence/case01/sdb.dd hash=sha256,md5 \
  hashlog=/evidence/case01/sdb.hashes bs=4M hashwindow=1G
```

`dc3dd` (from the DoD Cyber Crime Center) adds logging, hashing, and verification of the written output:

```bash
sudo dc3dd if=/dev/sdb hof=/evidence/case01/sdb.dd hash=sha256 log=/evidence/case01/sdb.log
```

`hof=` (hash output file) re-reads and hashes the output so you know the image matches the source.

`ddrescue` is for failing drives. It copies the good areas first and retries bad ones later, tracking progress in a map file so you can resume:

```bash
sudo ddrescue -n /dev/sdb /evidence/sdb.img /evidence/sdb.map    # fast pass, skip bad areas
sudo ddrescue -d -r3 /dev/sdb /evidence/sdb.img /evidence/sdb.map # retry bad areas, direct I/O
```

### Expert Witness Format (E01) with ewfacquire

E01 images are compressed, embed case metadata and hashes, and are accepted by essentially every forensic tool:

```bash
sudo ewfacquire -t /evidence/case01/sdb -C "CASE01" -D "Web server disk" \
  -E "EV001" -e "Analyst Name" -N "Seized 2026-09-28" \
  -f encase6 -c fast -d sha256 -S 4GiB -u /dev/sdb
ewfverify /evidence/case01/sdb.E01
ewfinfo /evidence/case01/sdb.E01
```

Guymager is a good GUI alternative on forensic distributions like CAINE, Tsurugi, or Kali, producing raw or E01 images with automatic verification.

### Remote acquisition

For servers you cannot physically reach, stream the disk over the network. Over SSH (encrypted, preferred):

```bash
ssh root@target "dd if=/dev/sda bs=4M status=none" | dd of=/evidence/sda.dd bs=4M
ssh root@target "dd if=/dev/sda bs=4M status=none | gzip -1" | gunzip | tee /evidence/sda.dd | sha256sum
```

Over netcat (unencrypted, only on a trusted network; flag syntax varies between netcat variants):

```bash
# Analyst machine:
nc -l -p 9000 | dd of=/evidence/sda.dd bs=4M
# Target:
dd if=/dev/sda bs=4M | nc <analyst-ip> 9000
```

Hash the source device on the target and the image on your side, and compare. Remember that imaging a live, mounted disk produces a "smeared" image, since the filesystem is changing during the copy. Document that it was a live acquisition.

For cloud and virtualization, snapshotting is usually cleaner: create an EBS snapshot in AWS (or the equivalent in Azure or GCP), create a volume from it, attach it read-only to a forensic instance, and image or analyze it there. For VMware or KVM, copy the `.vmdk` or `.qcow2` from a snapshot, then convert if needed (`qemu-img convert -O raw disk.qcow2 disk.raw`).

### Mounting images read-only for analysis

Always work on a copy of the image, mounted read-only.

First, understand the partition layout:

```bash
mmls /evidence/sdb.dd
# Slot  Start     End        Length     Description
# 002:  0000002048 0001050623 0001048576 Linux filesystem
# 003:  0001050624 0209713151 0208662528 Linux filesystem
```

Mount by calculating the byte offset (start sector × sector size):

```bash
sudo mkdir -p /mnt/evidence
sudo mount -o ro,loop,noexec,nodev,nosuid,noload,offset=$((1050624*512)) /evidence/sdb.dd /mnt/evidence
```

The `noload` option matters for ext3 and ext4. Without it, mounting a filesystem that was not cleanly unmounted replays the journal, which modifies the image even with `ro`. For XFS, use `norecovery` instead. Mounting with `ro` alone is not enough.

Alternatively, let the kernel map partitions for you:

```bash
sudo losetup -r -f -P --show /evidence/sdb.dd     # -r read-only, -P scan partitions; prints /dev/loopN
sudo mount -o ro,noload,noexec /dev/loop0p3 /mnt/evidence
```

For E01 images, expose the raw data first:

```bash
sudo ewfmount /evidence/sdb.E01 /mnt/ewf          # creates /mnt/ewf/ewf1 as a raw view
sudo losetup -r -f -P --show /mnt/ewf/ewf1
```

LVM volumes (very common on RHEL and Ubuntu server installs) need activation:

```bash
sudo losetup -r -f -P --show /evidence/sdb.dd
sudo pvscan; sudo vgscan; sudo lvscan
sudo vgchange -ay <vgname>
sudo mount -o ro,noload,noexec /dev/<vgname>/root /mnt/evidence
```

If the suspect's volume group has the same name as your workstation's (both called `ubuntu-vg`, for example), rename it or use `vgimportclone` to avoid collisions.

LUKS-encrypted volumes need the passphrase or key (or a key recovered from memory):

```bash
sudo cryptsetup luksDump /dev/loop0p3             # header metadata, key slots
sudo cryptsetup open --readonly /dev/loop0p3 evidence_crypt
sudo mount -o ro,noload,noexec /dev/mapper/evidence_crypt /mnt/evidence
```

This is another strong reason to capture memory on a running system: if the volume is unlocked, the master key is in RAM, and it may be the only way in afterward.

### Filesystem-level analysis with The Sleuth Kit

TSK works directly on the image without mounting, and it sees deleted entries:

```bash
fsstat -o 1050624 sdb.dd                    # filesystem details: type, last mount time, last mount point
fls -r -o 1050624 sdb.dd                    # recursive listing including deleted (marked with *)
fls -r -d -o 1050624 sdb.dd                 # deleted entries only
fls -o 1050624 sdb.dd -r | grep -i "\.sh$"
istat -o 1050624 sdb.dd 1318922             # full inode metadata including all timestamps
icat -o 1050624 sdb.dd 1318922 > recovered_file
ffind -o 1050624 sdb.dd 1318922             # inode number to filename
ifind -o 1050624 -n /tmp/.x/payload sdb.dd  # filename to inode
```

Filesystem timeline with fls and mactime:

```bash
fls -r -m / -o 1050624 sdb.dd > body.txt
mactime -b body.txt -d -y -z UTC 2026-09-20..2026-09-28 > fs_timeline.csv
```

Deleted-file recovery on ext4:

```bash
extundelete /evidence/partition.img --restore-all          # uses the journal
ext4magic /evidence/partition.img -a $(date -d "-3 day" +%s) -r -d /evidence/recovered
photorec /evidence/sdb.dd                                   # signature-based carving
foremost -i /evidence/sdb.dd -o /evidence/carved
bulk_extractor -o /evidence/be_out /evidence/sdb.dd         # emails, URLs, IPs, etc. from raw data
```

For deleted logs, a raw keyword search on the image often works well because text is easy to spot:

```bash
grep -a -b "Accepted password" /evidence/sdb.dd | head      # -b gives byte offsets for context
strings -a -t d /evidence/sdb.dd | grep "203.0.113.45"
```

### Collecting key artifacts from the mounted image

With the image mounted at `/mnt/evidence`, systematically examine the following.

Accounts and privileges:

```bash
cat /mnt/evidence/etc/passwd
awk -F: '$3==0' /mnt/evidence/etc/passwd                       # UID 0 accounts
awk -F: '$7 !~ /nologin|false/' /mnt/evidence/etc/passwd       # accounts with login shells
cat /mnt/evidence/etc/shadow                                   # field 3 = days since epoch of last change
cat /mnt/evidence/etc/group | grep -E "sudo|wheel|adm|docker"
cat /mnt/evidence/etc/sudoers; ls -la /mnt/evidence/etc/sudoers.d/
```

Membership in the `docker` group is effectively root access and is worth flagging.

SSH:

```bash
find /mnt/evidence -name authorized_keys -o -name authorized_keys2 2>/dev/null | xargs ls -la
cat /mnt/evidence/etc/ssh/sshd_config | grep -vE "^#|^$"      # PermitRootLogin, AuthorizedKeysFile changes
ls -la /mnt/evidence/home/*/.ssh/ /mnt/evidence/root/.ssh/
cat /mnt/evidence/home/*/.ssh/known_hosts                      # where users SSH'd to (lateral movement)
```

Persistence mechanisms (the main places to look):

```bash
# Cron
cat /mnt/evidence/etc/crontab
ls -la /mnt/evidence/etc/cron.d /mnt/evidence/etc/cron.{hourly,daily,weekly,monthly}
ls -la /mnt/evidence/var/spool/cron/ /mnt/evidence/var/spool/cron/crontabs/
# at jobs
ls -la /mnt/evidence/var/spool/at* 2>/dev/null
# systemd services and timers, sorted by modification time
find /mnt/evidence/etc/systemd /mnt/evidence/lib/systemd /mnt/evidence/usr/lib/systemd \
  /mnt/evidence/home/*/.config/systemd -type f -printf '%TY-%Tm-%Td %TT %p\n' 2>/dev/null | sort | tail -40
grep -r "ExecStart" /mnt/evidence/etc/systemd/system/
# Legacy init
cat /mnt/evidence/etc/rc.local 2>/dev/null; ls -la /mnt/evidence/etc/init.d/
# Shell startup files
cat /mnt/evidence/etc/profile /mnt/evidence/etc/bash.bashrc; ls -la /mnt/evidence/etc/profile.d/
cat /mnt/evidence/home/*/.bashrc /mnt/evidence/home/*/.profile /mnt/evidence/root/.bashrc
# Preload / library hijacking
cat /mnt/evidence/etc/ld.so.preload 2>/dev/null
cat /mnt/evidence/etc/ld.so.conf.d/*
# PAM backdoors (malicious pam_*.so modules accepting a magic password)
ls -la --time-style=full-iso /mnt/evidence/lib/x86_64-linux-gnu/security/ /mnt/evidence/usr/lib64/security/ 2>/dev/null
grep -r "pam_" /mnt/evidence/etc/pam.d/ | grep -vE "^#"
# Kernel module autoload
ls -la /mnt/evidence/etc/modules-load.d/; cat /mnt/evidence/etc/modules 2>/dev/null
# Other: udev rules, MOTD scripts, git hooks, apt hooks
ls -la /mnt/evidence/etc/udev/rules.d/ /mnt/evidence/etc/update-motd.d/ /mnt/evidence/etc/apt/apt.conf.d/
```

Suspicious files and locations:

```bash
ls -laR /mnt/evidence/tmp /mnt/evidence/var/tmp /mnt/evidence/dev/shm 2>/dev/null
find /mnt/evidence -name ".*" -type d -not -path "*/proc/*" 2>/dev/null | grep -vE "\.cache|\.config|\.local|\.ssh|\.git"
find /mnt/evidence -name "... " -o -name ".. " 2>/dev/null           # dot-space tricks
find /mnt/evidence -perm -4000 -type f -ls 2>/dev/null               # SUID binaries: compare to a clean baseline
find /mnt/evidence -perm -2000 -type f -ls 2>/dev/null               # SGID
getcap -r /mnt/evidence 2>/dev/null                                  # file capabilities (e.g., cap_setuid on python)
find /mnt/evidence -newermt "2026-09-25" ! -newermt "2026-09-28" -type f -ls 2>/dev/null
find /mnt/evidence/usr/bin /mnt/evidence/usr/sbin /mnt/evidence/bin -newermt "2026-09-01" -ls
find /mnt/evidence -type f -size +10M -path "*/tmp/*" 2>/dev/null
```

Binary integrity against the package database (detects trojaned system binaries):

```bash
# Debian/Ubuntu, on the mounted image:
sudo debsums -r /mnt/evidence -c 2>/dev/null     # or chroot, with care
# RHEL:
sudo rpm --root=/mnt/evidence -Va | grep -E "^..5"   # '5' in column 3 = checksum mismatch
```

Hashing and scanning:

```bash
find /mnt/evidence/tmp /mnt/evidence/dev/shm /mnt/evidence/var/www -type f -exec sha256sum {} \; > suspicious_hashes.txt
yara -r rules/linux_malware.yar /mnt/evidence/ 2>/dev/null
```

Submit hashes (not files, if confidentiality matters) to threat intelligence services.

Other user artifacts: `.viminfo` (files edited and search strings), `.lesshst`, `.wget-hsts` (hosts contacted by wget), `.local/share/recently-used.xbel` (desktop file access), browser profiles under `.mozilla` and `.config/google-chrome`, `.local/share/Trash`, and `.gnupg`.

Containers: `/var/lib/docker/` holds images, container filesystems (`overlay2`), and container configuration (`containers/*/config.v2.json`). An attacker may have launched a privileged container mounting the host root filesystem, which appears in `docker ps -a` output, the container configuration, and Docker logs.

Finally, hash everything you exported and document the full collection.

---

## 7. Linux Evidence Acquisition with Autopsy

Autopsy is the open-source graphical front end for The Sleuth Kit, maintained by Basis Technology (Sleuth Kit Labs). It is free, widely used in training and in real casework, and it handles Linux images well, although many of its automated artifact parsers were built with Windows in mind. There are two generations you may encounter.

### Autopsy 2 (legacy web interface)

This is the version preinstalled on Kali and other forensic distributions as the `autopsy` command. It runs as a small local web server:

```bash
sudo autopsy
# then browse to http://localhost:9999/autopsy
```

The workflow is: click New Case and enter the case name, description, and investigators; add a host (name, time zone, clock skew adjustment, optional known-good and known-bad hash databases); then add an image by giving the path to the raw image and choosing whether Autopsy should symlink, copy, or move it into the evidence locker. It detects partitions and lets you choose which to analyze and whether to calculate or verify an MD5 hash.

Analysis modes in Autopsy 2 map directly onto TSK tools. File Analysis browses directories (deleted files shown in red) and shows file content, metadata, and hex. Keyword Search runs string or grep-style regex searches across the image, including unallocated space, which is useful for finding deleted log lines. File Type sorts files by signature and flags extension mismatches. Image Details shows filesystem details (the `fsstat` equivalent). Meta Data browses by inode (`istat`), and Data Unit browses raw blocks (`blkcat`). Timeline creation builds a body file and then a MAC timeline, just like `fls -m` plus `mactime`. There are also notes and an event sequencer for building the narrative.

Autopsy 2 is dated and single-threaded, so for serious work use Autopsy 4, but it is lightweight and still perfectly adequate for learning or quick analysis on a Kali box.

### Autopsy 4 (modern desktop application)

Autopsy 4 is a Java desktop application, native on Windows, and supported on Linux and macOS with some setup. The usual Linux installation involves installing a Java runtime that includes JavaFX (Basis recommends a specific build, historically BellSoft Liberica JDK), installing the Sleuth Kit Java bindings package (`sleuthkit-java_<version>_amd64.deb`), downloading the Autopsy zip, and running its `unix_setup.sh` script with `JAVA_HOME` set, then launching `bin/autopsy`. Some distributions and the Snap store also offer packages. Since the exact steps change between releases, follow the Linux/macOS instructions in the release notes for the version you download. Many examiners simply run Autopsy on a Windows forensic workstation and analyze Linux images there, which works well because TSK reads ext-family filesystems regardless of the host operating system.

#### Step 1: Create a case

Choose New Case, then set the case name and base directory (put it on a large, fast drive that is not the evidence drive), choose single-user or multi-user (multi-user needs PostgreSQL and Solr servers), and enter case number and examiner details. These appear in reports.

#### Step 2: Add a data source

The Add Data Source wizard offers several source types. A disk image or VM file supports raw (`.dd`, `.img`, `.raw`, split raw), E01/Ex01, VMDK, VHD, and others; this is the normal choice for a Linux investigation. A local disk option acquires or analyzes a physically attached drive (use a write blocker), and on the Windows version it can also create a VHD copy while processing. Logical files let you add a folder, such as a UAC collection or copied `/var/log`, which is handy when you only have triage data. There is also an unallocated space image file option and the option to import XRY or Cellebrite phone extractions (not relevant here).

For a disk image, set the time zone to the suspect system's time zone (or UTC and convert consistently; either way, document it), and provide the expected hash if you have one so Autopsy's Data Source Integrity module can verify the image.

Filesystem support comes from TSK: ext2/3/4, FAT, NTFS, HFS+, APFS, ISO 9660, and UFS are well supported. XFS and Btrfs support has been added in recent TSK releases but is newer and less mature, and LVM support is also relatively recent. If Autopsy does not see the filesystem inside an LVM or LUKS container, handle that layer yourself first (activate the volume group or unlock LUKS as shown in Part 2), then image the resulting logical volume (`dd if=/dev/mapper/vg-root of=root_lv.dd`) and add that as the data source.

#### Step 3: Choose ingest modules

Ingest modules run automatically in the background after adding the source. The relevant ones for Linux:

| Module | Linux relevance |
|---|---|
| Data Source Integrity | Verifies the image hash. Always enable. |
| Hash Lookup | Flags known-bad files against hash sets you import (malware hashes, your IOCs) and hides known-good ones (NSRL) to cut noise. |
| File Type Identification | Signature-based typing, which reveals an ELF binary named `.jpg` or a script named `kworker`. |
| Extension Mismatch Detector | Flags files whose extension does not match content. |
| Keyword Search | Indexes text with Solr so you can search everything, including unallocated space and slack. Built-in lists cover IPs, emails, URLs, phone numbers, and credit cards; add your own lists (attacker IPs, usernames, domains, web shell function names such as `base64_decode`, `eval(`, `shell_exec`). |
| Interesting Files Identifier | Rule-based flagging. Create a Linux rule set, for example: any file in `/tmp`, `/var/tmp`, or `/dev/shm`; any file named `authorized_keys`, `.bash_history`, `ld.so.preload`, or `crontab`; any `.php` file under `/var/www` containing uploads in the path; any ELF file in a home directory. |
| Embedded File Extractor | Opens archives (zip, tar, gz, 7z) so their contents get indexed, which catches attacker toolkits dropped as tarballs. |
| PhotoRec Carver | Carves files from unallocated space, important on ext4 where deleted inodes lose their pointers. |
| Encryption Detection | Flags high-entropy files and encrypted containers (possible ransomware output, encrypted exfiltration archives, or packed malware). |
| Picture Analyzer (EXIF) and Email Parser (mbox) | Useful for user-focused cases. |
| Recent Activity | Largely Windows-oriented (registry, prefetch, event logs), but it does parse browser history (Firefox, Chrome) from Linux home directories. |
| Plaso | Runs log2timeline in the background and imports its events into Autopsy's timeline, which brings Linux syslog, auth, wtmp, journal, and other log events into the GUI timeline. It is slow on large images, so enable it deliberately. |
| YARA Analyzer | Available in recent versions; runs your YARA rules against files. |

Because the automated parsers are Windows-centric, expect to do much of the Linux artifact review manually in the file tree, which is why custom keyword lists and Interesting Files rules make such a difference.

#### Step 4: Analyze

The main window has a tree on the left, a result table in the top right, and a content viewer (hex, text, application, file metadata, results) in the bottom right.

Data Sources shows the file tree. Navigate straight to the Linux artifacts from the earlier sections: `/var/log` (select `auth.log` or `secure` and read it in the text viewer; compressed rotated logs are opened by the Embedded File Extractor), `/home/*/.bash_history`, `/root/.bash_history`, `/home/*/.ssh/authorized_keys`, `/etc/passwd`, `/etc/shadow`, `/etc/crontab`, `/var/spool/cron`, `/etc/systemd/system`, `/tmp`, `/dev/shm` (usually empty on disk since it is RAM-backed), and `/var/www`. Deleted files appear with a red X icon. The File Metadata tab shows the inode, all four timestamps, owner, and permissions (the `istat` output).

Views groups files by type, extension, MIME type, size, and deleted status, and includes a recently modified files view. Filtering by the executable MIME type (`application/x-executable`, `application/x-sharedlib`) quickly surfaces ELF binaries in odd places.

Results collects everything the ingest modules found: hash hits, keyword hits, interesting items, extension mismatches, encryption suspects, and web history. Keyword hits on your IOC list (attacker IP in `auth.log`, in a deleted log fragment in unallocated space, and in a web log) quickly tie the story together.

Keyword search at the top right runs ad hoc exact, substring, or regex searches. A regex like `Accepted (password|publickey) for \S+ from 203\.0\.113\.45` finds successful attacker logins even in carved or unallocated data.

Timeline (Tools, then Timeline) provides an interactive histogram of filesystem events (and Plaso events if enabled). You can zoom to the incident window, filter by file type or path, and see clustered activity: a burst of file creations in `/tmp`, followed by changes in `/etc/systemd/system` and a modified `.bashrc`, a few minutes after the first successful login, is a very clear picture. Its details view lists individual events, and you can tag them.

Tagging lets you tag files and results as notable, follow-up, or custom tags (for example, "Initial Access," "Persistence," "Exfiltration") and add comments. Tags drive the report and keep the analysis organized.

The hex and strings viewers let you examine suspicious binaries without executing them, revealing embedded IPs, URLs, mining pool addresses, and tool names. Extract files (right-click, Extract File) for deeper analysis in a sandbox, with Ghidra, or with `readelf` and `strings`, and hash them.

#### Step 5: Report

Generate Report supports HTML, Excel, a portable case (a self-contained Autopsy case with just the tagged items, which you can hand to another examiner), a tagged-files export, KML (geolocation), and STIX-related output. A typical approach is to report only tagged items, alongside a written narrative built from your timeline.

### A worked example: SSH brute force to cryptominer

Putting the pieces together, a realistic investigation might run like this. An alert reports high CPU on a web server. During live response you capture memory with AVML, then find in `ps` a process called `[kworkerd]` using 390% CPU, whose `/proc/<PID>/exe` points to `/tmp/.X11-unix/.x/kworkerd (deleted)`; you copy the binary out through `/proc`. `ss -tanp` shows it connected to a known mining pool on port 3333. You snapshot the VM disk and image it to E01.

In the logs, `auth.log` shows 14,000 failed passwords from one IP over two hours, then `Accepted password for deploy` from the same IP. wtmp confirms the session. auditd execve records (with auid of the `deploy` user) show `wget` fetching a tarball into `/tmp`, extraction, and execution, followed by `sudo` exploiting a misconfigured sudoers rule. `apt/history.log` is unremarkable, but the journal shows auditd being stopped two minutes later, and `.bash_history` for `deploy` is a symlink to `/dev/null`.

On the image, in Autopsy and with TSK, you find a new systemd service `/etc/systemd/system/dbus-helper.service` launching the miner, an attacker SSH key added to `/root/.ssh/authorized_keys`, and a cron entry that re-downloads the miner every ten minutes. The Plaso-enriched timeline places all of this within 25 minutes of the initial login, and a keyword search of unallocated space recovers deleted lines from a truncated `auth.log.1` that confirm an earlier reconnaissance scan from a related IP. Your report ties the initial access (weak password on an internet-exposed SSH account), privilege escalation (sudoers misconfiguration), persistence (service, cron, key), and impact (cryptomining), with hashes of every artifact.

---

## Final recommendations

Preparation determines outcomes. Before an incident, deploy persistent journald storage, auditd with a solid rule set, remote log forwarding to a SIEM, and NTP-synced clocks, and prepare a trusted toolkit (UAC, AVML, LiME builds for your standard kernels, static binaries) plus kernel symbol files for Volatility. During an incident, capture memory first, never trust the suspect system's binaries, never write to its disks, and hash and document everything. During analysis, correlate across sources, because a single log can be forged but consistent evidence across auth logs, wtmp, the journal, auditd, filesystem timestamps, and memory is very hard to fake.

