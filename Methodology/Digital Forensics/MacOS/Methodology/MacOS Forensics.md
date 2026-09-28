# macOS Forensics

## 1. Introduction

macOS forensics is the practice of identifying, preserving, acquiring, analyzing and reporting on digital evidence from Apple computers. It follows the same principles as any forensic discipline: preserve integrity, keep a chain of custody, work from verified copies, and document everything. Apple's platform, however, differs from Windows and Linux in ways that change how an examiner has to work.

### Why macOS is different

**Hardware-bound encryption is the default.** Macs with the T2 security chip (roughly 2018–2020 Intel models) and all Apple Silicon Macs (M1 and later) encrypt the internal SSD at all times, using keys held in the Secure Enclave. Even with FileVault "off," the data is encrypted. The keys are only protected by hardware rather than by the user's password. As a result, removing the NAND chips ("chip-off") or swapping the SSD into another machine yields unreadable ciphertext. The machine itself is part of the decryption path.

**FileVault adds a user-credential layer.** When FileVault is on, the user's password (or a recovery key, or an institutional key) becomes part of the key hierarchy. Without one of those credentials, a powered-off Mac is effectively a sealed box. Brute force is throttled by the Secure Enclave, so the old approach of extracting a hash and cracking it offline is heavily constrained on modern hardware.

**Apple's security layers restrict what tools can do.** System Integrity Protection (SIP) limits even root. The Signed System Volume (SSV) cryptographically seals the OS. Transparency, Consent and Control (TCC) gates access to user data such as Mail, Messages, Desktop and Documents. Kernel extensions are deprecated in favor of system extensions. All of this makes live collection and memory acquisition much harder than on Windows. A forensic tool running on a live Mac usually needs Full Disk Access granted explicitly, and that act leaves its own trace.

**Hardware generation dictates the playbook.** In practice there are three eras:

| Era | Examples | Acquisition implications |
|---|---|---|
| Intel, no T2 (pre-2018) | Older MacBook Pro, iMac | Traditional: boot from external media or use Target Disk Mode, image physically with dd-style tools. Removable drives in some models. |
| Intel with T2 (2018–2020) | MacBook Pro 2018–2020, iMac Pro, Mac mini 2018 | SSD soldered and hardware-encrypted. External boot is blocked by default (Startup Security Utility). Target Disk Mode still works and presents decrypted data if the volume is unlocked. |
| Apple Silicon (2020+) | M1–M-series MacBooks, iMacs, Mac Studio, Mac mini | No Target Disk Mode. It is replaced by "Share Disk" in Recovery, which is SMB file-level sharing, not block-level. Physical imaging is effectively unavailable. Live logical or "full file system" acquisition is the norm. |

**The system is rich in structured artifacts.** macOS stores huge amounts of activity data in property lists (plists), SQLite databases, the Unified Log, FSEvents, Spotlight, Biome/KnowledgeC and Apple-specific formats. There's no registry, but these sources often reconstruct user behavior in more detail than the Windows registry does.

### The general forensic process on macOS

The workflow usually follows these stages:

1. **Triage and scene assessment.** Is the Mac on or off? Is it locked or unlocked? Is FileVault enabled? Which chip does it have? If it's powered on and unlocked, **do not shut it down casually.** Shutting down may lock the data forever if you don't have the password.
2. **Volatile collection** if the machine is live: running processes, network connections, logged-in users, mounted volumes, and a Unified Log collection.
3. **Acquisition**: physical where possible, otherwise logical or targeted collection, with hashing.
4. **Analysis**: timeline creation, artifact parsing, correlation.
5. **Reporting.**

The order of volatility still applies. Memory and live state come first, then disk, then backups and cloud data.

---

## 2. macOS File Systems

### Historical file systems

**MFS (Macintosh File System, 1984)** was a flat file system with no real folders. It's of historical interest only.

**HFS (Hierarchical File System, 1985)** introduced a hierarchy managed by B-trees. You'll rarely see it in modern casework, but it may appear on legacy media.

### HFS+ (Mac OS Extended), 1998–2017

HFS+ was the default until macOS High Sierra (10.13), and it still appears on older Macs, external drives, and older Time Machine disks. Its key structures are:

- **Volume Header** at offset 1024 bytes, with a backup copy near the end of the volume.
- **Catalog File**, a B-tree describing every file and folder. Each item has a Catalog Node ID (CNID), similar to an inode number.
- **Extents Overflow File**, which tracks file fragments beyond the first eight extents.
- **Attributes File**, which stores extended attributes.
- **Allocation File**, a bitmap of used and free blocks.
- **Journal**, added in 10.2.2 for crash consistency. It's forensically interesting because old copies of catalog records can survive in it.

HFS+ files have a **data fork** and a **resource fork**. Resource forks are a legacy Mac concept: a secondary data stream, analogous in spirit to NTFS Alternate Data Streams. Timestamps are stored in seconds since **January 1, 1904**, a detail that matters when parsing raw structures. HFS+ records create, modify, attribute change, access and backup dates. **HFSX** is the case-sensitive variant.

Deleted-file recovery on HFS+ is feasible because the file system overwrites in place. Carving unallocated space and examining the journal and old B-tree nodes can recover data, although TRIM on SSDs reduces this.

### APFS (Apple File System), 2017–present

APFS arrived with macOS 10.13 and is the default for all modern Macs, iPhones and iPads. It was designed for flash storage and encryption. It is fundamentally different from HFS+, and it's the file system you'll deal with most often.

**Containers and volumes.** An APFS partition is a *container*. It holds multiple *volumes* that share the container's free space dynamically ("space sharing"). Each volume can be encrypted independently.

**The volume group layout (Catalina 10.15 and later).** A modern Mac's container typically holds several volumes. The **System** volume holds the read-only OS; since Big Sur it's a sealed snapshot. The **Data** volume holds user data, applications and settings, and it's where almost all evidence lives. **Preboot** holds boot files and encryption metadata. **Recovery** holds the recovery OS, and **VM** holds swap and the sleep image. The System and Data volumes are joined by **firmlinks**, bidirectional links that make paths like `/Users` or `/Applications` appear seamless even though they live on the Data volume. When examining an image, remember that `/System/Volumes/Data/` is the real location of user content.

**Signed System Volume (Big Sur 11+).** The OS volume is hashed in a Merkle tree and sealed. The Mac boots from a *snapshot* of it. For forensics this means the system volume is almost never where evidence of tampering lives, and any modification breaks the seal.

**Copy-on-write (CoW).** APFS never overwrites data in place. Modified blocks are written to new locations and metadata pointers are updated. In principle this means old versions of data may linger in unallocated space. In practice TRIM, encryption, and the difficulty of mapping orphaned blocks back to files make recovery much harder than on HFS+.

**Checkpoints and the object map.** APFS keeps multiple checkpoints of the container superblock (NXSB) and object maps (omap). Older checkpoints can sometimes reveal earlier file system states. Advanced tools and research, such as work by Kurt Hansen and Fergus Toolan and the APFS support in The Sleuth Kit, exploit this to recover deleted files.

**Snapshots.** APFS supports point-in-time, read-only snapshots of volumes. Time Machine creates **local snapshots**, and since Big Sur, Time Machine backs up to APFS destinations using snapshots too. Snapshots are a forensic goldmine: they can contain files the user later deleted. You can list them with `tmutil listlocalsnapshots /` and mount them read-only.

**Clones.** Copying a file on the same APFS volume can create a *clone*: a new file that shares the same data blocks until one is modified. Clones consume no extra space. This matters for "Copy and Duplicate," covered below.

**Native encryption.** APFS supports unencrypted, single-key and multi-key encryption (per-file keys, used on iOS). On Macs, FileVault is implemented as APFS volume encryption. On T2 and Apple Silicon Macs it sits on top of the always-on hardware encryption.

**Timestamps.** APFS stores timestamps as **64-bit nanoseconds since the Unix epoch (January 1, 1970, UTC)**. That's high precision, which is excellent for timeline correlation. Each inode records creation (birth), modification, change (inode metadata) and access time. APFS also records **Date Added**, when the item was placed in its current folder, which Finder and Spotlight use. Access-time updates are relaxed by default ("relatime"-like behavior), so don't rely on atime as proof of access.

**Case sensitivity.** Volumes are case-insensitive by default, with a case-sensitive option. **Fusion Drive** setups, which combine an SSD and HDD into one logical APFS container, complicate imaging because both physical devices must be acquired together.

### Extended attributes (xattrs)

Both HFS+ and APFS support extended attributes. They're some of the most valuable metadata on the platform:

| Attribute | Meaning |
|---|---|
| `com.apple.quarantine` | Set on downloaded files. Includes flags, a timestamp, the downloading app, and a UUID linking to the QuarantineEvents database. |
| `com.apple.metadata:kMDItemWhereFroms` | The URL(s) a file was downloaded from, and sometimes the referring page or email sender. |
| `com.apple.metadata:kMDItemDownloadedDate` | When the file was downloaded. |
| `com.apple.lastuseddate#PS` | When the file was last opened. |
| `com.apple.FinderInfo` | Finder flags, color labels and type/creator codes. |
| `com.apple.metadata:_kMDItemUserTags` | User-assigned tags. |
| `com.apple.ResourceFork` | Legacy resource fork data. |
| `com.apple.provenance` | Newer attribute (Ventura+) tracking app provenance, relevant to Gatekeeper. |

Use `xattr -l <file>` to view them. Many parsers decode them automatically. Some file transfers strip xattrs, for example uploading to certain cloud services or copying to FAT32 (which creates `._` AppleDouble files instead). That behavior is itself evidence.

### Other file systems you'll see on Macs

macOS reads and writes **FAT32 and exFAT**, which are common on USB sticks and SD cards. It reads **NTFS** natively, but writes only with third-party drivers. It also supports network file systems (SMB, NFS). Removable media connected to a Mac often carries telltale hidden files: `.Spotlight-V100`, `.fseventsd`, `.Trashes`, `.DS_Store`, and `._filename` AppleDouble files. Finding these on a USB drive is strong evidence that it was attached to a Mac.

### Hidden file-system-level directories worth knowing

At the root of volumes you'll find `/.fseventsd` (the FSEvents change log), `/.Spotlight-V100` (the Spotlight index), `/.DocumentRevisions-V100` (the Versions database for auto-saved documents), `/.Trashes` (per-volume trash on external drives), and `/.vol` (a virtual directory allowing access by file ID). `.DS_Store` files in every browsed folder store Finder view settings and file names. They can prove a folder was browsed and reveal names of files that no longer exist.

---

## 3. Copy and Duplicate on macOS

This topic covers two things: forensically sound acquisition (creating verified duplicates of evidence), and understanding how macOS itself copies and duplicates files, since that affects the artifacts you interpret.

### Part A: Forensic acquisition and imaging

**Core principles.** Always write-protect the source when possible. Hash the source and the image (SHA-256 now, often with MD5 or SHA-1 alongside for legacy compatibility). Document every step, and work only on copies.

**Preventing auto-mounting.** macOS aggressively mounts any volume it sees, and mounting can modify metadata: journal replay, `.fseventsd` writes, Spotlight indexing, and `.DS_Store` creation. On a forensic examination Mac, use a hardware write blocker for external media. Where that isn't possible, mount volumes read-only (`diskutil mount readOnly /dev/diskXsY`) and disable Spotlight indexing on evidence volumes. Historically, examiners disabled the Disk Arbitration daemon to prevent automount. On modern macOS with SIP, that's more difficult, and dedicated forensic tools or write-blocker software are preferred.

**Acquisition options by hardware.**

On **Intel Macs without a T2 chip**, traditional physical imaging works. You can boot the target from a forensic boot USB (such as a Linux forensic distribution or a vendor boot tool) and image the internal disk with `dd`, `dc3dd`, `dcfldd` or `ewfacquire`. Alternatively, put the target in **Target Disk Mode** (hold T at boot), connect it via Thunderbolt or FireWire to a forensic workstation through a write blocker, and image it as an external disk.

On **T2 Macs**, external booting is disabled by default. Enabling it requires changing Startup Security Utility in Recovery, which needs an administrator's credentials. Target Disk Mode still works. If FileVault is off, the T2 transparently decrypts and the host sees plaintext. If FileVault is on, you need the password to unlock the volume. A raw image of the SSD without the T2 decrypting it is worthless.

On **Apple Silicon Macs**, there's no Target Disk Mode. The replacement, **Share Disk** (Recovery → Utilities → Share Disk), exposes the volume over SMB as a file share. That's a logical, file-level copy only, and it requires unlocking. The practical approach is a **live acquisition** on an unlocked Mac using a forensic tool that performs a logical or "full file system" collection, often packaged into a sparse image or DMG. Tools like Cellebrite Digital Collector, SUMURI RECON ITR, and Magnet's acquisition tools are designed for this. The tool typically needs Full Disk Access granted in System Settings. The acquisition is logical, so deleted data in unallocated space is generally out of reach, but the live file system, snapshots and all artifacts are captured.

**Handling APFS snapshots.** Local snapshots should be captured, because they hold earlier states of the file system:

```bash
tmutil listlocalsnapshots /
mkdir /tmp/snap
mount_apfs -o ro -s com.apple.TimeMachine.2026-09-28-101500.local /System/Volumes/Data /tmp/snap
```

**Native Apple tools for duplication.** `hdiutil` can create disk images from a device or folder:

```bash
# Read-only compressed image of a device
sudo hdiutil create -srcdevice /dev/disk4 -format UDZO evidence.dmg

# Image from a folder (logical)
sudo hdiutil create -srcfolder /Volumes/Target -format UDRO evidence.dmg
```

`dd` and variants work on raw devices (`/dev/rdiskN`, the "raw" character device, is much faster than `/dev/diskN`):

```bash
sudo dd if=/dev/rdisk4 of=/Volumes/Evidence/image.dd bs=4m conv=noerror,sync
shasum -a 256 /Volumes/Evidence/image.dd
```

`ditto` and `rsync` (with the appropriate flags) copy files while preserving metadata, xattrs, ACLs and resource forks, which is useful for targeted logical collection. `asr` (Apple Software Restore) can do block-level copies of volumes. It's mainly used for deployment, but it's relevant to know.

**Memory acquisition.** This is the weakest area of macOS forensics today. Historical tools such as OSXPmem (from the Rekall project), Mac Memory Reader, and some commercial options relied on kernel extensions. On modern macOS with SIP, the kext restrictions and Apple Silicon's architecture make full physical memory capture largely infeasible without weakening system security. Examiners rely instead on **live response collection**: process listings (`ps aux`), open files and sockets (`lsof`), network connections (`netstat`, `lsof -i`), launchd state (`launchctl list`), logged-in users, mounted volumes, and a Unified Log archive via `log collect`. Apple's own `sysdiagnose` produces a large diagnostic bundle that's forensically useful. Note that `/private/var/vm/sleepimage` and swap files are encrypted on modern systems, so they're of limited value.

**Other duplicates of evidence.** Always consider data stored elsewhere: Time Machine backups on external drives or network storage, iCloud Drive and iCloud backups (Advanced Data Protection end-to-end encrypts most categories, which limits legal-process returns from Apple), and **iPhone/iPad backups stored on the Mac** at `~/Library/Application Support/MobileSync/Backup/`. Those backups are often an unexpected treasure trove.

### Part B: How macOS copies and duplicates files, and the artifacts that result

Understanding copy behavior prevents misinterpreting evidence.

**Finder "Duplicate" (⌘D) and copying on the same APFS volume.** These create a **clone**. The new file gets its own inode and a new birth time. Metadata may be carried over, but the data blocks are shared. No extra disk space is consumed until one copy is modified. `cp -c` explicitly requests a clone.

**Copying to a different volume** (for example, to a USB drive) creates a full physical copy. Finder generally preserves the **modification date** and often the creation date too, which can make a copy look older than the act of copying. The **Date Added** attribute and FSEvents records, by contrast, reflect when the copy happened. This is a classic interpretation trap. A file with a modification date older than its creation date is usually a sign that it was copied from elsewhere.

**Terminal `cp` without flags** may not preserve all metadata. `cp -p` preserves times and permissions. On modern macOS, `cp` does preserve xattrs by default, including the quarantine flag. That means a downloaded file's `kMDItemWhereFroms` URL can follow copies around, which can be very useful for proving where a file originated.

**Moving versus copying.** A move within one volume keeps the same inode and timestamps, changing only the parent directory. The move is visible in FSEvents as a rename. A move across volumes is a copy followed by a delete.

**Copies to FAT/exFAT** can't store xattrs natively. macOS writes `._filename` AppleDouble companions to hold them, so these files on removable media reveal what was copied from a Mac and can preserve the original metadata.

**AirDrop** transfers land in `~/Downloads` with quarantine attributes and leave traces in the Unified Log (the `sharingd` subsystem).

**Duplicate detection in analysis.** When hunting for duplicate evidence files, rely on hash values rather than names or sizes. On APFS, remember that clones can make two files look like separate full copies in a logical listing while sharing physical storage. That can confuse space-usage analysis but doesn't affect content hashing.

---

## 4. Evidentiary Data on macOS

This is the heart of macOS forensics. Artifacts come in a handful of formats: **plists** (XML or binary; parse them with `plutil -p`), **SQLite databases** (watch for `-wal` and `-shm` files, which contain uncommitted and sometimes deleted records), the **Unified Log** (tracev3), **FSEvents**, **Spotlight**, and Apple-specific binary formats like **SEGB** (Biome) and **NSKeyedArchiver** blobs inside plists.

Paths below use `~` for a user's home folder. On an image, system paths may be under `/System/Volumes/Data/`.

### A note on timestamp formats

Timestamps are one of the most common sources of errors in Mac casework:

| Format | Epoch | Where you'll see it |
|---|---|---|
| Mac Absolute Time / Cocoa Core Data | Seconds since 2001-01-01 00:00:00 UTC | Most Apple SQLite databases (Messages, Safari, KnowledgeC, Photos) |
| Unix | Seconds since 1970-01-01 | Many system files, logs |
| APFS | Nanoseconds since 1970-01-01 | File system metadata |
| HFS+ | Seconds since 1904-01-01 | HFS+ structures |
| WebKit/Chrome | Microseconds since 1601-01-01 | Chrome history |

Messages' `chat.db` stores Mac Absolute Time in nanoseconds on newer versions. Always validate a decoded time against a known event.

### System information

The OS version is in `/System/Library/CoreServices/SystemVersion.plist`. The computer name and host name are in `/Library/Preferences/SystemConfiguration/preferences.plist`. The time zone is reflected by the `/etc/localtime` symlink and `/Library/Preferences/.GlobalPreferences.plist`. The approximate OS installation or setup date can come from the timestamp of `/private/var/db/.AppleSetupDone`. Software and update install history is in `/Library/Receipts/InstallHistory.plist` and `/private/var/db/receipts/`. Serial number and hardware details come from `system_profiler` on a live system, or from various plists and logs on an image.

### User accounts and authentication

Local user accounts are stored as plists in `/private/var/db/dslocal/nodes/Default/users/`. These contain the UID, home directory, the password hash (`ShadowHashData`, using SALTED-SHA512-PBKDF2), the account creation time, and failed login counts. Groups (including membership in the `admin` group) are under `.../groups/`. `/Library/Preferences/com.apple.loginwindow.plist` shows the last logged-in user and auto-login settings. If auto-login is enabled, `/etc/kcpassword` holds the password in trivially reversible obfuscated form, which is a significant finding. Login and logout activity, screen unlocks, and authentication events are recorded in the Unified Log and in the legacy `/private/var/log/` files where they exist. `last` works on a live system (it reads utmpx).

### The Keychain

User keychains are at `~/Library/Keychains/` (`login.keychain-db` plus a UUID-named folder for the local items/iCloud keychain). The system keychain is at `/Library/Keychains/System.keychain`. Keychains hold saved passwords, Wi-Fi keys, certificates and tokens. They're encrypted, and with the user's password, tools like Chainbreaker (for legacy keychains) or commercial tools can decrypt them. Much of the modern data-protection keychain is tied to the Secure Enclave and is only accessible on the live, unlocked machine.

### The Unified Log (macOS 10.12 Sierra and later)

The Unified Log replaced most traditional text logs. It records a vast amount of system activity, including process execution, authentication, network events, USB connections, AirDrop, Bluetooth, sleep and wake, Gatekeeper decisions, and TCC prompts. Data lives in `/private/var/db/diagnostics/` (`.tracev3` files in Persist, Special, Signpost and HighVolume subfolders) with string tables in `/private/var/db/uuidtext/`. **Both directories must be collected together**, or messages can't be decoded.

On a live system:

```bash
sudo log collect --output evidence.logarchive --last 7d
log show evidence.logarchive --predicate 'subsystem == "com.apple.sharing"' --info
log show --predicate 'eventMessage CONTAINS "USB"' --start "2026-09-20"
```

Retention varies: some categories last days, others weeks, depending on volume and log level. Collect early. Some message content is marked `<private>` by default, which redacts dynamic values. That's a real limitation.

Legacy logs still exist in part: `/private/var/log/system.log` (much reduced), `install.log` (software installs, very useful), `wifi.log` on older systems, and the Apple System Log (`.asl`) files on older versions.

### FSEvents

`/.fseventsd/` on each volume contains gzip-compressed logs of file system changes: creation, deletion, rename, modification, and mounts and unmounts. Each record holds the full path, event flags and an event ID, though no precise timestamp (dates are inferred from the log file and neighboring events). FSEvents can prove that a file existed at a path and was deleted, even long after the file itself is gone. It also records activity on external volumes and can reveal names of files on USB drives. This is one of the single most powerful macOS artifacts.

### Spotlight

The Spotlight index lives in `/.Spotlight-V100/` (the `store.db` files). It holds metadata for indexed files, including names, content snippets, dates, last-used dates, usage counts, and "where from" data, sometimes for files that have since been deleted. Tools like `spotlight_parser` (part of mac_apt) parse the raw database. `mdls <file>` shows a file's metadata live. There are also per-user Spotlight stores inside `~/Library/Metadata/CoreSpotlight/`, which index app content such as Mail, Messages and Notes.

### Pattern-of-life databases: KnowledgeC and Biome

`knowledgeC.db` exists in `/private/var/db/CoreDuet/Knowledge/` and in `~/Library/Application Support/Knowledge/`. It records app usage (which app was in focus and when), screen lock and unlock, display backlight, plugged-in status, Safari history, and more. Starting around macOS Ventura/Sonoma, much of this data moved to **Biome**, in `/private/var/db/biome/` and `~/Library/Biome/`. Biome uses SEGB-format files organized into "streams" (app in focus, notifications, device lock, now playing, and others). Sarah Edwards' **APOLLO** framework and the mac_apt and Biome parsers extract these. They answer questions like "was the user actively using the computer at 2:14 a.m.?"

**Screen Time** data (`RMAdminStore-Local.sqlite` and related files in `/private/var/folders/.../com.apple.ScreenTimeAgent/`) records app and web usage summaries, sometimes synced across the user's devices.

### Program execution and application artifacts

There's no Prefetch or ShimCache equivalent, so evidence of execution is assembled from several sources. These include the Unified Log, KnowledgeC and Biome "app in focus" records, the `com.apple.lastuseddate#PS` xattr on application bundles, Spotlight's `kMDItemLastUsedDate` and `kMDItemUseCount`, `~/Library/Application Support/com.apple.sharedfilelist/` (recent applications, documents and servers in `.sfl2` or `.sfl3` files), and per-app preference plists in `~/Library/Preferences/`. Application-specific state is kept in `~/Library/Saved Application State/` (window state, which can reveal what was open), `~/Library/Containers/` (sandboxed app data) and `~/Library/Group Containers/`. Installed applications are in `/Applications` and `~/Applications`. Apps installed from the Mac App Store carry receipts inside their bundles.

Terminal activity is captured in `~/.zsh_history` (zsh has been the default shell since Catalina), `~/.bash_history` on older systems, and `~/.zsh_sessions/`, which holds per-window session history.

### Recent files and user navigation

`~/Library/Application Support/com.apple.sharedfilelist/` holds recent documents, both global and per application. `~/Library/Preferences/com.apple.finder.plist` contains recently visited folders, "Go to Folder" entries, and connected servers. **`.DS_Store` files** reveal folder browsing and file names. **Document Versions** in `/.DocumentRevisions-V100/` preserves earlier versions of documents edited in apps that support auto-save (TextEdit, Pages, Preview and others), which can reveal deleted or altered content.

### Downloads and file origin

`~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2` is an SQLite database recording downloads made through quarantine-aware apps: the URL, the originating app, and the timestamp. It links to the `com.apple.quarantine` xattr on individual files through a shared UUID. Combined with `kMDItemWhereFroms`, this reconstructs download provenance even after browser history has been cleared. Safari also keeps `~/Library/Safari/Downloads.plist`.

### Web browsers

**Safari** stores data in `~/Library/Safari/` and the `~/Library/Containers/com.apple.Safari/` container. The important files are `History.db` (visits and URLs), `Downloads.plist`, `Bookmarks.plist`, `TopSites.plist`, `LastSession.plist` and the per-profile folders introduced in Sonoma. Cache and website data are under `~/Library/Caches/com.apple.Safari/` and `~/Library/WebKit/`. iCloud tabs from the user's other devices are in `CloudTabs.db`, which can reveal browsing on the user's iPhone.

**Chrome** stores data in `~/Library/Application Support/Google/Chrome/Default/` (or `Profile N/`): `History`, `Cookies`, `Login Data`, `Web Data`, `Bookmarks` and more. **Firefox** stores data in `~/Library/Application Support/Firefox/Profiles/<profile>/`, mainly `places.sqlite`, `formhistory.sqlite` and `cookies.sqlite`. Edge, Brave and other Chromium browsers follow the Chrome structure.

### Communications

**Messages (iMessage/SMS)** stores data in `~/Library/Messages/chat.db`, with attachments in `~/Library/Messages/Attachments/`. With "Text Message Forwarding" and Messages in iCloud, a Mac can hold the user's full phone messaging history. Pay attention to the `-wal` file and to deleted-message recovery (iOS 16 and macOS Ventura introduced "Recently Deleted," which stays for up to 30 days).

**Mail** stores messages in `~/Library/Mail/V10/` (the version number increases over releases) as `.emlx` files, with the `Envelope Index` SQLite database acting as the master index. Attachments are also stored there.

**Call history** from FaceTime and iPhone Continuity calls is in `~/Library/Application Support/CallHistoryDB/CallHistory.storedata`. **Contacts** are in `~/Library/Application Support/AddressBook/`. **Calendar** data is in `~/Library/Calendars/` or its group container. **Notes** is in `~/Library/Group Containers/group.com.apple.notes/NoteStore.sqlite`, with protobuf-encoded, gzipped note bodies. Tools like apple_cloud_notes_parser decode them, including locked notes if you have the password. Third-party apps (Slack, Teams, WhatsApp, Telegram, Signal and others) keep data in their own containers, often in SQLite or LevelDB. Signal encrypts its database with a key protected by the keychain.

### Photos and media

The Photos library is at `~/Pictures/Photos Library.photoslibrary/`, with the core metadata database at `database/Photos.sqlite`. It contains EXIF-derived GPS data, face and person recognition, scene classification (Apple's ML labels such as "car" or "beach"), albums, the hidden album, and "Recently Deleted." Originals are under `originals/`. The library may contain photos synced from the user's iPhone through iCloud Photos.

### Network activity

Known Wi-Fi networks are in `/Library/Preferences/com.apple.wifi.known-networks.plist` (Monterey and later), which includes SSIDs, BSSIDs, first- and last-join timestamps and security type. Older systems used `com.apple.airport.preferences.plist`. DHCP leases are in `/private/var/db/dhcpclient/leases/`. Network interface configuration is in `/Library/Preferences/SystemConfiguration/NetworkInterfaces.plist` and `preferences.plist`. Per-process network usage is in `/private/var/networkd/db/netusage.sqlite`, which is excellent for showing which apps communicated and how much data they transferred. VPN configurations, firewall settings (`/Library/Preferences/com.apple.alf.plist` on older systems), and SSH artifacts (`~/.ssh/known_hosts`, `authorized_keys`) also matter. Remote access traces include Screen Sharing and ARD logs and preferences, plus third-party tools like TeamViewer and AnyDesk, which keep their own logs.

### External devices, Bluetooth and USB

macOS has no single USB history store like the Windows registry's USBSTOR. Evidence of external devices comes from several places: the Unified Log (IOKit, USB and disk arbitration messages), FSEvents (volume mount and unmount records and file activity on the device), Spotlight and `.fseventsd` folders written *onto* the removable media, `/private/var/db/` and Finder plists that track mounted volumes and disk images, and the `sharedfilelist` "recent servers" list for network shares. Paired Bluetooth devices appear in `/Library/Preferences/com.apple.Bluetooth.plist` (plus the Unified Log). iOS devices paired with the Mac leave lockdown records in `/private/var/db/lockdown/` and backups in the MobileSync folder.

### Persistence mechanisms (key for malware and intrusion cases)

Launch agents and daemons are the primary persistence mechanism. Look in `~/Library/LaunchAgents/`, `/Library/LaunchAgents/`, `/Library/LaunchDaemons/` and the Apple-owned `/System/Library/` equivalents, which are protected by the SSV. **Login items and background items** are managed in Ventura and later by Background Task Management, with a database at `/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm`. It's parseable with `sfltool dumpbtm` on a live system and records persistent items with their developer identity. Other mechanisms include cron (`/usr/lib/cron/tabs/`), the `periodic` scripts, configuration profiles (`/private/var/db/ConfigurationProfiles/`, or `profiles list` live), system and kernel extensions (`/Library/SystemExtensions/`, `/Library/Extensions/`), shell startup files (`~/.zshrc`, `~/.zprofile`), authorization plugins, legacy login and logout hooks, and malicious browser extensions.

### Security and privacy subsystems

**TCC databases** (`/Library/Application Support/com.apple.TCC/TCC.db` and `~/Library/Application Support/com.apple.TCC/TCC.db`) record which apps were granted access to the camera, microphone, screen recording, Full Disk Access, contacts and more, and when. They're crucial for spyware and stalkerware cases. **XProtect**, Apple's built-in anti-malware, keeps a behavioral database at `/private/var/protected/xprotect/XPdb` (Ventura and later) that logs detected rule violations. Gatekeeper decisions appear in the Unified Log and the quarantine artifacts. Also check the MRT (Malware Removal Tool) logs on older systems.

### Location

`/private/var/db/locationd/clients.plist` records which apps requested Location Services. Photos GPS data, Wi-Fi BSSIDs (which can be geolocated), Find My and time zone data help establish where a device was.

### Trash and deletion

The user's Trash is at `~/.Trash/`. The `.DS_Store` inside it stores the **Put Back** information (`ptbL` for original location, `ptbN` for original name), proving where a trashed file came from. External volumes use `/.Trashes/<UID>/`. After a Trash is emptied, evidence of the deleted files can persist in FSEvents, Spotlight, APFS snapshots, Document Versions, Time Machine backups, SQLite free pages and WAL files, `sharedfilelist` recents, `.DS_Store` files, and cloud sync databases.

### iCloud and cloud sync

iCloud Drive content is stored in `~/Library/Mobile Documents/`. The sync state is in `~/Library/Application Support/CloudDocs/session/db/` (`client.db` and `server.db`), which lists files in the user's iCloud Drive, including files that were never downloaded locally ("dataless" files that show up with a cloud icon). The Apple Account is identified in `~/Library/Preferences/MobileMeAccounts.plist`. Dropbox, OneDrive and Google Drive keep their own sync databases and logs.

### Power, sleep and system state

`pmset -g log` on a live system shows a detailed history of sleep, wake, display on and off, and reasons for waking. It's backed by power management logs and the Unified Log. It's useful for establishing whether the machine was active at a given time. Shutdown and reboot records appear in the Unified Log and `last`.

---

## 5. macOS Forensics Tools

The landscape changes often, so check current versions and support for the latest macOS before relying on any tool in a case.

### Commercial acquisition tools

**Cellebrite Digital Collector** (formerly MacQuisition from BlackBag) performs live and dead-box acquisition of Macs, including logical and full file system collection on T2 and Apple Silicon systems, plus targeted collection. **SUMURI RECON ITR** is a bootable and live imaging and triage tool designed specifically for Macs, with strong Apple Silicon support. **Magnet** offers acquisition via Magnet AXIOM/Magnet Acquire and the enterprise-oriented AXIOM Cyber and Magnet One platforms. **Binalyze AIR** and similar enterprise DFIR platforms support remote macOS collection. **Passware Kit** includes FileVault attack and memory analysis capabilities.

### Commercial analysis suites

**Cellebrite Inspector** (formerly BlackBag BlackLight) is one of the most Mac-focused analysis tools, with deep APFS, Unified Log, KnowledgeC/Biome and Apple artifact support. **Magnet AXIOM** parses a very wide range of macOS and iOS artifacts and correlates them with mobile and cloud data. **SUMURI RECON LAB** is Mac-native analysis software with a strong artifact library. **Belkasoft X**, **Exterro FTK**, **OpenText EnCase**, and **X-Ways Forensics** all support APFS and many macOS artifacts to varying degrees. **Elcomsoft** tools cover iCloud acquisition, keychain analysis and password recovery.

### Open-source and free tools

**mac_apt** (macOS Artifact Parsing Tool, by Yogesh Khatri) is arguably the most comprehensive open-source macOS artifact parser. It works on E01, DD and DMG images, mounted volumes, and live systems. It parses dozens of artifacts, including FSEvents, Spotlight, Unified Logs, Safari, Messages, Wi-Fi, users, quarantine, TCC and more. It supports APFS natively, including encrypted volumes with a password. It comes with its own mac_apt_artifact_collector and a Spotlight parser.

**The Sleuth Kit and Autopsy** support APFS in recent versions, including pools and volumes. They're useful for low-level file system analysis. **apfs-fuse** mounts APFS images on Linux, including encrypted volumes with a password. **Plaso/log2timeline** builds super-timelines and includes parsers for many macOS formats (FSEvents, plists, SQLite, the Unified Log, `.DS_Store`, and more).

For the Unified Log, **Mandiant's macos-UnifiedLogs** (a Rust library and tool) parses logarchives and raw tracev3 files on non-Mac platforms. Apple's own `log` command and Console.app remain the reference. Older Python options like UnifiedLogReader exist.

**FSEventsParser** (by David Cowen/G-C Partners) parses `.fseventsd` records. **APOLLO** (Apple Pattern of Life Lazy Output'er, by Sarah Edwards) runs SQL modules against KnowledgeC, Biome, netusage, Screen Time and other databases to build pattern-of-life timelines. **Aftermath** (from Jamf) is an open-source macOS incident-response collection and analysis framework. **Velociraptor** has macOS artifacts for live collection and hunting across fleets. **Objective-See tools** (KnockKnock, BlockBlock, TaskExplorer, LuLu, DoNotDisturb and others, by Patrick Wardle) excel at persistence and malware analysis on live systems. **Chainbreaker** extracts and decrypts legacy keychains given the password. **apple_cloud_notes_parser** decodes Notes. **ccl_bplist**, **ccl_segb** (for Biome SEGB files) and related libraries from CCL Solutions help with Apple formats. **DB Browser for SQLite** and SQLite forensic tools (for WAL and freelist recovery) are indispensable. **Volatility** has macOS profiles, but it's limited by the memory acquisition problems described earlier.

### Built-in macOS commands every examiner should know

| Command | Use |
|---|---|
| `diskutil list`, `diskutil apfs list`, `diskutil info` | Enumerate disks, APFS containers, volumes, encryption state |
| `hdiutil` | Create, attach and verify disk images (attach read-only with `-readonly`) |
| `tmutil listlocalsnapshots`, `mount_apfs -s` | Find and mount APFS snapshots |
| `fdesetup status` | Check FileVault status |
| `log show`, `log collect` | Query and export the Unified Log |
| `plutil -p`, `defaults read` | Read plists |
| `sqlite3` | Query databases |
| `xattr -l`, `mdls`, `stat -x`, `GetFileInfo` | File metadata, xattrs, Spotlight attributes, timestamps |
| `sfltool dumpbtm` | Dump Background Task Management (persistence) items |
| `launchctl list`, `ps`, `lsof`, `netstat` | Live-response process and network state |
| `system_profiler`, `sysdiagnose` | Hardware and system details, large diagnostic bundle |
| `pmset -g log` | Sleep and wake history |
| `shasum -a 256`, `md5` | Hashing |

### Practical tool strategy

Most examiners combine tools. A typical modern approach is to acquire with a Mac-capable collector (live logical collection for Apple Silicon), hash and verify, then process the image in one or two commercial suites for broad coverage. Parsing the same key artifacts with open-source tools like mac_apt, APOLLO and a Unified Log parser serves as independent validation. Finally, correlate everything into a single timeline. Validating findings across two tools, and against manual inspection of the raw artifact, is best practice, especially for timestamps and for newer macOS versions whose formats tools may not yet fully support.

---

## Key takeaways

Modern macOS forensics is shaped by encryption and Apple's security architecture more than by the file system. Whether a Mac is powered on, unlocked, and which chip it has often determines what's possible before any analysis begins. APFS brings snapshots, clones and nanosecond timestamps, but it makes deleted-file recovery harder than it was on HFS+. The richest evidence usually comes from structured artifacts: the Unified Log, FSEvents, Spotlight, KnowledgeC/Biome, quarantine data, TCC, and application databases. Because the platform changes every year, keeping your tools current and validating their output are part of the job, not optional extras.
