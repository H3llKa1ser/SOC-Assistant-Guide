# iOS Forensics

## Introduction

iOS forensics is the practice of recovering, analyzing, and interpreting data from Apple mobile devices (iPhones, iPads, iPod Touch) in a forensically sound manner. It's used in law enforcement, corporate investigations, incident response, and e-discovery.

The core challenge of iOS forensics is Apple's security architecture. Modern iOS devices use hardware-backed encryption (the Secure Enclave), full-disk encryption tied to the user passcode, and a tightly controlled software environment. This makes acquisition harder than on many other platforms, and the available techniques depend heavily on the device model, iOS version, and whether you have the passcode.

Acquisition methods generally fall into a hierarchy of completeness:

- **Physical acquisition** — a bit-for-bit image of the storage. Largely obsolete on modern devices due to encryption; historically viable on older/jailbroken devices.
- **File system acquisition** — access to the full file system, usually requiring a jailbreak, an exploit (like checkm8 for certain older chipsets), or an agent-based method offered by commercial tools.
- **Logical acquisition** — extracting data through Apple's supported interfaces, principally by generating an iTunes-style backup. This is the most common and most legally defensible method.
- **iCloud acquisition** — pulling data from Apple's cloud services with credentials or tokens.

The dominant commercial tools in this space include Cellebrite UFED/Physical Analyzer, Magnet AXIOM, Elcomsoft's iOS Forensic Toolkit and Phone Breaker, Oxygen Forensic Detective, and MSAB XRY. On the open-source side, **libimobiledevice** and tools like **iLEAPP** (iOS Logs Events And Properties Parser) are widely used.

A recurring theme in this field: **the passcode is everything**. With it, you can decrypt backups and access most data; without it, on a modern locked device, your options narrow dramatically.

## iOS File System

Modern iOS uses **APFS (Apple File System)**, which replaced HFS+ starting with iOS 10.3 (2017). APFS was designed for flash storage and brings native encryption, snapshots, clones, and space sharing across volumes.

Key structural points:

- The storage is divided into an **APFS container** holding multiple **volumes**. Critically, iOS separates the **System volume** (read-only, containing the OS) from the **Data volume** (read-write, containing all user data). This split became more rigid with the Signed System Volume (SSV) in iOS 15.
- User data lives predominantly under `/private/var/mobile/`. Application data is under `/private/var/mobile/Containers/`, split into **Bundle** containers (the app itself) and **Data** containers (the app's documents, caches, preferences).

Forensically important artifacts and their typical locations:

- **SQLite databases** are the backbone of iOS data. Almost every app stores structured data in SQLite. Examples: `sms.db` (Messages), `CallHistory.storedata` (calls), `AddressBook.sqlitedb` (contacts), `Calendar.sqlitedb`, `consolidated.db` and `cache_encryptedB.db` (location).
- **Property lists (plists)** store configuration and preferences, in both binary and XML formats. `Info.plist`, `Manifest.plist`, and app-specific preference plists are common.
- **WAL and SHM files** — SQLite's Write-Ahead Logging means recent data may live in `-wal` and `-shm` sidecar files rather than the main database. Forensic examiners must account for these or risk missing recent records.
- **Knowledge and biome data** — `knowledgeC.db` and the newer Biome/Segb structures aggregate device usage patterns, app usage, and user activity, which are extremely valuable for timeline reconstruction.

A major forensic concept here is **Data Protection classes**. Every file is encrypted with a per-file key, which is wrapped by a class key. Classes range from "Complete Protection" (available only when the device is unlocked) to "No Protection." This is why some data is accessible even before first unlock (BFU) while other data is only available after first unlock (AFU). Understanding BFU vs. AFU state is central to modern iOS acquisition.

## Handling Locked Backups

iOS backups can be **encrypted** (password-protected), and this is where a lot of forensic effort concentrates.

When a user enables "Encrypt local backup" in iTunes/Finder, the entire backup is encrypted with a key derived from the user's chosen password. Importantly, **encrypted backups actually contain *more* data than unencrypted ones** — Apple only includes certain sensitive items (saved passwords/Keychain, Wi-Fi settings, Health data, call history, website history) in *encrypted* backups. So counterintuitively, an encrypted backup can be a richer forensic prize *if* you can break the password.

Handling locked (encrypted) backups involves:

- **Password recovery / brute-forcing.** Tools like Elcomsoft Phone Breaker and Passware attack the backup password. The feasibility depends heavily on iOS version because Apple has repeatedly strengthened the key derivation:
  - Pre-iOS 10.2 backups used weaker derivation, allowing very fast GPU-accelerated attacks.
  - iOS 10.0–10.1 briefly had a vulnerability enabling extremely fast attacks.
  - iOS 10.2 onward moved to **10,000,000 iterations of PBKDF2-SHA256**, drastically slowing brute-force and making strong passwords effectively unbreakable.
- **Dictionary and mask attacks.** Because brute force is slow, examiners rely on wordlists, known-password reuse, and patterns.
- **Removing/knowing the password.** If you have the unlocked device and the passcode, you can sometimes reset the backup encryption password (on iOS 11+, "Reset All Settings" clears the backup password without wiping data), then create a fresh encrypted backup with a password you control.

The cryptographic detail worth knowing: encrypted backups protect the `Manifest.db` (the index of backup files) and the file contents using keys derived from the backup password via a Keybag structure. Without the password, the manifest and files are opaque.

## Handling iCloud Data

iCloud is an increasingly important source because so much data now syncs to the cloud rather than living only on the device.

What can be in iCloud:

- **iCloud Backups** — full device backups (similar in spirit to local backups).
- **iCloud-synced data** — Photos, Contacts, Calendars, Notes, iCloud Drive, Safari data, and more, synced independently of backups.
- **iCloud Keychain** — synced passwords.
- **Messages in iCloud** — when enabled, iMessages/SMS sync to iCloud.

Acquisition approaches:

- **With credentials (Apple ID + password).** Tools authenticate as the user. The huge obstacle is **two-factor authentication (2FA)**, which is now effectively mandatory. You need access to a trusted device or the 2FA code, plus often an **authentication token** captured from a computer where the user was signed in.
- **With authentication tokens.** Elcomsoft and others can use tokens extracted from a target's computer (e.g., from iCloud for Windows) to access iCloud without the password, though token lifetimes and validity have been tightened over time.
- **Legal process.** In law enforcement contexts, data is frequently obtained directly from Apple via warrant or subpoena. Apple publishes what it can provide, and notably, **standard iCloud Backups have historically been recoverable by Apple** because Apple held the keys.

A major recent development is **Advanced Data Protection (ADP)**, introduced in late 2022. When a user enables ADP, most iCloud categories become **end-to-end encrypted**, meaning Apple itself cannot decrypt them and cannot hand them over even under legal process. This significantly changes the calculus for cloud forensics — for ADP-enabled accounts, cloud acquisition largely requires the user's own keys/credentials.

## Files in Backup Data

An iOS backup (local, iTunes/Finder-style) has a specific and somewhat non-intuitive structure. Understanding it is essential because backup files are **not** stored with their original names or paths.

On disk, a backup folder (named with the device UDID or a hash) contains:

- **`Manifest.db`** — a SQLite database that maps each backed-up file to its original path, domain, and the hashed filename it's stored under. This is the master index. (In encrypted backups this is itself encrypted.)
- **`Manifest.plist`** — metadata about the backup, including whether it's encrypted, the applications installed, and the keybag.
- **`Status.plist`** — backup status (whether it completed, snapshot state, backup type: full/incremental).
- **`Info.plist`** — device metadata (device name, model, iOS version, phone number, installed apps, last backup date, IMEI/serial).
- **Hashed content files** — the actual backed-up files, each renamed to a **SHA-1 hash** of its domain + relative path, and organized into subfolders named by the first two hex characters of that hash (e.g., a file's hash `3d0d7e5fb2ce288813306e4d4636395e047a3d28` lives in a folder named `3d/`).

So to reconstruct meaningful data, a tool reads `Manifest.db`, looks up the original path and domain for each hash, and maps the opaque hashed files back to their logical names like `sms.db` or an app's data container.

The concept of a **domain** is key: files are grouped into domains such as `HomeDomain`, `CameraRollDomain`, `AppDomain-<bundleid>`, `KeychainDomain`, `WirelessDomain`, etc. The domain plus the relative path within it is what gets hashed into the filename.

## Handling Backup Data

Practically working with backup data involves parsing the structure above and extracting the artifacts that matter. The general workflow:

1. **Locate the backup.** On macOS: `~/Library/Application Support/MobileSync/Backup/`. On Windows: `\Users\<user>\AppData\Roaming\Apple Computer\MobileSync\Backup\` (or the Microsoft Store location for the Store version of iTunes).
2. **Assess encryption.** Read `Manifest.plist` to check the `IsEncrypted` flag. If encrypted, decryption/password recovery must happen first.
3. **Parse `Manifest.db`.** Query the `Files` table, which contains `fileID` (the hash), `domain`, `relativePath`, and a `file` blob (a binary plist of file metadata including size, timestamps, and the protection class / encryption key).
4. **Map and extract.** For each file of interest, use the `fileID` to locate the hashed file on disk, decrypt if needed, and write it out with its real path.
5. **Parse the artifacts.** Open the recovered SQLite databases and plists and interpret them.

Key high-value targets in backup data:

- **`sms.db`** (HomeDomain, `Library/SMS/sms.db`) — SMS and iMessage, with the `message`, `chat`, `handle`, and `attachment` tables. Timestamps are in Mac absolute time (seconds since 2001-01-01), often in nanoseconds on newer versions.
- **`AddressBook.sqlitedb`** — contacts.
- **`CallHistory.storedata`** — call logs (only in encrypted backups on modern iOS).
- **`Calendar.sqlitedb`** — events.
- **`Photos.sqlite`** — photo metadata, including EXIF, geolocation, and album membership.
- **Safari** `History.db` and `Bookmarks.db` — browsing history.
- **`knowledgeC.db`** — the aggregated device-usage/knowledge store.

## Handling Backup Data — 2

Building on the above, deeper handling of backup data involves the harder problems: decryption internals, timestamp normalization, deleted-record recovery, and third-party app parsing.

**Decryption internals.** For encrypted backups, the flow is:
- `Manifest.plist` contains a **keybag** (a `BackupKeyBag`) with wrapped class keys.
- The backup password, run through PBKDF2 (double-hashed with the newer high iteration counts), derives a key that unwraps the keybag.
- Each file's metadata (in the `Manifest.db` `file` blob) contains a wrapped per-file key referencing a protection class; that class key from the keybag unwraps the per-file key, which then decrypts the file with AES.
- `Manifest.db` itself is encrypted with a key stored (wrapped) in `Manifest.plist`, so you must decrypt the manifest first before you can even see the file index.

**Timestamp normalization.** iOS mixes several time formats and examiners must convert carefully:
- **Mac Absolute Time / Cocoa Core Data time** — seconds since 2001-01-01 00:00:00 UTC (some tables store nanoseconds).
- **Unix epoch** — seconds since 1970-01-01.
- **WebKit/Chrome time** — microseconds since 1601-01-01 (appears in some browser artifacts).
- **APFS timestamps** — nanoseconds since Unix epoch.
Getting these wrong produces timelines that are off by decades, so this is a common and consequential error.

**Deleted-record recovery.** SQLite doesn't immediately overwrite deleted rows. Examiners recover deleted data from:
- **Freelist pages and unallocated space** within the database file.
- **The WAL file**, which may contain older or newer versions of records not yet checkpointed into the main DB.
- **Journal files.**
Tools and manual carving can recover deleted messages, call entries, etc., from these areas — a frequent source of critical evidence.

**Third-party app parsing.** Backups include app data containers (`AppDomain-<bundleid>`), but every app stores data differently. Investigators must reverse-engineer the schema of messaging apps (WhatsApp, Signal, Telegram, Snapchat), each of which uses its own SQLite databases, plists, and sometimes its own encryption. WhatsApp's `ChatStorage.sqlite`, for example, is a well-documented target; Signal deliberately encrypts its local store, making it much harder.

**Validation and integrity.** Sound practice throughout: hash the backup and extracted files, document tool versions, and where possible verify findings across multiple tools, since parsers can and do misinterpret evolving schemas.

---

A few honest caveats worth flagging. This field moves quickly — Apple changes data-protection behavior, iCloud encryption, and backup cryptography with nearly every major iOS release, and exploit-based acquisition (checkm8, various jailbreaks, commercial agents) is a constant cat-and-mouse. Specific version thresholds (iteration counts, which artifacts land in encrypted vs. unencrypted backups, ADP behavior) can shift, so for anything you're relying on operationally or in court, verify against current tool documentation and primary sources rather than treating the above as fixed.

## 1. The Data Protection class system

This is the foundation everything else sits on, so it's worth understanding precisely.

Every file on iOS is encrypted with its own **per-file key** (sometimes called the file key). That key is not stored in the clear — it's wrapped (encrypted) by a **class key**. The class key determines *when* the file is accessible. The class keys themselves are stored in the **system keybag**, and most of them are wrapped by a key derived from the user's passcode entangled with a hardware key (the UID key) baked into the Secure Enclave / AES engine. That hardware entanglement is why you can't just copy the flash off the board and decrypt it elsewhere — the UID key never leaves the silicon.

The main protection classes:

- **NSFileProtectionComplete** — the file key is wrapped such that it's only available while the device is unlocked. A few seconds after lock, the decrypted class key is evicted from memory. This data is unreachable in a locked state.
- **NSFileProtectionCompleteUnlessOpen** — accessible while unlocked, and stays accessible if the file was already open when the device locked (uses ephemeral key agreement so a background download can finish). 
- **NSFileProtectionCompleteUntilFirstUserAuthentication** — this is the **default** for most third-party app data. The class key stays available in memory from the first unlock after boot until the device powers off. It does *not* get evicted on subsequent locks.
- **NSFileProtectionNone** — the class key is wrapped only by the UID key, so it's available even before first unlock, as long as the device is powered on.

This directly produces the **BFU vs AFU** distinction, which is the single most important operational concept in modern iOS acquisition:

- **BFU (Before First Unlock)** — device powered on but the passcode has not been entered since boot. Only `NSFileProtectionNone` (and complete-unless-open in some edge cases) class keys are available. You get very little: some system logs, limited metadata, but essentially no messages, photos, or app data.
- **AFU (After First Unlock)** — the passcode has been entered at least once since boot and the device hasn't been powered off. Now the `CompleteUntilFirstUserAuthentication` keys are resident in memory. The vast majority of user data becomes accessible, even if the device subsequently re-locks.

The forensic implication: **when you seize a device, keep it powered and charged, and do not let it power off or reboot**, because a running AFU device is dramatically more valuable than one that has dropped to BFU. This is also why Faraday bags plus power are standard seizure practice.

The Keychain has its own parallel set of classes with the same semantics (`kSecAttrAccessibleWhenUnlocked`, `...AfterFirstUnlock`, `...Always` (deprecated), and the `ThisDeviceOnly` variants which are additionally bound to the UID so they never sync or restore to another device).

## 2. The Manifest.db schema and a working extraction approach

For an unencrypted backup, `Manifest.db` is a plain SQLite file. The core table is `Files`:

```sql
CREATE TABLE Files (
    fileID      TEXT PRIMARY KEY,   -- SHA-1 of "domain-relativePath"
    domain      TEXT,               -- e.g. HomeDomain, AppDomain-net.whatsapp.WhatsApp
    relativePath TEXT,              -- e.g. Library/SMS/sms.db
    flags       INTEGER,            -- 1 = file, 2 = directory, 4 = symlink
    file        BLOB                -- an NSKeyedArchiver binary plist of metadata
);
```

The `fileID` is `SHA1(domain + "-" + relativePath)` as lowercase hex. So the Messages database, which lives in domain `HomeDomain` at relative path `Library/SMS/sms.db`, hashes to `3d0d7e5fb2ce288813306e4d4636395e047a3d28`. On disk in the backup folder, that file sits at `3d/3d0d7e5fb2ce288813306e4d4636395e047a3d28` (subfolder = first two hex chars). That constant hash is worth memorizing because it's the same on every iPhone.

The `file` BLOB is the subtle part. It's an `NSKeyedArchiver`-serialized binary plist (a `MBFile` object) that contains an objects array. Inside it you'll find the file's `Size`, `Mode` (Unix permissions), `UserID`, `GroupID`, the three timestamps (`LastModified`, `LastStatusChange`, `Birth`), the **`ProtectionClass`**, and — for encrypted backups — an **`EncryptionKey`** blob (the wrapped per-file key). To parse it you can't just read it as a normal plist; you have to resolve the `$objects`/`$top` keyed-archiver references (the `ccl_bplist` library, or `nska_deserialize` helpers, handle this).

A minimal extraction of an *unencrypted* backup looks like this:

```python
import sqlite3, os, shutil

BACKUP_DIR = "/path/to/backup/<udid>"
OUT_DIR = "/path/to/output"

db = sqlite3.connect(os.path.join(BACKUP_DIR, "Manifest.db"))
db.row_factory = sqlite3.Row

for row in db.execute(
    "SELECT fileID, domain, relativePath, flags FROM Files WHERE flags = 1"
):
    file_id = row["fileID"]
    src = os.path.join(BACKUP_DIR, file_id[:2], file_id)
    if not os.path.exists(src):
        continue
    # Rebuild a human-readable path
    dst = os.path.join(OUT_DIR, row["domain"], row["relativePath"])
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
```

That reconstructs the whole backup into a readable directory tree keyed by domain and original path. The excellent open-source tool **iOSbackup** (Python) and **iLEAPP** do exactly this plus the metadata parsing, and are worth using rather than reinventing — but knowing the mechanism lets you validate what they report.

To pull just the Messages DB you'd filter `WHERE domain='HomeDomain' AND relativePath='Library/SMS/sms.db'`, copy it out, and open it — remembering to grab `sms.db-wal` and `sms.db-shm` too (they hash from the same domain with `-wal`/`-shm` appended to the relative path).

## 3. Decrypting an encrypted backup (the full crypto flow)

For encrypted backups you can't even read `Manifest.db` until you've done the key derivation, because the manifest itself is encrypted. The chain:

**Step 1 — the keybag.** `Manifest.plist` contains a `BackupKeyBag` blob. It's a TLV (type-length-value) structure. Parsing it yields, per protection class, a `WPKY` (wrapped class key), a wrapping type `WRAP`, plus the KDF parameters: `SALT`, `ITER` (PBKDF2 iteration count), and for iOS 10.2+ a second-round `DPSL` (double-protection salt) and `DPIC` (double-protection iteration count).

**Step 2 — derive the passcode key.** Newer backups use a two-stage derivation:

```
inner = PBKDF2-SHA256(password, DPSL, DPIC)         # the expensive stage
key   = PBKDF2-SHA1(inner, SALT, ITER, dkLen=32)    # 32-byte KEK
```

The `DPIC` here is the ~10,000,000 iterations Apple introduced, and it's deliberately the *first* stage so an attacker pays the full cost per password guess. This is why post-10.2 backup passwords are effectively unbreakable unless weak or known.

**Step 3 — unwrap the class keys.** For each class entry, use RFC 3394 AES key unwrap with the derived KEK to turn each `WPKY` into a plaintext class key.

**Step 4 — decrypt the manifest.** `Manifest.plist` has a `ManifestKey` — its first 4 bytes are the protection class number, the rest is the wrapped key. Unwrap it with the matching class key, then AES-CBC decrypt `Manifest.db` with it. Now you have the file index.

**Step 5 — decrypt individual files.** Each file's `EncryptionKey` (from its `file` BLOB metadata) is likewise `[class(4 bytes)][wrapped key]`. Unwrap with the class key, then AES-CBC decrypt the on-disk hashed file. Note the file's stored `Size` is the true plaintext length — you truncate the decrypted output to it because CBC pads to the block boundary.

The `iOSbackup` library and Elcomsoft's tools implement all of this; if you're doing it yourself, the historical reference implementation is Zdziarski's and the `iphone-dataprotection` project, and `impacket`/`cryptography` give you the AES-unwrap primitives.

## 4. SQLite and WAL: recovery and the WAL mechanics

This is where a lot of "deleted" evidence actually comes from.

**Why WAL matters.** In WAL mode, SQLite doesn't write changes straight into the main `.db` file. It appends new page images to the `-wal` file, and a checkpoint later folds them back into the main file. Two consequences for forensics:

- The *newest* version of a record may exist **only in the WAL**, not the main DB. If your tool opens the DB without the WAL present (or copies the DB but not the sidecar), you miss recent messages.
- The WAL can hold **multiple historical versions of the same page**, so you can sometimes recover a record's prior state — including rows that were later deleted.

The WAL is a header plus a series of frames; each frame is a 24-byte frame header plus one full page image. The frame header includes the page number and two salt/checksum values, and a frame with a nonzero "commit" size marks a transaction boundary. A frame is only valid (would be replayed) if its checksums match the running checksum seeded by the WAL header salts — invalid/superseded frames are exactly the interesting leftover material.

**Where deleted rows hide within the main DB:**

- **Freelist pages** — when content is deleted, pages can be moved to a freelist; their old content often remains until reused.
- **Unallocated space inside a page** — SQLite tracks a cell-content area and free blocks within each B-tree page. A deleted row's cell frequently survives in that intra-page free space, sometimes fully intact, sometimes with the header partially overwritten.
- **Fragmented/overflow pages** — long values stored on overflow pages can persist.

**Practical recovery workflow:**

1. Always capture the `.db`, `-wal`, and `-shm` together, hash all three.
2. First, read the DB *with* the WAL applied to get current state (just open it normally; SQLite replays automatically if the sidecars are present and compatible).
3. Then analyze the WAL separately for superseded frames — tools like **`walitean`**, the SANS **`sqlite-parser`**/`undark`, **`bring2lite`**, and Sanderson's Forensic Toolkit for SQLite carve these.
4. Carve the main DB's freelist and page slack with a tool like `undark` or by parsing the B-tree yourself.
5. Correlate recovered `ROWID`s and foreign keys (e.g., a recovered `message.handle_id` back to the `handle` table) to reattribute orphaned rows to conversations.

A concrete example in `sms.db`: a deleted iMessage may be gone from the live `message` table but present in a WAL frame containing the older page image, or recoverable from page slack. Its `date` column is Mac absolute time in nanoseconds (post-iOS 11), and its `handle_id` links to the phone number/email in `handle`. Recovering the row is only half the job — reattributing and timestamp-converting it correctly is the other half.

## 5. iCloud token acquisition and cloud specifics

Cloud acquisition splits into "with password" and "with token," and the token path is what makes it interesting.

**The authentication token approach.** When a user signs into iCloud on a desktop (notably iCloud for Windows, or macOS), the OS stores authentication material locally so it doesn't re-prompt constantly. Forensic tools (Elcomsoft Phone Breaker being the classic) can harvest that material from the live or imaged computer and reuse it to talk to iCloud *without* the Apple ID password and *without* triggering 2FA, because the token already represents an authenticated, trusted session.

Practical realities that have tightened over time:

- Tokens are **short-lived** and Apple has repeatedly reduced their validity window and the scope of what a token alone can pull (full backups increasingly require the password, not just a token).
- The token is bound to context, so you generally extract it from the specific machine where the user was signed in (from the user's live session or a decrypted image), not from arbitrary locations.
- With password + 2FA, you need either a trusted device to approve, an SMS/authenticator code, or in some tools the ability to use the device passcode/screen-lock as the second factor to unlock certain end-to-end categories.

**What lives where in iCloud** matters because backups and synced data are separate:

- An **iCloud Backup** is a snapshot bundle, historically decryptable by Apple (pre-ADP) because Apple held the keys — which is why law-enforcement warrants to Apple were productive.
- **Synced categories** (Photos, Notes, iCloud Drive, Safari, Contacts, Calendars) sync continuously and independently. Some, like iCloud Keychain and Health, have always been end-to-end encrypted and require the passcode/device secret in the derivation.

**Advanced Data Protection (ADP)** is the game-changer for the legal-process route. With ADP on, the previously-Apple-holdable categories (including iCloud Backup, Photos, Notes, and more) become end-to-end encrypted, so Apple can no longer produce their contents under warrant — the keys are held only by the user's trusted devices. For an ADP account, cloud acquisition effectively collapses back to needing the user's own credentials plus a trusted device or recovery key. A handful of categories remain non-E2EE even under ADP for interoperability reasons (notably iCloud Mail, Contacts, and Calendar, because they use open protocols like IMAP/CalDAV), which is a useful detail to know.

## Timestamp reference (since it trips everyone up)

Getting this wrong produces timelines off by decades, so keep a conversion table handy:

| Format | Epoch | Unit | Seen in |
|---|---|---|---|
| Mac Absolute / Cocoa Core Data | 2001-01-01 UTC | seconds (or ns post-iOS 11) | `sms.db`, most Apple DBs |
| Unix epoch | 1970-01-01 UTC | seconds / ms | many third-party apps |
| WebKit | 1601-01-01 UTC | microseconds | Safari/Chrome-derived |
| APFS | 1970-01-01 UTC | nanoseconds | filesystem metadata |
| `knowledgeC` | 2001-01-01 UTC | seconds (float) | usage analytics |

The classic gotcha is a `sms.db` `date` value like `690595200000000000` — that's nanoseconds since 2001, so you divide by 1e9 before adding to the 2001 epoch, whereas an older backup stores the same field in plain seconds. Blindly applying one rule mangles the other.

---

Two honest caveats again, because they matter for anything operational: the version thresholds (PBKDF2 iteration counts, which artifacts land in encrypted backups, exactly what ADP does and doesn't cover, token validity) shift with Apple's releases, and the specific column names in databases like `sms.db`/`Photos.sqlite` change across iOS versions — the `chat_message_join` structure and the photo asset schema have both been reworked more than once. So treat the schemas above as representative rather than eternal, and confirm against the actual DB version in front of you. For court-bound work, validating findings across at least two independent tools is standard for exactly this reason.
