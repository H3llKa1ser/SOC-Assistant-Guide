# Windows Disk Forensics: Foundations and Six Key Artifacts

---

## Part 1: The Foundations

### Acquisition and handling

Disk forensics starts with a defensible copy. The traditional approach is a physical image through a hardware write blocker, captured as raw (dd) or Expert Witness (E01) format with tools like FTK Imager, Guymager, or ewfacquire. You hash the image (MD5 and SHA-1/SHA-256) at acquisition and on every verification.

In incident response, full imaging is often replaced by **triage collection**. KAPE or Velociraptor pulls just the high-value artifacts from a live system using raw NTFS access, which bypasses file locks on files like `SRUDB.dat`, registry hives, and `$MFT`.

Three things complicate modern acquisitions:

- **BitLocker** is on by default on many Windows 11 devices. You need the recovery key, or an image taken while the volume is unlocked.
- **Volume Shadow Copies (VSS)** hold point-in-time snapshots of the volume. Every artifact below may have older versions sitting in shadow copies, which is often where the deleted history lives.
- **Memory** should be captured first when the system is live. It holds decrypted keys, running processes, and data that never touched disk.

### NTFS internals

NTFS is where much of the ground truth lives.

- **`$MFT`** (Master File Table) holds a record for every file. Each record has two sets of timestamps. `$STANDARD_INFORMATION` is easily altered by user-mode timestomping tools. `$FILE_NAME` is maintained by the kernel and is much harder to tamper with.
- **`$UsnJrnl:$J`** (the USN change journal) logs creates, deletes, renames, and data changes. It is invaluable for proving a file existed and what happened to it.
- **`$LogFile`** is the transactional log for metadata changes. It covers a shorter window than the USN journal but at a finer grain.
- **`$I30` index attributes** on directories can retain slack entries for files that have been deleted.
- **Alternate Data Streams**, especially `Zone.Identifier`, record the Mark of the Web: the source URL and zone for downloaded files.

Tools for these include MFTECmd, which parses `$MFT`, `$J`, `$LogFile`, `$Boot`, and `$SDS`. The Sleuth Kit, Autopsy, and X-Ways cover them too.

### The registry

The core hives are `SAM`, `SYSTEM`, `SOFTWARE`, and `SECURITY` in `C:\Windows\System32\config`. Per-user hives are `NTUSER.DAT` in the profile root and `UsrClass.dat` in `AppData\Local\Microsoft\Windows`. `Amcache.hve` sits in `C:\Windows\AppCompat\Programs`.

Always process hives together with their transaction logs (`.LOG1`/`.LOG2`), because dirty hives can be missing recent data. Registry Explorer, RECmd, and RegRipper are the standard tools.

### Artifact categories

Most practitioners organize artifacts by the question they answer.

**Evidence of execution:**
- Prefetch (`C:\Windows\Prefetch\*.pf`): run count and up to 8 last-run times on Win8+.
- Amcache: SHA-1 of executables.
- Shimcache/AppCompatCache in the SYSTEM hive: indicates presence, and execution with caveats.
- BAM/DAM: last execution per user SID.
- UserAssist: GUI launches, ROT13-encoded.
- SRUM.
- Event ID 4688, if process auditing is enabled.

**File and folder knowledge/opening:**
- LNK files in `Recent`.
- Jumplists.
- ShellBags in `UsrClass.dat`, covering folders browsed, including on removed USB and network drives.
- RecentDocs, OpenSaveMRU, and LastVisitedMRU.
- Office MRUs.
- The Search Index and Thumbnail Cache.

**Deleted files:**
- Recycle Bin.
- `$MFT` unallocated records.
- USN journal.
- VSS.
- Carving of unallocated space.

**External devices:**
- USBSTOR and USB keys in SYSTEM.
- MountedDevices.
- `setupapi.dev.log`.
- The Partition/Diagnostic event log (ID 1006, which records volume boot sectors).
- Windows Portable Devices.
- Volume serial numbers inside LNK files and Jumplists, which tie files to specific devices.

**Account and logon activity:**
- SAM, and Security event log IDs 4624/4625/4634/4672/4720.
- For RDP, the specific logs covered in the RDP section.

**Network and cloud:**
- NetworkList profiles in SOFTWARE and WLAN profiles.
- SRUM network tables.
- Browser databases.
- OneDrive logs and `SyncEngineDatabase.db`.

**Timeline:**
- ActivitiesCache.db, used by Windows 10's Timeline feature and largely deprecated since.
- Plaso/log2timeline super-timelines, which combine everything.

The core discipline is **corroboration**. No single artifact is conclusive. A strong finding is one where Prefetch, SRUM, a Jumplist, and the USN journal all tell the same story.

---

## Part 2: Deep Dives

### 1. SRUM (System Resource Usage Monitor)

**What it is.** SRUM was introduced in Windows 8 to feed the Task Manager "App history" tab and battery/data-usage settings. It records per-application, per-user resource consumption. Forensically, it is one of the best sources for **data exfiltration volume**, **evidence of execution** for programs long since deleted, and **network connectivity history**.

**Location and format.**
- Database: `C:\Windows\System32\sru\SRUDB.dat`, an Extensible Storage Engine (ESE / "JET Blue") database.
- The same folder holds the transaction logs (`SRU*.log`, `SRUtmp.log`) and the checkpoint file `SRU.chk`.

**How data gets there.** The Diagnostic Policy Service (DPS) runs SRUM providers that collect data continuously. The data is buffered and flushed into the database roughly **every hour**, and at shutdown. Some pending data sits temporarily in the registry under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SRUM\Extensions`. The provider GUIDs used as table names are also registered there.

**Retention.** Typically around **30 days** for most tables. Energy "long-term" tables hold more. Older data may survive in Volume Shadow Copies.

**Key tables.** Table names are provider GUIDs:

| GUID | Provider | Forensic value |
|---|---|---|
| `{973F5D5C-1D90-4944-BE8E-24B94231A174}` | Network Data Usage | BytesSent / BytesRecvd per app, per user, per interface |
| `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}` | Application Resource Usage | Foreground/background CPU cycle time, bytes read/written |
| `{DD6636C4-8929-4683-974E-22C046A43763}` | Network Connectivity | Connected time per network profile (which Wi-Fi, how long) |
| `{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}` | Push Notifications | App notification activity |
| `{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}` (and `...LT`) | Energy Usage / Long-Term | Battery and charge state |
| `{5C8CF1C7-7257-4F13-B223-970EF5939312}` | App Timeline | Per-app activity timelines (Win10+) |
| `SruDbIdMapTable` | ID map | Resolves integer AppId/UserId values to app paths/names and SIDs |

**Important columns.**
- Every provider table has `TimeStamp`, `AppId`, and `UserId`.
- The network table adds `InterfaceLuid` and `L2ProfileId`. The upper bits of the LUID encode the IANA interface type: 71 is 802.11 wireless, 6 is Ethernet.
- `L2ProfileId` links to the WLAN profile, so you can say "this app sent 4 GB while connected to SSID `CoffeeShop_Guest`." To resolve it, use the SOFTWARE hive (`Microsoft\WlanSvc\Interfaces` and `NetworkList\Profiles`) or the profile XML files in `C:\ProgramData\Microsoft\Wlansvc\Profiles`.

**Critical interpretation caveats.**
- **`TimeStamp` is when the record was written**, usually at the hourly flush, not when the activity started. Treat each row as "during the hour ending at approximately this time."
- Values are aggregated. You cannot tell whether 2 GB went to one destination or many, or what the destinations were. SRUM records volume only, not endpoints.
- AppIds can be full paths for executables, service names, or UWP package names.
- Data for the current hour may not yet be committed on a live box.
- SRUM is not reliably populated on Windows Server editions.

**Processing.** The database is usually "dirty" when collected from a live or crashed system.
1. Check its state with `esentutl /mh SRUDB.dat`.
2. If it reports a dirty shutdown, copy the whole `sru` folder and run `esentutl /r sru /i` inside it to replay the logs.
3. Use `/p` (repair) only as a last resort, on a copy, because it can discard data.

Parsers:
- **SrumECmd** (Eric Zimmerman): pass the SOFTWARE hive too, for network name resolution.
- **srum-dump** (Mark Baggett): produces an Excel workbook.
- **NirSoft ESEDatabaseView**: for raw browsing.
- **Velociraptor**: has SRUM artifacts.

**Classic use cases.**
- Proving that `rclone.exe` or `7z.exe` ran and pushed large volumes outbound, even after the attacker deleted the binary and Prefetch was disabled.
- Tying activity to a specific user SID.
- Showing that a laptop connected to an unusual network.
- Detecting mining malware through high background CPU cycles.

---

### 2. Jumplists

**What they are.** Introduced in Windows 7, Jumplists power the recent and pinned items shown when you right-click a taskbar or Start icon. Each application gets its own list. Forensically, they are **per-application records of files and resources a user opened**, with rich embedded metadata and often long persistence.

**Location** (per user):
- `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations\<AppID>.automaticDestinations-ms`
- `%APPDATA%\Microsoft\Windows\Recent\CustomDestinations\<AppID>.customDestinations-ms`

**AppIDs.** The 16-hex-character filename identifies the application. For most apps it is a CRC-64-based hash of the application's path, or of its explicit AppUserModelID if it sets one. Well-known examples:
- `1b4dd67f29cb1962`: Windows Explorer pinned/recent (Win7 era).
- `5f7b5f1e01b83767`: Quick Access (Win10+).
- `9b9cdc69c1c24e2b`: 64-bit Notepad.

Because the hash depends on the install path, the same app installed in a nonstandard location gets a different AppID. Always check against a maintained AppID list, such as the one bundled with JLECmd/EZ Tools or the Forensics Wiki list, and treat unknown AppIDs as leads.

**AutomaticDestinations format.** Each file is an **OLE Compound File** (a CFB structured storage container, the same container as legacy .doc files). Inside:
- **Numbered streams** (`1`, `2`, `a`, ...) are each a complete **Shell Link (LNK)** structure for one item.
- **The `DestList` stream** holds the MRU/MFU metadata for every entry:
  - Entry number, which maps to the stream name.
  - Last-access FILETIME for that entry, i.e. when the user last opened the item via that app.
  - Access count (Win10+), pinned status, and the NetBIOS name of the machine where the target lived.
  - **Droid volume and file identifiers** (distributed link tracking object IDs). These can embed the MAC address of the machine that created them and a timestamp encoded in the UUIDv1.
  - The target path.

  The DestList header version changed across Windows versions, so parsers must handle this. Win10 introduced version 3 and later 4.

**What each embedded LNK gives you:**
- The target file's own created/modified/accessed timestamps at the time the LNK was written.
- File size and full path, or the network share path.
- **Volume serial number, drive type, and volume label.** This lets you link a file opened from a USB stick to the specific device seen in USBSTOR.
- The MFT entry and sequence number of the target.
- A TrackerDataBlock with the machine ID (NetBIOS name) and droid IDs.

**CustomDestinations.** These are application-defined lists, such as a browser's "Frequent" sites or pinned tasks. The format is simpler: a header followed by concatenated LNK structures, delimited by a footer signature (`0xBABFFBAB`). No DestList exists here. Parse the LNKs individually, or carve them.

**Why investigators love them:**
- **Persistence.** Entries survive deletion of the target file, and often survive uninstallation of the app. An entry proves the user opened `Q3_customer_export.xlsx` from `E:\` even though both the file and the drive are gone.
- **Two timestamp perspectives.** DestList gives when the user interacted with the item. The LNK gives the target file's own MACB times.
- **Per-application context.** You know which program opened the file: WinRAR, Notepad++, mstsc, or VLC.
- **Remote access.** The Remote Desktop client's Jumplist shows RDP destinations.

**Caveats.**
- Lists are capped. Oldest unpinned entries roll off; the default is about 10–20 items per app, depending on configuration.
- Users can clear them. Group Policy or registry settings can disable recent-item tracking (`Start_TrackDocs` = 0).
- Not every app implements Jumplists well.

**Tools:**
- **JLECmd** and **JumpList Explorer** (Zimmerman).
- **LECmd**, for standalone LNKs.
- Any OLE viewer, such as SSView, for manual stream inspection.

---

### 3. Recycle Bin Artifacts

**The evolution:**

| Windows version | Folder | Metadata |
|---|---|---|
| 95/98/ME | `C:\RECYCLED` | `INFO` / `INFO2` |
| NT/2000/XP/2003 | `C:\RECYCLER\<SID>\` | `INFO2`; files renamed `Dc<n>.<ext>` (D + drive letter + index) |
| Vista through Win11 | `C:\$Recycle.Bin\<SID>\` | Paired `$I` / `$R` files per deleted item |

Each volume has its own Recycle Bin folder, and the **SID subfolder** attributes the deletion to a user account. Map SIDs to usernames via the SAM hive or the `ProfileList` key in SOFTWARE.

**Vista+ mechanics.** When a user deletes `C:\Users\bob\Documents\plans.docx` normally (not Shift+Delete), Windows:
1. **Renames** the file, which stays on the same volume, to `$R` + 6 random characters + the original extension, e.g. `$RX7K2QA.docx`. The content is untouched. This is a move, not a copy, so the `$STANDARD_INFORMATION` timestamps are generally preserved and the `$FILE_NAME` timestamps update.
2. **Creates** a companion `$IX7K2QA.docx` holding the metadata.

**`$I` file structure.**

*Vista/7/8/8.1 (version 1): fixed 544 bytes*

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Header/version (1) |
| 8 | 8 | Original file size |
| 16 | 8 | Deletion time (FILETIME, UTC) |
| 24 | 520 | Original path, UTF-16LE, fixed length |

*Windows 10/11 (version 2): variable length*

| Offset | Size | Field |
|---|---|---|
| 0 | 8 | Header/version (2) |
| 8 | 8 | Original file size |
| 16 | 8 | Deletion time (FILETIME, UTC) |
| 24 | 4 | Path length in characters (including null) |
| 28 | var | Original path, UTF-16LE |

**XP `INFO2`.** A single file with a header followed by fixed 800-byte records, one per deleted item. Each record holds the ANSI path (260 bytes), record index, drive number, deletion time, size, and Unicode path (520 bytes).

**Deleted folders.** The `$R` item becomes a directory, and everything inside it **keeps its original names**. So a deleted folder shows its full contents, which is useful when a user deletes an entire staging directory.

**What bypasses the Recycle Bin:**
- Shift+Delete.
- `del` or `rd` in cmd, and `Remove-Item` in PowerShell.
- Most programmatic deletions.
- Files too large for the bin's configured capacity.
- Deletions from removable flash media, which Windows typically deletes directly. Many external hard drives and fixed volumes do get a `$Recycle.Bin`.
- Network shares.

Per-volume settings live under `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\BitBucket\Volume\{GUID}` (`MaxCapacity`, `NukeOnDelete`).

**After the bin is emptied.** The `$I` and `$R` files are deleted, but you can still work with:
- **`$MFT` records** for `$I`/`$R` entries, which may remain in unallocated MFT space. Small `$I` files are often **MFT-resident**, so their content survives in the record itself.
- **USN journal** rename entries showing `plans.docx` becoming `$RX7K2QA.docx`, then the later deletions. This reconstructs the deletion and emptying timeline.
- **`$I30` slack** in the SID folder's index.
- **Volume Shadow Copies** containing earlier states of `$Recycle.Bin`.
- **Carving** of the `$R` content from unallocated clusters, if not yet overwritten.

**Interpretation notes.**
- The `$I` deletion time is when the item went into the bin. It is not when the bin was emptied; for that, use USN or MFT.
- Restoring an item removes the pair, so an item's absence doesn't mean it was never deleted.
- Deletion of evidence-relevant files shortly after a triggering event, such as an HR notice or a security alert, is a classic intent indicator.

**Tools:**
- **RBCmd** (Zimmerman): handles `$I` and INFO2.
- **Rifiuti2**.
- Autopsy/X-Ways/Axiom have built-in parsing.

---

### 4. Windows Search Index

**What it is.** The Windows Search service (`WSearch`, process `SearchIndexer.exe`) crawls configured locations and builds a database of file metadata. Sometimes it also stores extracted content. The index also covers Outlook mailboxes in cached mode, OneNote, and historically IE/legacy Edge history.

Forensically, it can prove that **files existed at a path, with specific metadata, even after deletion**, and sometimes preserves **snippets of their content**.

**Location and format.** The base is `C:\ProgramData\Microsoft\Search\Data\Applications\Windows\`. The data directory is configurable via `HKLM\SOFTWARE\Microsoft\Windows Search` (`DataDirectory`).

*Windows 7/8/10:*
- `Windows.edb`: an ESE database, like SRUM.
- Transaction logs `MSS*.log` and checkpoint `MSS.chk`.

*Windows 11 (and some late Win10 builds):* migrated to **SQLite**:
- `Windows.db`: property store.
- `Windows-gather.db`: gather and crawl data.
- Associated `-wal` and `-shm` files, which hold uncommitted data and must be collected alongside the databases.

*Full-text inverted index:* `...\Projects\SystemIndex\Indexer\CiFiles\` (`*.ci`, `*.wid`, `*.dir`). This part is far less commonly parsed.

**Key tables (ESE).**
- **`SystemIndex_PropertyStore`** (named `SystemIndex_0A` on Win7): the main table. One row per indexed item, with columns for Windows properties. Column names are prefixed with numeric IDs, e.g. `4447-System_ItemPathDisplay`. Interesting properties include:
  - `System.ItemPathDisplay` and `System.ItemName`.
  - `System.DateCreated`, `DateModified`, and `DateAccessed`.
  - `System.Size` and `System.FileOwner`.
  - `System.Author`, `System.Title`, and `System.Company` (document metadata).
  - `System.Search.AutoSummary`: an extracted **text snippet** from the document or email.
  - Email fields: sender, recipients, subject, sent/received times.
  - **`System.ThumbnailCacheId`**: the key for correlating with the Thumbnail Cache (see section 6).
- **`SystemIndex_Gthr`**: gather table with DocumentID, ScopeID, filename, last-modified, and crawl status.
- **`SystemIndex_GthrPth`**: the scope/path hierarchy used to rebuild full paths from Gthr entries.

In Windows 11 SQLite, the property store is normalized. Rows are keyed by WorkId and property ID, and must be pivoted to rebuild records. This is why dedicated tools matter.

**What gets indexed.** By default ("Classic" mode) only the user profile libraries, the Start Menu, and a few other locations are indexed, not the entire C: drive. Removable drives are not indexed by default. "Enhanced" mode indexes the whole PC. Check the configured crawl scopes in the registry (`Gathering Manager\Applications\Windows\GatheringSet\...`) before concluding a file wasn't there. The service is disabled by default on Windows Server.

**Forensic value:**
- **Deleted files.** Records persist until the indexer notices the deletion and processes it. Even then, deleted rows often remain in ESE dirty/free pages or SQLite freelists and WAL, and are recoverable.
- **Email evidence.** Subjects, senders, and snippets from `.ost` content, even if the mailbox was later deleted.
- **Content snippets.** AutoSummary can hold text from a document that no longer exists.
- **Thumbnail attribution.** Maps thumbnail cache entries back to file paths.
- **User attribution.** Items in `C:\Users\<name>` paths, plus file owner properties.

**Processing notes.**
- As with SRUM, check the ESE state (`esentutl /mh`) and recover with `esentutl /r MSS /i` in a copied folder.
- On a live system the database is locked, so use VSS or raw copy.
- Files can be multiple gigabytes.

**Tools:**
- **SIDR (Search Index DB Reporter)**: handles both ESE and Win11 SQLite.
- **WinSearchDBAnalyzer**: notable for recovering deleted ESE records.
- **ESEDatabaseView**, and ESE carving tools for deleted records.
- Velociraptor artifacts.
- A SQLite browser for Windows 11 databases, if you're willing to pivot manually.

---

### 5. RDP Bitmap Cache

**What it is.** To save bandwidth, the Microsoft Remote Desktop client (`mstsc.exe`) caches screen tiles from the remote session to disk. This is "Persistent bitmap caching," enabled by default on the Experience tab and set by `bitmapcachepersistenable:i:1` in `.rdp` files.

The critical point: **the cache lives on the client, i.e. the source machine**. If an attacker pivots through compromised host A to reach host B, host A's disk holds image fragments of what the attacker saw on host B. This can include admin consoles, file listings, command prompts, and sometimes typed text.

**Location** (per user): `%LOCALAPPDATA%\Microsoft\Terminal Server Client\Cache\`

| File | Era |
|---|---|
| `bcache2.bmc`, `bcache22.bmc`, `bcache24.bmc` | Older clients (RDP 6 and earlier); number reflects color depth |
| `Cache0000.bin`, `Cache0001.bin`, ... | RDP 7+ (Win7 onward) |

**Format (Cache####.bin).**
- A small file header with the signature `RDP8bmp` and a version.
- Then a sequence of tiles. Each has a 12-byte header (an 8-byte key, 2-byte width, 2-byte height) followed by raw 32-bit BGRA pixel data.
- Tiles are typically **64×64 pixels**.
- The cache is size-capped and recycles, so you get fragments from many sessions mixed together. There are no timestamps per tile. Timing must come from file system timestamps and other RDP artifacts.

**Analysis workflow:**
1. **Extract tiles** with **bmc-tools** (ANSSI): `python bmc-tools.py -s <cache_dir> -d <out_dir> -b`. The `-b` flag also creates a collage bitmap of all tiles.
2. **Review and reassemble.** Tiles are mostly in cache order, not screen order. The collage often reveals readable strips. **RdpCacheStitcher** (from Germany's BSI) provides a GUI for manually and semi-automatically stitching tiles into larger screen regions.
3. **Look for** window title bars, file paths, usernames, hostnames, tool UIs (Mimikatz output, AD Users & Computers, PowerShell), and sensitive documents.

**Corroborating RDP artifacts.**

*On the client (source):*
- `HKCU\Software\Microsoft\Terminal Server Client\Default`: MRU0–MRU9 of recent destinations.
- `...\Servers\<host>`: `UsernameHint`, the username used for that server.
- `Documents\Default.rdp` (hidden): last connection settings.
- The mstsc Jumplist.
- Prefetch for `MSTSC.EXE`.
- The `Microsoft-Windows-TerminalServices-RDPClient/Operational` log: event 1024 (connection attempt, with destination) and 1102.
- SRUM network usage for `mstsc.exe`.

*On the server (destination):*
- Security log: 4624 with Logon Type 10 (RemoteInteractive), or Type 3 preceding it when NLA is used. Also 4778/4779 (session reconnect/disconnect) and 4625 failures.
- `TerminalServices-RemoteConnectionManager/Operational`: event 1149, which records the source IP and user even before full logon.
- `TerminalServices-LocalSessionManager/Operational`: 21 (logon), 22 (shell start), 24 (disconnect), 25 (reconnect).

**Caveats.**
- Only the native Microsoft client produces this cache in this format. Third-party clients like FreeRDP, Royal TS, or the newer Windows App may behave differently or not cache at all.
- Users or attackers can disable persistent caching.
- The cache shows fragments, not full screenshots. Findings should be presented as partial visual evidence.

---

### 6. Thumbnail Cache

**What it is.** When Explorer shows a file with a thumbnail preview, including images, videos, PDFs, and Office documents with embedded previews, Windows caches that thumbnail. The cache can prove a user **had and viewed image content that no longer exists**, including content from removable media or network shares. It is heavily used in CSAM, IP theft, and harassment cases.

**Vista and later: centralized cache.** Location (per user): `%LOCALAPPDATA%\Microsoft\Windows\Explorer\`. Files include:
- `thumbcache_16.db`, `_32`, `_48`, `_96`, `_256`, `_768`, `_1280`, `_1920`, `_2560`. The larger sizes were added in Win8.1/10; the set varies by Windows version.
- `thumbcache_sr.db`, `_wide.db`, `_exif.db`, `_wide_alternate.db`, `_custom_stream.db`.
- `thumbcache_idx.db`: an index mapping cache entry hashes to locations in the size-specific files.
- `iconcache_*.db`: application icons, of lesser forensic interest.

**Format.**
- Each database begins with a header whose signature is **`CMMM`**, followed by a format version (varies by OS), cache type, and offsets to the first entry and next free entry.
- Each entry also begins with `CMMM`, followed by:
  - The **64-bit cache entry hash** (the thumbnail cache ID).
  - Extension or identifier info (on some versions).
  - Identifier string size, padding size, and data size.
  - Data and header checksums, then the image data.
- Thumbnails are stored as **BMP, JPEG, or PNG**, and can be carved by signature if the database is damaged.

**The crucial limitation, and how to overcome it.** Vista+ thumbcache entries **do not store the original filename or path**, only the hash-based ID. To attribute a thumbnail to a file:
- Use the **Windows Search Index**. The `System.ThumbnailCacheId` property in the property store matches the cache entry hash, which gives you the path, filename, and metadata. Thumbcache Viewer can take a `Windows.edb` and do this mapping automatically.
- Cross-reference with other artifacts: ShellBags showing the folder was browsed, Jumplists or LNKs showing files were opened, USB artifacts, and the USN journal.

**XP-era and network shares: `Thumbs.db`.** On Windows XP, a hidden `Thumbs.db` was created **inside each folder** viewed in Thumbnails view. It is an OLE Compound File with a `Catalog` stream that **does store filenames** and modification times, plus JPEG thumbnails in numbered streams. Modern Windows still creates `Thumbs.db` files on **network shares (UNC paths)** browsed in thumbnail view, unless disabled by the "Turn off the caching of thumbnails in hidden thumbs.db files" policy. A `Thumbs.db` on a file server can point to which images existed there. Parse these with **Thumbs Viewer** (Eric Kutcher) or Autopsy.

**Forensic value and interpretation:**
- **Existence and viewing.** A thumbnail indicates the file was present and displayed in an Explorer view: thumbnail/large icons mode, a file-open dialog, or the preview pane. It does **not** alone prove the user opened the file, or even consciously saw it. Thumbnails can be generated for every file in a folder the user scrolled past.
- **Persistence.** Thumbnails survive deletion of the originals, deletion of containers, and disconnection of USB/network sources. They're cleared by Disk Cleanup's "Thumbnails" option, by manual deletion, or when Windows rebuilds the cache.
- **User attribution.** The cache sits in a specific user's profile.
- **Timestamps.** The cache has no per-entry creation times in most versions. Use the database files' own timestamps, and correlate with ShellBags and the Search Index.
- **Recovery.** Deleted cache databases can be carved. Older versions frequently survive in Volume Shadow Copies.

**Tools:**
- **Thumbcache Viewer** (Eric Kutcher): parses all versions and does Search Index correlation.
- **Thumbs Viewer**: for `Thumbs.db`.
- Autopsy, Axiom, and X-Ways support.

---

## Bringing It Together: A Worked Scenario

Suppose you suspect an insider exfiltrated customer data before resigning. The artifacts can combine like this:

- **ShellBags and Jumplists** show the user browsed `\\fileserver\Finance\Customers` and opened `master_list.xlsx`. The embedded LNK shows the file's volume serial and MFT reference.
- **Thumbnail Cache**, mapped via the **Search Index**, shows image scans from that share were viewed.
- **Search Index** records preserve metadata and an AutoSummary snippet of a document that has since been deleted.
- **SRUM** shows `rclone.exe` sent 6.2 GB over the user's home Wi-Fi SSID in a two-hour window, even though the binary is gone.
- **Recycle Bin** `$I` files, or USN journal rename records, show `rclone.exe` and a staging folder were deleted the next morning. The `$Recycle.Bin` SID folder ties the deletion to the user.
- **RDP Cache** on a jump host the user accessed contains tiles showing a file-share browser window, corroborating the RDP logons seen in event logs.

No single artifact would carry that conclusion, but together they form a coherent, corroborated timeline. That is the essence of Windows disk forensics.
