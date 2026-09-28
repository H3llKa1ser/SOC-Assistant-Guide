# Windows Registry Forensics

## 1. Introduction to Windows Registry Forensics

The Windows Registry is a hierarchical database that holds configuration for the operating system, hardware, installed software, and each user account. Windows and its applications constantly read and write to it, so it keeps a detailed record of system state and user behaviour. That makes it one of the most valuable artifact sources in Windows forensics. From the registry you can answer questions like: what the system was, who used it, what programs ran, which files and folders were opened, what USB devices were plugged in, which networks it joined, and what persistence mechanisms exist.

### Structure: keys, values, and data

The registry is organized into **keys** (like folders) and **values** (like files inside those folders). Each value has a name, a data type, and data. The common data types are:

| Type | Meaning |
|---|---|
| REG_SZ | A string |
| REG_EXPAND_SZ | A string with environment variables, such as `%SystemRoot%` |
| REG_MULTI_SZ | A list of strings |
| REG_DWORD | A 32-bit integer |
| REG_QWORD | A 64-bit integer |
| REG_BINARY | Raw binary data (many forensic gold mines are here) |

Every **key** has a **Last Write Time**, an 8-byte FILETIME in UTC. It updates whenever a value in that key is added, deleted, or modified, or a subkey is created or deleted. Individual **values do not have timestamps**. This is one of the most important concepts in registry forensics. When a value records the time of an event, the timestamp is stored inside the value's data. Otherwise, you infer timing from the parent key's last write time.

### Root keys

What you see in Regedit is a logical view built from several files on disk:

| Root key | What it is |
|---|---|
| HKEY_LOCAL_MACHINE (HKLM) | System-wide configuration, built from the SYSTEM, SOFTWARE, SAM, and SECURITY hives |
| HKEY_USERS (HKU) | All loaded user profiles (NTUSER.DAT and UsrClass.dat for each logged-on user), plus DEFAULT and service accounts |
| HKEY_CURRENT_USER (HKCU) | A pointer to the logged-on user's hive inside HKU |
| HKEY_CLASSES_ROOT (HKCR) | A merged view of HKLM\SOFTWARE\Classes and the user's UsrClass.dat (file associations, COM objects) |
| HKEY_CURRENT_CONFIG (HKCC) | A pointer to the current hardware profile in SYSTEM |

Offline, only the underlying hive files exist, and you analyze those directly.

### Hive files on disk

| Hive | Location | Key contents |
|---|---|---|
| SYSTEM | `C:\Windows\System32\config\SYSTEM` | Control sets, services, devices, USB, network interfaces, time zone, Shimcache, BAM |
| SOFTWARE | `C:\Windows\System32\config\SOFTWARE` | OS version, installed programs, network profiles, Run keys, ProfileList |
| SAM | `C:\Windows\System32\config\SAM` | Local user accounts, groups, logon statistics, password hashes |
| SECURITY | `C:\Windows\System32\config\SECURITY` | LSA secrets, cached domain credentials, audit policy |
| DEFAULT | `C:\Windows\System32\config\DEFAULT` | The default user profile (used by the logon screen and services) |
| NTUSER.DAT | `C:\Users\<user>\NTUSER.DAT` | Per-user activity: RecentDocs, UserAssist, ComDlg32, TypedPaths, RunMRU, Office MRU |
| UsrClass.dat | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | Per-user classes, and most importantly Shellbags (Win7+) |
| Amcache.hve | `C:\Windows\AppCompat\Programs\Amcache.hve` | Program and executable inventory, including SHA1 hashes |

Other locations worth knowing:

* **Transaction logs** sit next to each hive (`SYSTEM.LOG1`, `SYSTEM.LOG2`, `NTUSER.DAT.LOG1`, and so on).
* **`C:\Windows\System32\config\RegBack`** used to hold periodic backups. Since Windows 10 1803 this is disabled by default and the files are usually 0 bytes, unless someone enabled `EnablePeriodicBackup`.
* **Volume Shadow Copies** often contain historical versions of every hive. These are excellent for comparing "before and after" states.

### Transaction logs and "dirty" hives

Windows does not write every change straight to the primary hive file. Changes go first to the transaction logs (.LOG1/.LOG2), and are flushed into the hive later. If you copy a hive from a live or improperly shut down system, it may be **dirty**: the header's primary and secondary sequence numbers do not match, and recent changes exist only in the logs. Since Windows 8.1 the logs use a newer format, and a lot of recent activity can live there. **Always collect the .LOG1 and .LOG2 files together with the hive.** Tools such as Registry Explorer, RECmd, and rla.exe can replay them into a clean hive.

### Internal hive format

It helps to know the binary layout, especially for deleted-data recovery:

* A hive begins with a 4 KB **base block** with the signature `regf`. It contains the sequence numbers, a last-written timestamp, the root cell offset, and a checksum.
* It is followed by **hbins** (hive bins, signature `hbin`), usually 4 KB multiples, which contain **cells**.
* Cell types include:
  * `nk`: a key node, containing the name, last write time, parent, subkey list, and value list.
  * `vk`: a value.
  * `sk`: a security descriptor.
  * `lf`, `lh`, `li`, `ri`: subkey index lists.
  * `db`: big data, for values larger than about 16 KB.
* The cell size field is negative for allocated cells and positive for free cells.

When a key or value is deleted, its cell is marked free but often not overwritten. That means **deleted keys and values can frequently be recovered** from unallocated cell space. Registry Explorer does this automatically and shows the results under "Associated deleted records" and "Unassociated deleted records."

### Control sets

The SYSTEM hive contains `ControlSet001`, sometimes `ControlSet002`, and so on. `CurrentControlSet` does not exist offline; it is created at runtime. To find out which set was active, read `SYSTEM\Select`:

* `Current` is the active control set, usually 1.
* `LastKnownGood` is the fallback set.

Whenever this guide says `CurrentControlSet`, offline you should substitute `ControlSet00X` according to the `Current` value.

### Timestamp formats you will meet

| Format | Description | Where it appears |
|---|---|---|
| FILETIME | 64-bit count of 100-ns intervals since 1601-01-01 UTC | Most common |
| Unix epoch | Seconds since 1970 | For example, `InstallDate` |
| SYSTEMTIME | A 16-byte structure, often in **local time** | For example, NetworkList profiles |
| DOS date/time | 2-second granularity, local time | Inside shell items (Shellbags) |

Always record which time zone each timestamp is in. Mixing UTC and local times is a classic reporting error.

### The core tool kit

* **Registry Explorer** and **RECmd**, from Eric Zimmerman's tools.
* **RegRipper** (rip.exe), by Harlan Carvey. It is plugin-based and outputs reports.
* **Specialized parsers:** ShellBags Explorer/SBECmd, AppCompatCacheParser, and AmcacheParser.
* **Collection:** KAPE and FTK Imager.
* **Memory analysis:** Volatility.

---

## 2. Acquiring Registry Hives

### Why you can't just copy them

On a running system, the SYSTEM, SOFTWARE, SAM, SECURITY, and loaded NTUSER.DAT/UsrClass.dat files are locked by the kernel. A normal copy fails with a "file in use" error. The files are also hidden and marked as system files. You need tools that read the raw volume (parsing NTFS directly), use Volume Shadow Copies, or ask the OS to export the hive.

### Live acquisition options

**FTK Imager.** Use "File > Obtain Protected Files" for a quick grab of SAM, SYSTEM, SOFTWARE, SECURITY, and NTUSER. The more thorough approach is to add the physical or logical drive as an evidence item, browse to `Windows\System32\config`, and export the files along with their .LOG1/.LOG2 companions. You can export the user hives and Amcache the same way.

**KAPE (Kroll Artifact Parser and Extractor).** This is the modern standard for triage. The `RegistryHives` target collects system hives, user hives, transaction logs, RegBack, and Amcache. You can also use the `!SANS_Triage` or `KapeTriage` compound targets. It reads locked files through raw disk access and preserves timestamps. Example:

```
kape.exe --tsource C: --tdest E:\Collection --target RegistryHives,Amcache --vss
```

The `--vss` flag also pulls hives out of Volume Shadow Copies.

**reg save (built-in, requires admin).**

```
reg save HKLM\SYSTEM C:\out\SYSTEM.hiv
reg save HKLM\SOFTWARE C:\out\SOFTWARE.hiv
reg save HKLM\SAM C:\out\SAM.hiv
reg save HKLM\SECURITY C:\out\SECURITY.hiv
```

This produces a clean, consistent hive, but it is a logical export. Deleted-cell slack and transaction logs are not included, and the file's structure differs from the original. It is fine for configuration questions but weaker for deep analysis.

**Other raw-copy tools.** RawCopy, Invoke-NinjaCopy (PowerShell), and Velociraptor artifacts (such as `Windows.KapeFiles.Targets`) are useful for remote or enterprise-scale collection.

**Volume Shadow Copies.** List them with `vssadmin list shadows`, then access them through the `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopyX\` path or with KAPE's `--vss` flag. Historical hives can reveal keys an attacker later deleted.

### Dead-box acquisition

Work from a forensic image (E01 or raw) and never from the original disk. Mount it read-only with Arsenal Image Mounter or FTK Imager, or open it in Autopsy, X-Ways, or AXIOM, and export the hives. Because nothing is running, nothing is locked. Hives from a system that crashed or was hard-powered off are likely to be dirty, so grab the logs.

### Memory acquisition

Hives are also mapped in RAM. Volatility 3 plugins such as `windows.registry.hivelist`, `windows.registry.printkey`, and `windows.registry.userassist` let you inspect registry data that may never have been flushed to disk. This matters especially for Shimcache, which is only written at shutdown.

### Acquisition checklist

1. Collect all system hives, **every** user profile's NTUSER.DAT and UsrClass.dat, and Amcache.hve.
2. Always include the .LOG1/.LOG2 files.
3. Include RegBack contents and VSS copies where possible.
4. Hash everything (MD5/SHA1/SHA256) at collection and document chain of custody.
5. Record the system's time zone and clock offset.
6. Analyze copies, never originals.

---

## 3. Regedit and Registry Explorer

### Regedit

Regedit is Windows' built-in editor. It is useful for live exploration and learning, but it has serious limits for forensics.

* **No visible timestamps.** It doesn't show key last write times in the interface. The workaround is to right-click a key, choose Export, and set the type to "Text files (*.txt)." The text export includes the "Last Write Time" for each key.
* **Loading offline hives risks altering evidence.** You can select HKLM or HKU, then use "File > Load Hive" to mount an offline hive. However, the system may write to the hive and replay or alter logs. Only do this on a copy, never on evidence.
* **Weak with raw data.** It cannot recover deleted keys, doesn't handle dirty hives properly, and shows binary data only as raw hex.
* **Risk of accidental edits.** Changes save instantly, with no undo.

### Registry Explorer (Eric Zimmerman)

Registry Explorer is the go-to GUI for offline hive analysis. Its key features:

* **Transaction log handling.** When you load a dirty hive, it detects this and offers to replay the .LOG1/.LOG2 files, saving a cleaned copy. Holding SHIFT while loading opens the hive without replaying the logs.
* **Last write timestamps everywhere.** They appear in the key list and details panes, in UTC.
* **Deleted data recovery.** It automatically recovers deleted keys and values and shows them in associated and unassociated deleted records.
* **Bookmarks.** A built-in library of forensically relevant keys (UserAssist, ShellBags, USBSTOR, RecentDocs, ComDlg32, BAM, TypedPaths, and more) takes you straight to the good stuff.
* **Plugins that decode binary data.** It decodes UserAssist (ROT13 names, run counts, last run times), RecentDocs, ComDlg32 PIDL MRUs, SAM user records, AppCompatCache, TimeZoneInformation, and more into readable tables.
* **Data Interpreter.** Right-clicking selected bytes shows them interpreted as FILETIME, Unix time, integers, strings, and so on.
* **Powerful search.** You can search key names, value names, value data, and last write time ranges, with regex support.
* **Multi-hive views.** You can load several hives at once and compare them.

### The command-line companion: RECmd

RECmd uses **batch files** (.reb) to extract hundreds of artifacts across many hives into a single CSV that you can then timeline. The `Kroll_Batch.reb` or `DFIRBatch.reb` files are the common starting points. Example:

```
RECmd.exe -d E:\Collection --bn BatchExamples\Kroll_Batch.reb --csv E:\Out
```

Open the output in Timeline Explorer, where you can filter by category (Program Execution, File/Folder Opening, Persistence, and so on).

### Other tools worth knowing

* **RegRipper (rip.exe / rr.exe).** It runs profile-based plugins against a hive, for example `rip.exe -r NTUSER.DAT -p userassist`, or `-a` for all plugins. It is great for fast reports.
* **AccessData Registry Viewer.** An older tool, bundled with FTK, that can decrypt some protected storage.
* **Commercial suites.** AXIOM, X-Ways, and EnCase integrate registry parsing into their workflows.

**Best practice:** corroborate critical findings across at least two tools. Parsers occasionally differ, especially on new Windows builds.

---

## 4. System, Users and Network Information

### Operating system details

`SOFTWARE\Microsoft\Windows NT\CurrentVersion` holds the basics:

* **`ProductName`, `EditionID`, `DisplayVersion` (for example 22H2), `CurrentBuild`, and `UBR` (patch level).** Windows 11 often still reports "Windows 10" in `ProductName`. Use the build number instead: 22000 or higher is Windows 11.
* **`InstallDate`.** A Unix epoch value (REG_DWORD). `InstallTime` holds the same moment as a FILETIME. Be aware that feature updates reset these values. Older install dates can be found under `SYSTEM\Setup\Source OS (Updated on ...)` keys.
* **`RegisteredOwner` and `RegisteredOrganization`.**

### Computer name

`SYSTEM\CurrentControlSet\Control\ComputerName\ComputerName` → `ComputerName`

### Time zone

`SYSTEM\CurrentControlSet\Control\TimeZoneInformation` contains:

* `TimeZoneKeyName`
* `Bias` and `ActiveTimeBias`, in minutes from UTC
* `DaylightBias`

Establish the time zone first, because it underpins every local-time artifact.

### Last shutdown

`SYSTEM\CurrentControlSet\Control\Windows` → `ShutdownTime` is a FILETIME. `ShutdownCount` may also be present.

### Installed programs

* `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*` lists installed programs with `DisplayName`, `InstallDate`, `InstallLocation`, and `Publisher`.
* `SOFTWARE\WOW6432Node\...` holds the same information for 32-bit applications on 64-bit Windows.
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Uninstall` holds per-user installs.

### Autostart and persistence

These are the areas to check for persistence:

* **Run keys.** `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and `RunOnce`, and the same paths under NTUSER.DAT and WOW6432Node.
* **Services.** `SYSTEM\CurrentControlSet\Services\<name>`, with `ImagePath` and `Start` (2 = automatic, 3 = manual, 4 = disabled). A malicious service is often revealed by an odd `ImagePath` or a recent last write time.
* **Winlogon.** `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon` holds `Shell` and `Userinit`, which should normally be `explorer.exe` and `userinit.exe,`.
* **Other hijack points.** Image File Execution Options (the `Debugger` value), AppInit_DLLs, and COM hijacks in UsrClass.dat.

### Users

**SAM hive.** `SAM\Domains\Account\Users` contains:

* **`Names\<username>` subkeys.** The value *type* of the default value is the account's RID, and the key's last write time roughly reflects account creation.
* **`<RID in hex>` subkeys (for example `000003E9` = RID 1001).** Each holds:
  * **The `F` value** (binary), with the account's timestamps and counters at these offsets:

    | Offset | Field |
    |---|---|
    | 0x08 | Last logon |
    | 0x18 | Password last set |
    | 0x20 | Account expires |
    | 0x28 | Last failed logon |
    | 0x30 | RID |
    | 0x38 | Account control flags (disabled, password not required, and so on) |
    | 0x40 | Failed logon count |
    | 0x42 | Logon count |

  * **The `V` value**, containing the username, full name, comment, and the (encrypted) LM/NT hashes.
* **Built-in RIDs:** 500 is Administrator, 501 is Guest, 503 is DefaultAccount, and 504 is WDAGUtilityAccount. Created users start at 1000 or 1001.

The SAM only covers **local** accounts. Domain and Microsoft accounts show up in:

* `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\<SID>`, which maps each SID to its `ProfileImagePath` (profile folder). It includes load and unload times on newer builds.
* `SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI`, which records `LastLoggedOnUser` and `LastLoggedOnSAMUser`.

The Registry Explorer SAM plugin and the RegRipper `samparse` plugin decode all of this.

### USB and external devices (closely related system artifacts)

* **`SYSTEM\CurrentControlSet\Enum\USBSTOR`.** Each device appears as `Disk&Ven_X&Prod_Y&Rev_Z\<SerialNumber>`. If the second character of the serial is `&`, Windows generated it and the device had no unique serial.
* **Timestamp properties.** Under the device's `Properties\{83da6326-97a6-4088-9453-a1923f573b29}` key:
  * `0064` = first install
  * `0066` = last arrival (connected)
  * `0067` = last removal
* **`SYSTEM\CurrentControlSet\Enum\USB`** holds the VID/PID.
* **`SYSTEM\MountedDevices`** maps volume GUIDs and drive letters to devices.
* **`SOFTWARE\Microsoft\Windows Portable Devices\Devices`** holds friendly names and volume labels.
* **`SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt`** holds ReadyBoost data, sometimes including volume serial numbers.
* **`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{GUID}`** attributes a device to a specific user.
* **Correlation:** `C:\Windows\INF\setupapi.dev.log` confirms first-connection times.

### Network information

**Interfaces and IP configuration.** `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\{InterfaceGUID}` contains:

* `DhcpIPAddress`, `DhcpSubnetMask`, `DhcpDefaultGateway`, `DhcpServer`, and `DhcpDomain`
* `LeaseObtainedTime` and `LeaseTerminatesTime` (Unix epoch)
* `IPAddress` for static configurations

There are often subkeys holding history for each network.

**Networks the machine has connected to (Wi-Fi, wired, VPN, mobile).**

* **`SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{ProfileGUID}`** contains:
  * `ProfileName` (the SSID or network name) and `Description`
  * `DateCreated` (first connection) and `DateLastConnected`. Both are 16-byte SYSTEMTIME values stored in **local time**, not UTC.
  * `NameType`: 0x06 (6) = wired, 0x17 (23) = broadband/mobile, 0x47 (71) = wireless
  * `Category`: 0 = Public, 1 = Private, 2 = Domain
* **`...\NetworkList\Signatures\Unmanaged` and `\Managed`.** These link a `ProfileGuid` to `DefaultGatewayMac`, `DnsSuffix`, and `FirstNetwork`. The gateway MAC is powerful: you can geolocate a Wi-Fi access point's BSSID with services like WiGLE and prove the device was at a physical location.
* **Wi-Fi keys and passphrases are not in the registry.** They are in `C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\{GUID}\*.xml`, protected with DPAPI.

**Shares and mapped drives.**

* `SYSTEM\CurrentControlSet\Services\LanmanServer\Shares` lists shares hosted by this machine.
* `NTUSER.DAT\Network\<DriveLetter>` lists persistent mapped drives, with `RemotePath`.
* `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU` lists recently mapped paths.
* MountPoints2 entries such as `##server#share` show remote shares the user accessed. These are useful for lateral-movement investigations.

---

## 5. Shellbags

### What they are

Shellbags ("shell bag MRUs") store Windows Explorer's view preferences for each folder a user has browsed: window size and position, view mode (icons or details), sort order, and so on. Windows remembers these settings per folder, so the registry ends up with a record of **folders the user interacted with through the Explorer shell**. That includes folders that have since been deleted, folders on removable media and network shares, and folders on machines that no longer exist.

### Locations

* **Windows 7 and later (the primary location):**
  `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU`
  `UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\Bags`
* **Also check:** `NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU` and `\Bags`. This was the main location on XP (along with `ShellNoRoam`) and still holds some entries on newer versions, such as certain desktop and network items.

### How the structure works

* **BagMRU** is a tree that mirrors the folder hierarchy. The root represents the Desktop namespace. Each numbered value (0, 1, 2…) contains a **shell item** (a binary structure from a PIDL) that describes one child folder. Each numbered value has a matching numbered subkey, which holds that folder's own children, and so on down the tree.
* **MRUListEx** in each key lists the children in most-recently-used order. It is a series of 4-byte indices that ends with `FFFFFFFF`.
* **NodeSlot** in each BagMRU subkey points to a numbered subkey under **Bags**, which holds the actual view settings.
* **Rebuilding a full path** means walking the tree, for example: My Computer → C:\ → Users → Bob → Secret Stuff.

### Forensic value

Shellbags can show:

* **Folder access.** Evidence that a user browsed to a folder, even if it was later deleted or wiped.
* **Removable media and network paths.** Shell items record drive letters, volume names, UNC paths (`\\server\share`), and portable devices (MTP phones and cameras).
* **Compressed folders.** Browsing inside ZIP files through Explorer.
* **Special folders.** Control Panel categories, Recycle Bin, Libraries, search results, and FTP folders.
* **Knowledge of a folder's existence and structure.** This is useful to counter "I never saw that folder" claims.

### Timestamps

There are several sources of time, and it is important to understand their different meanings:

1. **Embedded file system timestamps.** File-entry shell items contain the folder's modified time in DOS format (local time, 2-second granularity), captured when the shell item was created. Extension blocks (signature `0xBEEF0004`) add created and accessed times, plus sometimes the MFT entry and sequence number. These describe **the folder** at the time the bag was written, not the user's action.
2. **Key last write time.** When a BagMRU key updates, the child listed first in its MRUListEx was the most recently interacted-with. That lets you attribute the key's last write time to it as a "last interacted" time.
3. **"First interacted" times.** Tools like ShellBags Explorer infer these by analysing when an entry was created.

### Tools

* **ShellBags Explorer** (GUI) and **SBECmd** (CLI), both by Eric Zimmerman. Example:

  ```
  SBECmd.exe -d E:\Collection\Users --csv E:\Out
  ```

* **Also:** RegRipper's `shellbags` plugin, and Registry Explorer's built-in ShellBag plugin.

### Caveats

* **Shellbags show folder interaction, not file opening.** They don't prove that a specific file inside the folder was opened.
* **Not every folder access creates a shellbag.** Folders accessed through the command line, PowerShell, or many third-party file managers may never create one. However, an Open/Save dialog in any application can generate one.
* **Behaviour has shifted across Windows builds.** For example, some Windows 10/11 builds create entries more eagerly.
* **Updates and deletions.** Entries update when view settings change, and Windows may prune shellbags when a folder's settings are reset. Registry cleaners such as CCleaner can wipe them, but the deleted keys may still be recoverable from unallocated hive space.

---

## 6. Shimcache (AppCompatCache)

### Purpose

The Application Compatibility Infrastructure checks whether an executable needs a "shim" (a compatibility fix) to run properly. To avoid repeated lookups, Windows caches metadata about executables it has evaluated. That cache is Shimcache, and it becomes a list of executables that existed on and were evaluated by the system.

### Location

`SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache` → the `AppCompatCache` value, a large REG_BINARY blob.

On XP it was `...\Session Manager\AppCompatibility\AppCompatCache`.

### What each entry contains (varies by OS)

* The full file path.
* The file's **Last Modified time** from $STANDARD_INFORMATION. This is **not** the execution time, and it is the most commonly misunderstood point about Shimcache.
* File size (on XP and Server 2003).
* **An execution flag:**
  * **Windows 7 and Server 2008 R2:** there is an "InsertFlag" or execution flag.
  * **Windows 8 and later:** this is less reliable.
  * **Windows 10/11:** entries start with the signature `10ts`. Recent research suggests some bytes in each entry's data field may correlate with execution, but treat that as a supporting indicator, not proof.
* **Ordering:** entries are stored **most recent first**, which gives you a relative sequence even without execution timestamps.
* **Capacity:** up to 1,024 entries on Windows 7 and later, and 96 on XP.

### Critical behaviour

* **Shimcache is written only at shutdown or reboot.** While the system runs, the cache lives in kernel memory. On a live system that has been up for weeks, the on-disk value may be missing everything since the last boot. Use memory forensics (for example, Volatility's shimcache plugins) to get the current contents.
* **Presence does not prove execution** on Windows 8, 10, and 11. Files can be added simply by being browsed in Explorer, or by being evaluated when a folder is enumerated. On Windows 7 and earlier, presence is stronger evidence, especially with the flag set.
* **Renamed or moved files, and modified files, create new entries.** This helps you track attacker tooling that was renamed.
* **Detecting timestomping.** Comparing the Shimcache modified time to the file's current MFT timestamps can reveal tampering. Shimcache captured the "real" time before the change.
* **Deleted files survive.** Shimcache can show that malware existed even after the file was deleted.

### Tools

* **AppCompatCacheParser**, by Eric Zimmerman. Example:

  ```
  AppCompatCacheParser.exe -f SYSTEM --csv E:\Out
  ```

  Add `--nl` to skip replaying the transaction logs.
* **Also:** RegRipper's `appcompatcache` plugin, Registry Explorer's plugin, and Mandiant's ShimCacheParser (older).

### How to phrase findings

A careful way to phrase a Shimcache finding: "The file `C:\Users\Bob\AppData\Local\Temp\x.exe` was present on the system, with a last modified time of T. Its position in Shimcache is consistent with activity before and after other entries." Corroborate execution with Prefetch, Amcache, BAM, UserAssist, or event logs.

---

## 7. Amcache

### What it is

Amcache.hve is a standalone registry hive used by the Application Experience and Compatibility Appraiser components. It inventories programs, executables, drivers, and devices. It appeared in Windows 8 and replaced Windows 7's `RecentFileCache.bcf`; later Windows 7 updates also added it. It is **not** mounted into the live registry view, so you won't see it in Regedit without loading it.

**Location:** `C:\Windows\AppCompat\Programs\Amcache.hve`, plus its .LOG1 and .LOG2 files.

### Structure (Windows 10 1607 and later, and Windows 11)

Under `Root\`:

* **`InventoryApplicationFile`.** The executable-level inventory, and the most important key. Each subkey is one file and includes:
  * **`FileId`**: the SHA1 hash of the file, prefixed with `0000`.
  * **`LowerCaseLongPath`**: the full path.
  * `Name`, `Size`, `Publisher`, `ProductName`, `Version`, `BinaryType` (for example pe32_i386 or pe64_amd64), and `IsOsComponent`.
  * **`LinkDate`**: the PE header compile timestamp. This is useful for malware analysis and spotting forged compile times.
  * **`ProgramId`**: links the file to its application in `InventoryApplication`.
  * **Key last write time**: often approximates when the entry was created or updated.
* **`InventoryApplication`.** Installed applications, with `Name`, `Publisher`, `Version`, `InstallDate`, `Source` (for example "AddRemoveProgram" or "Msi"), `RootDirPath`, and `UninstallString`. Store apps are included too.
* **`InventoryApplicationShortcut`.** Shortcut (.lnk) paths associated with applications.
* **`InventoryDriverBinary`.** Drivers, including whether they are signed, their hash, and their service name. This is excellent for rootkit and malicious-driver investigations.
* **`InventoryDevicePnp` and `InventoryDeviceContainer`.** Plug-and-play devices, including USB devices, with model and manufacturer.
* **Older builds (Windows 8 to early Windows 10)** used `Root\File\{VolumeGUID}\<FileRef>`, with numbered values:
  * `15` = path
  * `101` = SHA1
  * `17` = last modified time
  * `12` = created time
  * `0` = product name, and so on

  They also used `Root\Programs` for applications.

### The SHA1 caveat

The hash is computed over the **first 31,457,280 bytes (30 MB)** of the file. For files smaller than that, it is the true SHA1. For larger files, it won't match a full-file hash.

### Forensic value

* **Hashes survive deletion.** You get a SHA1 even if the file is gone. You can check it against VirusTotal or threat intelligence to identify malware the attacker deleted.
* **Full paths, publisher, and version** help spot masquerading. For example, `svchost.exe` in `C:\Users\Public\` with no publisher is suspicious.
* **Compile timestamps and driver data** support malware analysis.
* **Device and application install evidence.**

### Execution caveats

Research from ANSSI (Blanche Lagny's 2019 paper) showed that Amcache entries are created not only by execution. The **Microsoft Compatibility Appraiser** scheduled task scans the disk, and installations add entries too. So **an Amcache entry indicates presence, and often execution, but does not prove execution by itself.** Treat the key last write time as "time the entry was written," which may be near the first execution or may come from a scan. Corroborate with Prefetch, BAM, event ID 4688, or Sysmon.

### Tools

* **AmcacheParser**, by Eric Zimmerman. Example:

  ```
  AmcacheParser.exe -f Amcache.hve --csv E:\Out -i
  ```

  `-i` includes file entries associated with program entries. You can also whitelist or blacklist SHA1s with `-w` and `-b`.
* **Also:** Registry Explorer (load the hive directly) and RegRipper's `amcache` plugin.

---

## 8. Recent Files

Several NTUSER.DAT keys record recently accessed files and user activity. Taken together, they show what the user did.

### RecentDocs

`NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`

* **The root key** lists recently opened files and folders across all types. Numbered values hold a Unicode filename followed by the name of the matching .lnk file in `%AppData%\Microsoft\Windows\Recent` and an embedded shell item. `MRUListEx` gives the order.
* **Per-extension subkeys** (`.docx`, `.pdf`, `.jpg`, `.zip`, and a `Folder` subkey) track recent items of each type, each with its own MRUListEx.
* **Timing.** The last write time of each subkey equals the open time of the item listed first in that subkey's MRUListEx. By combining the root key and the extension subkeys, you can often date several items.
* **Coverage.** Files opened by double-clicking in Explorer or through many applications are recorded. Files opened through the command line may not be.

### Microsoft Office MRU

* **Paths:** `NTUSER.DAT\Software\Microsoft\Office\<Version>\<App>\File MRU` and `\Place MRU` (recent folders).
  * `<Version>`: 16.0 = Office 2016, 2019, 2021, and 365; 15.0 = 2013; 14.0 = 2010.
  * `<App>`: Word, Excel, PowerPoint, and so on.
* **Signed-in accounts.** With a Microsoft or Entra ID/AD account, the entries sit under `...\<App>\User MRU\<LiveId_xxxx | AD_xxxx | ADAL_xxxx>\File MRU`. That also ties activity to a specific identity.
* **Value format.** Values `Item 1`, `Item 2`, and so on look like:

  ```
  [F00000000][T01D9A3B2C4E5F600][O00000000]*C:\Users\Bob\Documents\Plan.docx
  ```

  The `T` field is a hex FILETIME for when the file was **last opened**. This is a per-item timestamp, which is valuable.
* **Trust Records.** `NTUSER.DAT\Software\Microsoft\Office\16.0\<App>\Security\Trusted Documents\TrustRecords` records documents where the user clicked "Enable Editing" or "Enable Content." The value data starts with a FILETIME. If the **last 4 bytes are `FF FF FF 7F`, macros were enabled.** This is huge in phishing investigations, because it proves the user enabled the malicious macro, and when.
* **Reading Locations** (in newer Office versions) records the last position in a document and the last-read time.

### Related user-activity keys you'll use alongside Recent Files

**UserAssist.** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count` records GUI program launches:

* `{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}` covers executables.
* `{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}` covers shortcut launches.

Value names are ROT13-encoded, and paths use known-folder GUIDs. The data includes the **run count**, **focus count and time**, and **last execution time** (FILETIME). This is strong evidence of execution through Explorer, the Start menu, or the taskbar.

**TypedPaths.** `...\Explorer\TypedPaths` records paths typed into the Explorer address bar (`url1` is the most recent). This shows deliberate intent, because the user typed a specific path.

**WordWheelQuery.** `...\Explorer\WordWheelQuery` records search terms typed into Explorer's search box. Entries are Unicode and ordered by MRUListEx.

**RunMRU.** `...\Explorer\RunMRU` records commands typed into the Win+R Run dialog. `MRUList` orders them with letters (a, b, c…). You will often see things like `cmd`, `powershell`, `\\10.0.0.5\c$`, or `mstsc`, which is great for attacker activity.

**BAM/DAM (Background Activity Moderator, Windows 10 1709 and later).** `SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>` (on 1709 the path was `bam\UserSettings`) maps executable paths to a **last execution FILETIME**, per user SID. It is one of the best registry execution artifacts. Entries can age out after about a week, and newer builds have changed the behaviour.

**Beyond the registry.** LNK files in `%AppData%\Microsoft\Windows\Recent` and Jump Lists (`AutomaticDestinations` and `CustomDestinations`) should always be correlated with the registry MRUs. They contain target MAC times, volume serials, and machine names.

---

## 9. Dialogue Boxes MRU (ComDlg32)

Whenever an application uses the standard Windows **Open** or **Save As** dialog, Windows records what was opened or saved, and from where. This captures file activity performed inside applications. That includes activity Explorer-based artifacts might miss, such as a user uploading a file in a browser, which opens a dialog.

**Root location:** `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\`

### OpenSavePidlMRU (Vista and later)

* Records files opened or saved through Open/Save As dialogs.
* **Subkeys by extension** (`docx`, `exe`, `pdf`, `zip`…) and a `*` subkey that holds the most recent items across all types.
* Values are numbered and contain **PIDLs (shell item lists)**, which parse to a full path (including on removable or network drives). `MRUListEx` gives the order.
* The last write time of each subkey equals the time of the first MRUListEx entry in it.
* On XP the equivalent was `OpenSaveMRU`, with plain-text paths.

### LastVisitedPidlMRU

* Records the **executable name** plus the **last folder** that application used in a dialog.
* It connects a program to a location. For example, `chrome.exe → C:\Users\Bob\Documents\Exfil`, which suggests Chrome was used to upload or download from that folder. `7zG.exe` and `WinRAR.exe` entries are common in data-staging cases.
* It also proves the program was run, since it showed a dialog.
* The XP equivalent was `LastVisitedMRU`. `LastVisitedPidlMRULegacy` holds entries in the older format, for compatibility.

### CIDSizeMRU (Windows 7 and later)

* Records executables that displayed a common dialog, along with the dialog's size and position.
* It is useful as another evidence-of-execution source, with ordering from MRUListEx.

### FirstFolder

* Records the folder first presented by a dialog for a given application.

### Interpretation tips

* Combine ComDlg32 findings with RecentDocs, Shellbags, LNK files, and Jump Lists to build a complete picture of file interaction.
* Only the key last write time gives you time data, which applies to the most recent item in each subkey. Earlier entries give you order only.
* **Tools:** Registry Explorer's ComDlg32 plugins decode the PIDLs, as do RegRipper's `comdlg32` plugin and RECmd batch files.

---

## Putting It All Together: Analysis Methodology

1. **Establish context first.** Identify the control set, time zone, OS version, users and SIDs, and the install date.
2. **Clean the hives.** Replay the transaction logs, keep the originals hashed, and check for deleted keys.
3. **Build a timeline.** Run RECmd batch files, AppCompatCacheParser, AmcacheParser, and SBECmd, then merge the results with $MFT, Prefetch, event logs, LNK, and Jump Lists (for example, using KAPE modules plus Timeline Explorer).
4. **Group findings by question:**

| Question | Artifacts |
|---|---|
| Program execution | BAM, UserAssist, Prefetch, Amcache, Shimcache, ComDlg32 LastVisited and CIDSizeMRU, RunMRU |
| File and folder opening | RecentDocs, Office MRU, OpenSavePidlMRU, Shellbags, TypedPaths, LNK and Jump Lists |
| External devices | USBSTOR and properties, MountedDevices, MountPoints2, Portable Devices, setupapi.dev.log |
| Network and lateral movement | NetworkList, interfaces, MountPoints2, Map Network Drive MRU, Terminal Server Client\Servers (RDP history in NTUSER.DAT) |
| Persistence | Run keys, Services, Winlogon, IFEO, COM hijacks, scheduled task caches in SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache |

5. **Understand what each artifact proves.** Presence, execution, and user interaction are different claims. Never rely on a single artifact for a critical conclusion.
6. **Watch for anti-forensics.** Look for registry cleaners, (recoverable) deleted keys, gaps in MRU lists, timestomping revealed by Shimcache, and missing Shimcache data because the system was never shut down. Volume Shadow Copies and memory images can recover what's been removed.

---
