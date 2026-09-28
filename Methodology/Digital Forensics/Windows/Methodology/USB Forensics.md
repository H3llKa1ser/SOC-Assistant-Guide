# USB Forensics

## 1. Introduction to USB Forensics

USB forensics is the part of Windows digital forensics that reconstructs the history of removable devices on a system. The questions it answers are almost always the same: which devices were connected, when they were first and last connected and removed, which user account was logged on, what drive letter and volume name the device had, and what files and folders were opened on it. These questions come up constantly in data theft and insider threat cases, malware introduction (patient-zero USB infections), policy violation investigations, and criminal cases involving contraband stored on removable media.

The core challenge is that no single artifact tells the whole story. Windows scatters evidence across the registry hives, the setup log, several event logs, and per-user artifacts such as Shellbags, LNK files and Jump Lists. The examiner's job is to correlate them using a few shared identifiers until they form one timeline.

### How Windows sees a USB device

When a device is plugged in, the Plug and Play (PnP) manager queries its USB descriptors and receives several key values.

The **Vendor ID (VID) and Product ID (PID)** are 4-digit hex values identifying the manufacturer and model. For example, VID_0781 is SanDisk. These can be looked up in public USB ID databases such as linux-usb.org's usb.ids list.

The **device serial number (iSerialNumber)** comes from the device firmware and is the single most important identifier, because it is what ties together artifacts across the registry and, potentially, across multiple computers. There is one critical caveat: if the device doesn't report a serial number, Windows generates one, and you can spot it because the **second character is an ampersand** (e.g., `6&2a3b4c5d&0`). A Windows-generated serial is unique only to that machine and can't be used to track the device across systems.

The **device class** also matters. Classic flash drives and external disks use the Mass Storage Class (MSC) and get a drive letter. Phones, cameras and media players often use the Media Transfer Protocol (MTP), which gets no drive letter and leaves a different set of artifacts, mostly under Windows Portable Devices. Some USB 3.x drives using the UASP protocol are enumerated under `SCSI` instead of `USBSTOR`, which trips up examiners who only check USBSTOR.

Finally, there's the **volume serial number (VSN)**, a 32-bit value written into the volume's boot record when it is formatted. This is not the same as the device serial number. The VSN changes if the device is reformatted, but it matters a lot because LNK files and Jump Lists record the VSN, not the device serial. Bridging the VSN to the device serial is one of the central correlation tasks in USB forensics.

### The investigative workflow

A typical examination follows a logical order. First, identify every device (vendor, product, serial) from the SYSTEM hive. Then establish the timeline of first install, last connect and last removal. Next, map each device to a drive letter and volume GUID, and map the volume GUID to a user account through that user's NTUSER.DAT. After that, recover the volume serial number and volume label, and finally pivot into user activity artifacts (Shellbags, LNK files, Jump Lists) to show which folders and files were accessed on that volume. Event logs corroborate and extend the timeline, especially for repeated connections that the registry overwrites.

### Key source files to collect

```
C:\Windows\System32\config\SYSTEM
C:\Windows\System32\config\SOFTWARE
C:\Windows\INF\setupapi.dev.log
C:\Windows\System32\winevt\Logs\*.evtx
C:\Users\<user>\NTUSER.DAT
C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\  (LNK files, AutomaticDestinations, CustomDestinations)
```

Always collect the registry transaction logs (`.LOG1`, `.LOG2`) alongside the hives, because recent changes may exist only in those logs until they are replayed. Volume Shadow Copies are also valuable, since they can contain older versions of hives that show devices later removed from the live registry.

---

## 2. USB Registry Keys

Before you start, remember that `CurrentControlSet` doesn't exist in an offline hive. Check `SYSTEM\Select\Current` to find which `ControlSet00X` was active (usually ControlSet001), and use that in place of CurrentControlSet in every path below.

### USBSTOR: the device inventory

```
SYSTEM\ControlSet001\Enum\USBSTOR\
    Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.00\
        4C530001230512345678&0\
```

Each subkey at the first level describes a device type (vendor, product, revision) and each subkey below it is a specific device identified by serial number, with `&0` appended to show the LUN. Inside, the `FriendlyName` value gives a human-readable name, and on older systems `ParentIdPrefix` helps link the device to its MountedDevices entry.

The most valuable data sits in the Properties subkey, under the GUID `{83da6326-97a6-4088-9453-a1923f573b29}`. These values are stored as 64-bit Windows FILETIME timestamps (in UTC):

| Value | Meaning |
|---|---|
| `0064` | First install date (first time the device was ever connected) |
| `0065` | Install date (most recent driver install) |
| `0066` | Last arrival (last time the device was connected) |
| `0067` | Last removal (last time the device was disconnected) |

On a live system the Properties key is protected and needs SYSTEM-level privileges to read, which is one reason offline analysis of an acquired hive is preferred.

### USB: vendor and product IDs

```
SYSTEM\ControlSet001\Enum\USB\VID_0781&PID_5567\4C530001230512345678
```

This key confirms the VID and PID and, for devices with genuine serials, the same serial number seen under USBSTOR. It also carries a Properties subkey with the same timestamp GUID, which is useful for corroboration. It also lists non-storage devices (keyboards, mice, phones), so it gives a broader picture of hardware connected to the system.

### SCSI and SWD\WPDBUSENUM

```
SYSTEM\ControlSet001\Enum\SCSI\
SYSTEM\ControlSet001\Enum\SWD\WPDBUSENUM\
```

UASP-capable USB 3 drives often appear under SCSI rather than USBSTOR. The WPDBUSENUM key records volumes and portable devices exposed through the Windows Portable Devices framework and often includes the device's friendly name and volume label, making it a good place to find MTP phones and cameras.

### MountedDevices: drive letters and volume GUIDs

```
SYSTEM\MountedDevices
```

This key maps `\DosDevices\E:` and `\??\Volume{GUID}` entries to binary data. For removable devices, that data contains a Unicode string embedding the USBSTOR device path, including the serial number. Matching the serial number in that string to your USBSTOR entry tells you which drive letter and volume GUID the device received. Drive letters get reassigned, so the `\DosDevices` entries only show the most recent assignment, while the volume GUID is more persistent.

### MountPoints2: tying the device to a user

```
NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\{Volume-GUID}
```

This is the crucial user attribution step. If a volume GUID from MountedDevices appears in a user's MountPoints2 key, that user account was logged on when the device was mounted. The LastWrite time of the GUID subkey is a reasonable indicator of the last time that user connected the device. Every user's NTUSER.DAT should be checked, because a device may appear under several accounts.

### Windows Portable Devices

```
SOFTWARE\Microsoft\Windows Portable Devices\Devices\
```

Subkeys here embed the device serial number in their names and contain a `FriendlyName` value, which is often the volume label the user saw in Explorer (for example, "BACKUP_2024"). This gives you the human-facing name that will match paths in LNK files and Shellbags.

### EMDMgmt: the volume serial number bridge

```
SOFTWARE\Microsoft\Windows NT\CurrentVersion\EMDMgmt\
```

This key belongs to ReadyBoost. Subkey names typically include the device serial, the volume label, and the **volume serial number written in decimal** at the end of the name. Converting that decimal to hex gives you the VSN recorded in LNK files and Jump Lists, which closes the loop between device and file activity. The caveat is that this key is often missing when the system runs from an SSD, since ReadyBoost is usually disabled in that configuration.

### VolumeInfoCache

```
SOFTWARE\Microsoft\Windows Search\VolumeInfoCache\E:
```

This key stores volume labels per drive letter, which helps confirm what label was associated with a letter at the time the key was last updated.

### DeviceClasses and DeviceContainers

```
SYSTEM\ControlSet001\Control\DeviceClasses\{53f56307-b6bf-11d0-94f2-00a0c91efb8b}   (disk interface)
SYSTEM\ControlSet001\Control\DeviceClasses\{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}   (volume interface)
SYSTEM\ControlSet001\Control\DeviceContainers\
```

These keys provide corroborating entries whose LastWrite times can back up connection times and help when primary keys have been tampered with.

### setupapi.dev.log: first connection

```
C:\Windows\INF\setupapi.dev.log
```

This isn't the registry, but it's always read alongside it. When a device is installed for the first time, Windows writes a section like `>>> [Device Install (Hardware initiated) - USBSTOR\Disk&Ven_...\<serial>&0]` followed by a `Section start` timestamp. Searching for the serial number gives an independent first-connect time. The timestamps here are in **local time**, while registry timestamps are UTC, which is a common source of apparent discrepancies.

### Registry pitfalls

The **Plug and Play Cleanup** scheduled task (Windows 8 and later) can remove device entries that haven't been seen for about 30 days, so a missing USBSTOR entry doesn't prove a device was never connected. Check Volume Shadow Copies, event logs and setupapi.dev.log for traces of older devices. Tools such as USBOblivion exist specifically to wipe these keys, so gaps between the registry and the logs can themselves be evidence of anti-forensics.

---

## 3. USB Event Logs

Event logs matter because the registry mostly keeps only the first and last events, while logs can record every connection and disconnection in the retention window. The relevant logs are in `C:\Windows\System32\winevt\Logs\`.

### Microsoft-Windows-Partition/Diagnostic (Event 1006)

On modern Windows 10 and 11 systems this is often the most valuable USB log. Event **1006** is written each time a storage device is connected and typically includes the manufacturer, model, device serial number, disk capacity, and raw bytes of the partition table and the **volume boot record (VBR)**. Because the VSN lives in the VBR, you can parse it out of this event and directly link the device serial to the VSN, even when EMDMgmt is absent. Disconnections often appear as a 1006 event with zero capacity. Since these events repeat per connection, they give you a full connection history rather than just first and last.

### Microsoft-Windows-Kernel-PnP/Configuration

Events **400** (device configured), **410** (device started) and **420** (device deleted) record PnP activity, including the device instance path with the serial number. They're useful for corroborating first installs and driver configuration.

### Microsoft-Windows-DriverFrameworks-UserMode/Operational

This log records connection events like **2003, 2004, 2006, 2010** and disconnection events like **2100, 2101, 2102, 2105, 2106**, each including the device serial. It is highly detailed when it exists, but it's **disabled by default** on modern Windows, so you'll mainly find it where administrators enabled it or on older systems.

### System.evtx

Look for **20001 and 20003** (UserPnp driver installation, which records new devices getting drivers) and **7045** if a device installed a service. Event 20001 appears at first installation and supports the first-connect timestamp.

### Security.evtx (requires audit policy)

If **Audit PNP Activity** is enabled, event **6416** records every new external device recognized, including device ID and class. If **Audit Removable Storage** is enabled, events **4663** (and 4656) record object access on removable media, meaning you get actual file-level read and write events with the user account, which is the gold standard in data exfiltration cases. Neither is on by default, so check the audit policy before assuming their absence means anything.

### Other useful logs

`Microsoft-Windows-Storsvc/Diagnostic` and `Microsoft-Windows-Ntfs/Operational` can hold supporting information about storage and volume mounts on newer builds, and `Microsoft-Windows-WPD-*` logs relate to portable devices. Their content varies by Windows build, so treat them as corroboration.

### Summary table

| Log | Event ID | What it tells you | Default on? |
|---|---|---|---|
| Partition/Diagnostic | 1006 | Connect/disconnect, serial, capacity, VBR (VSN) | Yes (Win10+) |
| Kernel-PnP/Configuration | 400, 410, 420 | Device configuration and start | Yes |
| System | 20001, 20003 | Driver install for new device | Yes |
| DriverFrameworks-UserMode | 2003, 2100 etc. | Detailed connect/disconnect | No |
| Security | 6416 | New external device recognized | No (audit policy) |
| Security | 4663, 4656 | File access on removable storage | No (audit policy) |

---

## 4. Folder Access Analysis via Shellbags

Shellbags are registry data that Windows Explorer keeps to remember how each folder was displayed (view mode, window size, icon position, sort order). They are forensically valuable because they are created when a user browses to a folder and they **persist after the folder is deleted or the device is removed**. That means they can prove a user navigated into specific folders on a USB drive even when the drive is long gone.

### Locations

```
UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\BagMRU
UsrClass.dat\Local Settings\Software\Microsoft\Windows\Shell\Bags
NTUSER.DAT\Software\Microsoft\Windows\Shell\BagMRU
NTUSER.DAT\Software\Microsoft\Windows\Shell\Bags
```

On Windows 7 and later, UsrClass.dat holds most of the local folder activity, while NTUSER.DAT tends to hold entries for network locations, the desktop and some special folders. Both need to be parsed.

### Structure

`BagMRU` is a tree that mirrors the folder hierarchy. Each numbered value holds a binary **shell item** describing one level of a path, and child subkeys represent subfolders. The `MRUListEx` value records the order in which children were most recently accessed. Each folder also has a `NodeSlot` value pointing to its display settings under `Bags`.

Shell items come in several types. A root folder item represents things like My Computer, a volume item holds the drive letter (e.g., `E:\`), and file entry items represent folders. On Windows 7 and later, file entry items usually carry an extension block (signature `0xBEEF0004`) holding the folder's **created, modified and accessed timestamps** as they were when the shellbag was written, plus the **MFT entry and sequence number** of the folder. For MTP devices, the path begins with the device's friendly name rather than a drive letter, like "Galaxy S23\Internal storage\DCIM".

### Interpreting timestamps

There are two kinds of time in Shellbags. The embedded MAC timestamps describe the folder itself on the USB volume (for example, when the folder was created there), not when the user viewed it. Interaction time comes from the **LastWrite time of the BagMRU key**, combined with the MRUListEx order: the LastWrite time generally shows when the most recently accessed child under that key was opened. Tools present these as "first interacted" and "last interacted" times, but understand that only the most recent child in a key can be tied directly to the LastWrite time.

### Tying Shellbags to a USB device

The volume item gives you a drive letter only, with no serial number. Link it to a device by comparing the time with the connection window from the registry and event logs, confirming the drive letter from MountedDevices, and matching the folder names to paths from LNK files and Jump Lists, which do carry the VSN. When a shellbag shows `E:\Project_X\Contracts` during the same window when a specific SanDisk device was mounted as E: by that user, you have strong attribution.

### Limitations

Shellbags prove folder navigation, not file opening. They can also be created by indirect actions such as browsing within an application's Open/Save dialog or extracting archives, so be careful claiming the user deliberately opened Explorer. Treat them as strong evidence of awareness of a folder's existence and contents, and use Jump Lists and LNK files to show file-level access.

---

## 5. File Access Analysis via Jump Lists

Jump Lists (Windows 7 and later) power the recent and pinned items that appear when you right-click an application on the taskbar or Start menu. Forensically, they are a per-application history of files opened, and each entry embeds a full LNK record with rich metadata about the target file and the volume it lived on.

### Locations

```
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms
C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms
```

**AutomaticDestinations** are created by Windows automatically when an app opens files. Each file is an OLE Compound File (structured storage), containing numbered streams (each a complete LNK record) plus a **DestList** stream acting as an index. **CustomDestinations** are built by applications that define their own jump list entries (like browsers with frequent sites) and are stored as concatenated LNK records.

### AppIDs

The filename is the **AppID**, a hash derived from the application's path, which tells you which program opened the files. Some commonly cited examples are `5f7b5f1e01b83767` for Quick Access in Explorer, `1b4dd67f29cb1962` for Windows Explorer pinned/recent items, and `9b9cdc69c1c24e2b` for 64-bit Notepad. AppIDs vary by application version and install path, so rely on maintained lookup lists (built into JLECmd, for example) rather than memorizing them.

### What each entry reveals

The DestList stream gives you the **last access time** for each entry, an **access count** (how many times the file was opened through that app), the **pinned status**, an entry number that shows ordering, and the NetBIOS name of the host.

Each embedded LNK record gives you the **full target path** (e.g., `E:\Project_X\Contracts\Q3_pricing.xlsx`), the **drive type** (where "Removable" is DRIVE_REMOVABLE, type 2), the **volume serial number**, the **volume label**, the target file's **created, modified and accessed timestamps** and **file size** as they were when the link was written, the target's **MFT entry and sequence number**, and machine identifiers (the machine ID and a MAC address embedded in the tracker data block).

### Why this is the pivot point

This is where the pieces lock together. A Jump List entry says: this user opened `Q3_pricing.xlsx` with Excel from a removable volume labeled "BACKUP_2024", VSN `A1B2-C3D4`, on a specific date, five times. The VSN matches the VBR value in Partition/Diagnostic event 1006 or the decimal value in EMDMgmt, which leads you to the device serial number, which leads you to the USBSTOR entry, the connection timeline and the user's MountPoints2 key. You now have device, user, time and specific file in one chain.

### Standalone LNK files

The same `Recent` folder holds standalone `.lnk` files that Windows creates when a user opens a file through Explorer. They carry the same metadata as Jump List LNK streams. The LNK file's own creation time is roughly the first time the file was opened and its modification time is roughly the last time. Office also keeps its own LNK files in `AppData\Roaming\Microsoft\Office\Recent\`.

### Persistence and limitations

Jump List and LNK entries survive the deletion of the target file and the removal of the device, which is exactly why they're so useful. On the other hand, entries age out as new ones are added, users can clear them, and entries record the file as opened by an application, not necessarily what was done with it. They don't prove a file was copied to the USB, though a file with a USB path created shortly before being opened is highly suggestive. Proving copying usually needs additional sources such as the Security 4663 audit events, the USB device's own `$MFT` and `$UsnJrnl` if you have the device, or endpoint monitoring logs.

---

## 6. Automated USB Parsers and Tools

Manual parsing is essential for understanding and validation, but in real cases you rely on tools and then verify key findings by hand.

### Collection

**KAPE** (Kroll Artifact Parser and Extractor) is the standard triage tool. Its targets collect registry hives with transaction logs, event logs, setupapi.dev.log and user Recent folders, and its modules run the parsers below automatically. **Velociraptor** does the same at scale across many endpoints, with built-in artifacts for USB device history, Shellbags and LNK parsing. **FTK Imager** is commonly used to grab locked files like registry hives from a live system.

### Eric Zimmerman's tools

These free tools are the de facto standard in Windows forensics. **Registry Explorer** and **RECmd** parse hives, replay transaction logs and decode the USBSTOR Properties timestamps. RECmd's batch files (such as the Kroll batch) extract USB keys in bulk to CSV. **SBECmd** and **ShellBags Explorer** parse Shellbags from UsrClass.dat and NTUSER.DAT, resolving shell item types and timestamps. **JLECmd** parses Jump Lists (including AppID lookups and DestList data), and **LECmd** parses standalone LNK files. **EvtxECmd** parses event logs with maps that extract the relevant fields from events like 1006. **Timeline Explorer** is a viewer for filtering and correlating the resulting CSVs.

### Dedicated USB tools

**USB Detective** (by Jason Hale) is purpose-built for USB analysis. It correlates the registry, setupapi.dev.log, event logs, LNK files and Jump Lists into a per-device report with connect and disconnect times, and handles the VSN-to-serial correlation for you. A free community version exists along with paid versions with more features. **USBDeview** (NirSoft) lists USB devices with first and last plug times, mainly on live systems, though it can also load an external system's registry. **USB Forensic Tracker** is another free tool that extracts USB history from live systems, mounted images and Volume Shadow Copies.

### RegRipper

**RegRipper** runs plugins against registry hives. Relevant plugins include `usbstor`, `usb`, `usbdevices`, `mountdev`, `mp2` (MountPoints2), `portdev`, `emdmgmt` and `shellbags`. It's fast, scriptable and well suited for quick checks and reporting.

### Timeline and event log tools

**Plaso / log2timeline** builds a super-timeline across registry, event logs, LNK files, Jump Lists and file system metadata, which is excellent for seeing USB events in context with everything else. **Hayabusa** and **Chainsaw** hunt through event logs rapidly and can pull out the USB-related events.

### Commercial suites

**Magnet AXIOM**, **Belkasoft X**, **X-Ways Forensics**, **EnCase** and **Autopsy** (which is free and open source) all include USB device analysis and user activity artifact parsing, often with built-in correlation and reporting that is helpful for court-ready output.

### Beyond Windows

The same principles apply elsewhere, with different sources. On Linux, check `/var/log/syslog`, `kern.log`, `messages` and the systemd journal (`journalctl`), where kernel messages record the VID, PID, serial and manufacturer on connection. The **usbrip** tool automates this. On macOS, look at the Unified Logs (queried with `log show`) and, historically, system log files, plus `fseventsd` data for file system activity on mounted volumes.

### Validation

Never rely on a single tool's output for key findings. Cross-check critical timestamps between tools and against raw data, be explicit about time zones (UTC in the registry and event logs, local time in setupapi.dev.log), note Windows-generated serials, and document each correlation step. The strongest USB cases are those where the registry, event logs, Shellbags and Jump Lists independently tell the same story.

---
