# Browser Forensics

## 1. Introduction to Browser Forensics

Browser forensics is the identification, acquisition, analysis, and reporting of artifacts that web browsers leave on a system. Most user activity now happens in a browser: email, cloud storage, SaaS apps, banking, social media, and file transfers. The browser is often the most detailed record of what a person did, when, and in what order.

In investigations, browser evidence answers questions like these:

- **Intent:** did the suspect search for "how to wipe a hard drive" before the incident?
- **Access:** did an employee open the corporate SharePoint and then a personal Dropbox?
- **Infection:** was malware delivered through a drive-by download or a phishing link?
- **Exfiltration:** what files were uploaded or downloaded?
- **Attribution:** which accounts were logged in, as shown by cookies, autofill, and sync settings?

It supports criminal cases (child exploitation, fraud, stalking), incident response (initial access vectors, phishing, credential theft), insider threat and IP theft cases, HR matters, and civil litigation.

### The browser landscape

Nearly every modern browser is built on one of three engines. The engine family matters more than the brand, because it determines the artifact formats.

| Engine family | Browsers | Primary storage formats |
|---|---|---|
| **Chromium (Blink)** | Chrome, Edge (2020+), Brave, Opera, Vivaldi, Yandex, Arc | SQLite, JSON, LevelDB, Chromium cache format, SNSS session files |
| **Gecko** | Firefox, Tor Browser, Waterfox, LibreWolf, Pale Moon (fork) | SQLite, JSON, mozLz4-compressed JSON, cache2 |
| **WebKit** | Safari (macOS/iOS), all iOS browsers historically | SQLite, binary plists, binarycookies |
| **Legacy (Trident/EdgeHTML)** | Internet Explorer, legacy Edge | `index.dat` (IE ≤9), ESE database `WebCacheV01.dat` (IE10/11, legacy Edge) |

If you learn Chromium's artifact structure, you can handle about 70–80% of cases. Edge, Brave, and Opera use almost the same databases as Chrome, just at different paths.

### Timestamps: the first thing that trips people up

Each browser family uses a different epoch, and getting this wrong breaks your timeline.

| Format | Used by | Definition | Conversion (SQLite) |
|---|---|---|---|
| **WebKit/Chrome time** | Chromium history, cookies, downloads | Microseconds since 1601-01-01 00:00:00 UTC | `datetime(ts/1000000 - 11644473600, 'unixepoch')` |
| **PRTime** | Firefox | Microseconds since 1970-01-01 UTC (Unix epoch) | `datetime(ts/1000000, 'unixepoch')` |
| **Mac Absolute / Cocoa time** | Safari | Seconds (often fractional) since 2001-01-01 UTC | `datetime(ts + 978307200, 'unixepoch')` |
| **Windows FILETIME** | IE/ESE databases | 100-nanosecond intervals since 1601-01-01 UTC | Tool-dependent |
| **Unix epoch (seconds/ms)** | Many JSON artifacts, some Firefox fields | Seconds or milliseconds since 1970 | `datetime(ts, 'unixepoch')` or `/1000` |

Almost all of these are stored in UTC. Tools that display local time do so by converting, so always record which timezone your report uses.

### Core challenges

Several obstacles come up repeatedly:

- **Private/incognito browsing** avoids writing history to disk, but it doesn't erase network traces or memory.
- **History clearing** and anti-forensic tools such as CCleaner and BleachBit.
- **Portable browsers** run from USB drives.
- **Browser sync** means activity from another device can appear locally, which is an attribution trap.
- **Encryption** of passwords and cookies is tied to the OS user account.
- **Constant schema changes:** Chrome ships a new major version roughly every four weeks.
- **Locked files** while the browser is running.
- **SQLite write-ahead logs**, which hold recent data outside the main database file.

---

## 2. Acquisition

Acquisition is where browser evidence is most often lost or contaminated. The goal is to collect everything relevant without changing it, and to document that you did so.

### Order of volatility

Follow the standard principle of collecting the most volatile data first:

1. **RAM.** It can hold incognito session content, decrypted cookies and passwords, session tokens, recently typed URLs, open tab content, and DPAPI master keys.
2. **Live system state:** running browser processes, open network connections, the DNS cache (`ipconfig /displaydns`), and open handles.
3. **Disk artifacts:** profile folders, cache, the pagefile, hibernation files, and Volume Shadow Copies.
4. **Remote/cloud sources:** Google account data, Firefox Sync, Microsoft account sync, and ISP or proxy logs.

### Memory acquisition

If the machine is running, and especially if the browser is open or incognito use is suspected, capture memory before shutting anything down. Common tools:

- **Capture:** WinPmem, DumpIt (Magnet/Comae), Magnet RAM Capture, Belkasoft RAM Capturer, and FTK Imager's memory capture. On Linux, AVML or LiME. On macOS, the options are limited because of SIP and Apple Silicon.
- **Analysis:**
  - Volatility 3, using `windows.pslist`, `windows.cmdline`, `windows.memmap --dump` on browser PIDs, and `windows.netscan`.
  - `strings` or `bulk_extractor`, which pulls URLs, emails, domains, and JSON fragments.
  - Keyword searches for URL patterns, and carving SQLite pages out of the process memory of browser processes.

Chromium runs each site in its own renderer process, so dumping every `chrome.exe`/`msedge.exe` process gives very rich results.

### Disk acquisition approaches

**Full disk imaging (dead-box).** This is the gold standard: a write-blocked E01 or raw image made with FTK Imager, Guymager, `dd`/`dc3dd`, or hardware imagers. It preserves unallocated space, which is where carved or deleted SQLite data lives, as well as shadow copies, the pagefile, and hiberfil.sys.

**Targeted/triage collection (live).** This is common in incident response and enterprise work:

- **KAPE** (Eric Zimmerman) has targets such as `WebBrowsers`, `Chrome`, `Edge`, `Firefox`, and `InternetExplorer`. It uses raw disk reads to get past locked files and can collect from VSS.
- **Velociraptor** has artifacts such as `Windows.KapeFiles.Targets`, `Windows.Applications.Chrome.History`, and `Generic.Forensic.SQLiteHunter`.
- **CyLR**, **FTK Imager** (export files from the live drive), and **RawCopy** or similar tools for locked files.
- **macOS:** Aftermath, mac_apt (for images), or a logical collection. Full Disk Access is required for Safari data.

### The critical gotchas

**1. SQLite WAL and journal files.** Modern Chromium and Firefox databases run in Write-Ahead Logging mode. Recent changes sit in `History-wal` (and `-shm`) until they are checkpointed back into the main file. If you copy only `History` without `History-wal`, you can miss the most recent activity, which is often the most important. Always collect the database, `-wal`, `-shm`, and `-journal` files together.

**2. Opening a database can modify it.** If you open a SQLite database in normal read/write mode with a WAL file present, SQLite may checkpoint the WAL into the main database. That changes the file and can overwrite recoverable deleted records in free pages. Follow these rules:

- Always work on copies and hash the originals first.
- Open databases read-only (DB Browser for SQLite has a "Read Only" option; in the CLI use `sqlite3 "file:History?mode=ro"`).
- Be aware that `immutable=1` tells SQLite to ignore the WAL entirely, so you would miss that data.
- Keep a pristine copy of the WAL itself so you can analyze old page versions later.

**3. Locked files.** Chrome locks `History`, `Cookies`, and other files while running. The options are:

- Raw NTFS reads (KAPE, FTK Imager, RawCopy, Velociraptor's NTFS accessor).
- Reading from a Volume Shadow Copy.
- Having the browser closed. Closing it yourself is a judgment call, because it forces writes to disk (session files, a WAL checkpoint).

**4. Multiple profiles and multiple users.** Collect every user's directory and every browser profile. Chromium profiles are `Default`, `Profile 1`, `Profile 2`, and so on; Firefox uses randomly named `xxxxxxxx.default-release` folders. The Chromium `Local State` file maps profile folders to display names and signed-in accounts.

### Encryption considerations

If you want saved passwords, cookie values, or autofill payment data, you need the decryption material, and it differs by platform:

- **Chromium on Windows:**
  - Values are encrypted with AES-GCM using a key stored in `Local State` → `os_crypt.encrypted_key`. That key is protected by DPAPI, so decrypting it needs the user's DPAPI master key: the user's password or hash, the domain backup key, or a live session as that user.
  - Since mid-2024 (around Chrome 127), Chrome on Windows adds **App-Bound Encryption** for cookies, identified by the `v20` prefix. This ties decryption to the Chrome elevation service and SYSTEM-level DPAPI, which makes offline decryption much harder.
  - The `v10` prefix denotes the older scheme.
- **Chromium on macOS:** the key is stored in the Keychain as "Chrome Safe Storage" and needs the user's login keychain password.
- **Chromium on Linux:** the key comes from GNOME Keyring or KWallet. Without either, Chromium falls back to a hardcoded key ("peanuts"), which makes decryption trivial.
- **Firefox:** passwords are in `logins.json`, encrypted with keys in `key4.db` (NSS). With no Primary Password set, decryption is straightforward with tools like `firepwd` or `firefox_decrypt`. With a Primary Password, you need that password.

You don't need any decryption to analyze history, downloads, visit metadata, or cookie *metadata*, including hosts, names, creation times, and expirations.

### Documentation and legal

Record the following:

- Hashes (MD5/SHA-256) of the image and of each extracted file.
- Tool versions and exact commands.
- System time vs. reference time (clock skew).
- The timezone setting of the system.
- Chain of custody.

Make sure your legal authority covers what you're collecting. Cloud-synced data and saved credentials that give access to online accounts may need separate authorization, because accessing a live account is not the same as examining a disk.

### Cloud and mobile sources

- **Cloud:**
  - Google Takeout, or legal process to Google (Chrome Sync history, "My Activity").
  - Microsoft account (Edge sync) and Mozilla (Firefox Sync, which is end-to-end encrypted, so provider-side value is limited).
  - Apple iCloud (Safari history and tabs).
- **Mobile:**
  - **iOS:** Safari's `History.db` lives in the app's container and is available through full file system extractions (GrayKey, Cellebrite, checkm8-based tools), with some data in iTunes/Finder backups.
  - **Android:** Chrome data sits in `/data/data/com.android.chrome/app_chrome/Default/` and needs a full file system extraction.

---

## 3. Browser Artifacts

### Where the data lives

**Chromium browsers (profile root):**

| Browser | Windows | macOS | Linux |
|---|---|---|---|
| Chrome | `%LOCALAPPDATA%\Google\Chrome\User Data\<Profile>\` | `~/Library/Application Support/Google/Chrome/<Profile>/` | `~/.config/google-chrome/<Profile>/` |
| Edge | `%LOCALAPPDATA%\Microsoft\Edge\User Data\<Profile>\` | `~/Library/Application Support/Microsoft Edge/` | `~/.config/microsoft-edge/` |
| Brave | `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data\<Profile>\` | `~/Library/Application Support/BraveSoftware/Brave-Browser/` | `~/.config/BraveSoftware/Brave-Browser/` |
| Opera | `%APPDATA%\Opera Software\Opera Stable\` (profile data is directly here) | `~/Library/Application Support/com.operasoftware.Opera/` | `~/.config/opera/` |

**Firefox:**

- **Windows:** the profile is at `%APPDATA%\Mozilla\Firefox\Profiles\<random>.default-release\`, and the cache is under `%LOCALAPPDATA%\Mozilla\Firefox\Profiles\<random>\cache2\`.
- **macOS:** `~/Library/Application Support/Firefox/Profiles/`, with the cache in `~/Library/Caches/Firefox/Profiles/`.
- **Linux:** `~/.mozilla/firefox/`.
- On every platform, `profiles.ini` in the parent directory lists the profiles.

**Safari (macOS):**

- `~/Library/Safari/` holds `History.db`, `Downloads.plist`, `Bookmarks.plist`, `LastSession.plist`, `TopSites.plist`, and `CloudTabs.db`.
- The cache is at `~/Library/Caches/com.apple.Safari/`.
- Cookies are in `Cookies.binarycookies`, under `~/Library/Containers/com.apple.Safari/Data/Library/Cookies/` on modern macOS (older versions used `~/Library/Cookies/`).

**Internet Explorer / legacy Edge:**

- IE10/11 and legacy Edge use `%LOCALAPPDATA%\Microsoft\Windows\WebCache\WebCacheV01.dat`, an ESE database. Open it with ESEDatabaseView or `esedbexport`, after `esentutl /r` recovery if the database is dirty.
- Older systems use `index.dat` files.
- The `NTUSER.DAT\Software\Microsoft\Internet Explorer\TypedURLs` key holds typed URLs.

### Chromium artifact inventory

| File/Folder | Format | What it contains |
|---|---|---|
| `History` | SQLite | Main history database: see the table list below |
| `Network\Cookies` (Chrome 96+; previously `Cookies` in the profile root) | SQLite | Cookie host, name, path, creation, last access, expiry, and encrypted value; flags such as secure and httponly |
| `Web Data` | SQLite | Autofill form entries (`autofill`), addresses (`autofill_profiles` or newer `local_addresses` tables), saved cards (`credit_cards`), search engines (`keywords`) |
| `Login Data` | SQLite | Saved credentials (`logins`): origin URL, username, encrypted password, date created, last used, times used |
| `Bookmarks` | JSON | Bookmark tree with `date_added` and `date_last_used` (WebKit time); `Bookmarks.bak` is a prior version |
| `Preferences` | JSON | Per-profile settings: signed-in account, download directory, extension settings, site permissions and exceptions with timestamps, zoom levels, and much more |
| `Local State` (in the User Data root) | JSON | Browser-wide state: profile list (`profile.info_cache` with names and emails), encryption key, last version |
| `Favicons` | SQLite | Favicon-to-page mappings, sometimes longer-lived than history |
| `Top Sites` | SQLite | Most frequently visited sites for the New Tab page |
| `Shortcuts` | SQLite | Omnibox text the user typed and the result they selected. Excellent evidence of typing intent |
| `Network Action Predictor` | SQLite | Text typed into the omnibox and the URLs it led to |
| `Sessions\` (`Session_<ts>`, `Tabs_<ts>`) | SNSS binary | Open tabs, windows, and navigation stacks, including back/forward history per tab |
| `Cache\Cache_Data\` | Chromium blockfile (`index`, `data_0`–`data_3`, `f_xxxxxx`) or "simple cache" | Cached pages, images, scripts, and HTTP headers, including server dates |
| `Code Cache\` | Binary | Compiled JavaScript and WASM, keyed by URL |
| `Local Storage\leveldb\` | LevelDB | Key/value data stored by websites; web apps often keep usernames, IDs, and state here |
| `Session Storage\` | LevelDB | Per-tab session storage |
| `IndexedDB\` | LevelDB + blobs | Structured web app databases. Webmail, chat apps (WhatsApp Web, Teams, Slack) store messages here |
| `Service Worker\CacheStorage\` | Cache format | Offline caches of progressive web apps |
| `Extensions\<id>\<version>\` | Folders | Installed extension code; `manifest.json` gives the name and permissions |
| `Media History` | SQLite | Media playback history (may be absent in newer builds) |
| `Visited Links` | Binary hash table | Hashes of visited URLs, used for link coloring. Can prove a visit to a known URL even after history is cleared |
| `TransportSecurity` | JSON | HSTS entries (hashed hostnames) with timestamps |
| `Network Persistent State` | JSON | Network properties of recently contacted servers |
| `History-journal` / `-wal` | SQLite journal | Uncommitted or recent transactions |

### Key tables in Chromium's `History` database

**`urls`**: one row per unique URL.

- Fields: `id`, `url`, `title`, `visit_count`, `typed_count`, `last_visit_time`, `hidden`.
- `typed_count` > 0 means the user typed the URL, or selected it from autocomplete, at least once.

**`visits`**: one row per visit event. This is the timeline.

- `id`, `url` (foreign key to `urls.id`), `visit_time`.
- `from_visit`: the referring visit ID, which lets you reconstruct navigation chains.
- `transition`: how the user got there (see below).
- `visit_duration`: microseconds the page was in the foreground or active, which is approximate.
- `segment_id`, `incremented_omnibox_typed_score`, plus newer columns such as `opener_visit`, `originator_cache_guid` (sync-related), and `is_known_to_sync`. Synced visits from other devices are an attribution consideration.

**`visit_source`**: whether a visit was synced, imported, or local. A source of 0 is sync (from another device), 1 is local browsing, 2 is from an extension, and 3–5 are imported. This is the crucial table for proving activity happened on *this* device.

**`downloads`**: records each downloaded file.

- Paths: `target_path` (the final path) and `current_path`.
- Times: `start_time` and `end_time`.
- Sizes: `received_bytes` and `total_bytes`.
- Status fields:
  - `state`: 0 in progress, 1 complete, 2 cancelled, 3 interrupted.
  - `danger_type`: Safe Browsing verdicts.
  - `interrupt_reason`.
  - `opened`: whether the user opened it from the browser.
  - `last_access_time`.
- Origin fields: `referrer`, `tab_url`, `tab_referrer_url`, `site_url`, `mime_type`, `original_mime_type`, and `by_ext_id` (an extension that initiated the download).

**`downloads_url_chains`**: the full redirect chain of URLs for each download. It matters for malware cases, where the final URL is often a CDN or redirector.

**`keyword_search_terms`**: search terms entered into search engines, linked to `urls`. This is a direct record of intent.

**`segments` / `segment_usage`**: aggregated site usage for Top Sites.

**`content_annotations` / `context_annotations` / `clusters`**: newer "Journeys" features that include page categories and user-facing grouping. Their contents vary by version.

### Chromium transition types

The `transition` value is a bitfield. The lower 8 bits (`transition & 0xFF`) are the core type:

| Value | Type | Meaning |
|---|---|---|
| 0 | LINK | Clicked a link |
| 1 | TYPED | Typed in the omnibox, or chose an autocomplete suggestion |
| 2 | AUTO_BOOKMARK | Opened from a bookmark or Top Sites UI |
| 3 | AUTO_SUBFRAME | Subframe loaded automatically (ads, iframes) |
| 4 | MANUAL_SUBFRAME | User-initiated navigation within a frame |
| 5 | GENERATED | Selected an omnibox suggestion that wasn't a URL (e.g., a search) |
| 6 | AUTO_TOPLEVEL | Start page, or passed on the command line |
| 7 | FORM_SUBMIT | Submitted a form |
| 8 | RELOAD | Reload, or session restore |
| 9 | KEYWORD | Used a keyword search engine shortcut |
| 10 | KEYWORD_GENERATED | Visit generated by a keyword search |

The upper bits are qualifiers:

| Mask | Qualifier |
|---|---|
| `0x01000000` | FORWARD_BACK (back/forward button) |
| `0x02000000` | FROM_ADDRESS_BAR |
| `0x04000000` | HOME_PAGE |
| `0x08000000` | FROM_API (extension/API) |
| `0x10000000` | CHAIN_START (start of a redirect chain) |
| `0x20000000` | CHAIN_END |
| `0x40000000` | CLIENT_REDIRECT (JavaScript or meta refresh) |
| `0x80000000` | SERVER_REDIRECT (HTTP 3xx) |

This distinction is powerful in court. A TYPED visit to a site is far stronger evidence of intent than an AUTO_SUBFRAME load caused by an embedded ad.

### Firefox artifact inventory

| File | Format | Contents |
|---|---|---|
| `places.sqlite` | SQLite | History and bookmarks. `moz_places` (URLs, title, visit count, frecency, `last_visit_date`), `moz_historyvisits` (each visit, `visit_type`, `from_visit`), `moz_bookmarks`, `moz_inputhistory` (typed text → selected URL), `moz_origins`, `moz_annos` (annotations, including download destination and metadata in modern versions) |
| `formhistory.sqlite` | SQLite | Form and search bar entries (`moz_formhistory`: fieldname, value, timesUsed, firstUsed, lastUsed) |
| `cookies.sqlite` | SQLite | `moz_cookies`, stored **unencrypted** |
| `favicons.sqlite` | SQLite | Favicons |
| `logins.json` + `key4.db` | JSON + SQLite | Saved credentials, encrypted with NSS |
| `sessionstore.jsonlz4`, `sessionstore-backups/recovery.jsonlz4`, `previous.jsonlz4`, `upgrade.jsonlz4-*` | mozLz4 (LZ4 with a `mozLz40\0` magic header) | Open windows and tabs, tab history, form data typed into pages, closed tabs and windows. Very valuable |
| `permissions.sqlite` | SQLite | Per-site permissions |
| `storage/default/<origin>/` | SQLite / IndexedDB / LocalStorage | Site storage |
| `webappsstore.sqlite` | SQLite | Legacy DOM storage |
| `extensions.json`, `addons.json` | JSON | Installed add-ons with install dates |
| `prefs.js` | JS | Preferences, including download dir and sync account |
| `cache2/entries/` | Binary | Cache entries with metadata (URL key, fetch count, times) |
| `downloads.sqlite` | SQLite | Downloads in very old versions (pre-v20); now in `moz_annos` |

**Firefox visit types** (`moz_historyvisits.visit_type`):

| Value | Type |
|---|---|
| 1 | LINK |
| 2 | TYPED |
| 3 | BOOKMARK |
| 4 | EMBED |
| 5 | REDIRECT_PERMANENT |
| 6 | REDIRECT_TEMPORARY |
| 7 | DOWNLOAD |
| 8 | FRAMED_LINK |
| 9 | RELOAD |

### Safari artifacts

`History.db` contains `history_items` (URL, domain expansion, visit count) and `history_visits` (visit time in Cocoa seconds, title, `load_successful`, `redirect_source`/`redirect_destination`, `origin`). The `origin` field distinguishes local visits from iCloud-synced ones.

The other files:

- `Downloads.plist`: download URL, path, bytes, and a sandbox bookmark.
- `LastSession.plist`: open tabs.
- `CloudTabs.db`: tabs open on the user's other iCloud devices.
- `Bookmarks.plist`, including the Reading List.
- `TopSites.plist`.
- `Cookies.binarycookies`, a proprietary format parsed with BinaryCookieReader-style scripts.

Also check the macOS quarantine database `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`, which records downloaded files with origin URLs across browsers. It is a strong corroborating source.

### Corroborating artifacts outside the browser

Browser evidence gets much stronger when it's backed up by OS artifacts:

- **Windows `Zone.Identifier` alternate data streams** on downloaded files contain `ZoneId=3`, `HostUrl`, and `ReferrerUrl`. They survive even when browser history is cleared.
- **Prefetch** shows when the browser executable ran. **SRUM** (`SRUDB.dat`) shows network bytes sent and received per application.
- **LNK files and Jump Lists** capture files opened from downloads, and browser jump lists can contain recent or pinned sites.
- **$MFT, $UsnJrnl, and $LogFile** show creation of downloaded files and deletion of history databases.
- **The pagefile, `hiberfil.sys`, and swap** contain fragments of pages and SQLite records, including incognito data.
- **Registry artifacts:** TypedURLs for IE, UserAssist, and BAM/DAM for browser execution.
- **Network sources:** DNS cache, firewall, proxy, and DNS server logs, EDR telemetry, and Windows Timeline (`ActivitiesCache.db`, legacy).

### Private/incognito browsing

Incognito mode keeps history, cookies, and form data in memory and discards them on close. What still remains:

- RAM while the session is open, and page and fragment data in the pagefile, hiberfil, or swap.
- Downloaded files, their `Zone.Identifier` streams, and sometimes download records.
- Bookmarks created during the session, which *are* saved.
- DNS cache and network logs.
- Prefetch and other evidence that the browser ran.
- Some Chromium settings, such as site permissions granted, that may be written to `Preferences`.
- On Windows, some OS-level traces such as thumbnails or jump lists of files opened.

Tor Browser is designed to be far more thorough, but memory and OS artifacts still apply.

### Deleted and cleared data

When a user clears history, SQLite normally deletes the records, but the data often survives in several places:

- **Freelist pages and unallocated space** within the database file. Browsers usually don't VACUUM immediately, though some do periodically.
- **Old page versions** in the WAL file.
- **Other databases the user didn't clear:** Favicons, Top Sites, Shortcuts, Network Action Predictor, cache, session files, Visited Links, and HSTS data. What survives depends on the options chosen in "Clear browsing data."
- **Volume Shadow Copies**, Time Machine backups, and cloud sync.
- **Unallocated disk space,** where you can carve SQLite pages and headers.

Recovery tools include:

- `sqlite3`'s `.recover` command.
- FQLite, Undark, bring2lite, and sqlite_miner.
- Commercial suites such as AXIOM, Belkasoft, and Oxygen, which do page-level carving.
- WAL parsers such as walitean.

---

## 4. Tool: BrowsingHistoryView

### What it is

**BrowsingHistoryView** is a free, portable Windows utility by Nir Sofer (NirSoft). It reads the history databases of multiple browsers and shows everything in **a single unified table**. It's lightweight, needs no installation, and is popular for fast triage and for quick cross-browser answers.

It supports:

- Chromium browsers: Chrome, Edge, Brave, Opera, Vivaldi, and Yandex.
- Firefox and Gecko forks (Waterfox, SeaMonkey, Pale Moon).
- Internet Explorer and legacy Edge, through the WebCache ESE database.
- Safari for Windows (legacy).

### Loading options

Loading is controlled by the **Advanced Options** dialog (F9). There you choose:

**Time filter.** Load only the last X hours or days, or a specific date/time range. The default often loads only the last 10 days, which is a common beginner mistake. Set a wide range, or disable the filter, for a full examination.

**Browsers to load.** Tick or untick each browser family.

**History source.** You can load from:

- The current user.
- All user profiles on the current system.
- A specified profiles root folder, such as `E:\Users` on a mounted image.
- Specific history files you point to directly.
- A remote computer over an admin share (e.g., `\\PC01\c$`), with sufficient privileges.

For forensic use, the key option is loading from a **mounted image or an exported folder** rather than the live system.

### Columns

| Column | Meaning |
|---|---|
| URL | Visited URL |
| Title | Page title |
| Visit Time | Timestamp, in local time by default; GMT can be toggled in Options |
| Visit Count | Total visits to that URL |
| Visited From | Referring URL (from `from_visit` / `from_visit` in Firefox) |
| Visit Type | Translated transition or visit type (Link, Typed, Reload, etc.) |
| Visit Duration | Chromium visit duration |
| Web Browser | Which browser the record came from |
| User Profile | Windows user profile |
| Browser Profile | Browser profile name or folder |
| URL Length | Useful for spotting encoded or exfil-style URLs |
| Typed Count | Chromium typed count |
| History File | Full path of the source database. Important for provenance |
| Record ID | Row ID in the source database |

### Output and reporting

You can sort, filter, and search; select rows and copy them as tab-delimited text; and export to HTML, CSV, tab-delimited, XML, and JSON (newer versions). The HTML reports are simple, readable exhibits.

### Command-line use

BrowsingHistoryView supports command-line operation for scripted collection:

```
BrowsingHistoryView.exe /HistorySource 2 /VisitTimeFilterType 1 /LoadIE 1 /LoadFirefox 1 /LoadChrome 1 /LoadSafari 1 /scomma C:\Cases\001\history.csv
```

- `/scomma`, `/stab`, `/shtml`, `/sxml`, `/sjson` save to the respective formats without showing the GUI.
- `/HistorySource` chooses the source: current user, all users, a profiles folder given with `/HistorySourceFolder`, or custom files.
- `/VisitTimeFilterType` and related switches control the time filter.
- `/cfg <file>` loads a saved configuration, which is useful for making runs repeatable.

The exact numeric values for switches like `/HistorySource` differ slightly between versions. Check the readme or the NirSoft page for your version, and record the `.cfg` file you used alongside your case notes.

### Strengths

- Very fast, portable, and free.
- One view across all browsers and all user profiles, which is excellent for "what did anyone do on this machine between 14:00 and 15:00?"
- Translates transition types and handles each browser's timestamp epoch for you.
- Good for triage, for verifying other tools' output, and for quick exhibits.

### Limitations and forensic cautions

- **History only.** It does not parse cache, cookies, downloads, autofill, sessions, LevelDB storage, or extensions. NirSoft has separate companion tools for those:
  - Cache: ChromeCacheView, MozillaCacheView, IECacheView.
  - Downloads: BrowserDownloadsView.
  - Cookies: ChromeCookiesView and MZCookiesView.
  - Other artifacts: BrowserAddonsView for extensions, WebBrowserPassView for passwords (live system), ESEDatabaseView for WebCache, and MyLastSearch for search queries.
- **No deleted record recovery.** It shows only live records.
- **Running it on a live suspect system changes that system:** Prefetch entries, file access times, possible WAL checkpoints, and memory changes. Prefer running it on an analysis workstation against a read-only mounted image (Arsenal Image Mounter, FTK Imager "Mount Image") or exported copies that include the `-wal` files.
- **Timezone:** confirm whether you're displaying local or GMT, and which machine's local time. The analysis workstation's timezone, not the suspect's, is applied by default.
- **Antivirus products** sometimes flag NirSoft tools as "potentially unwanted" because some of them recover passwords. Whitelist it on analysis machines.
- **Validation:** as with any tool, spot-check key findings against the raw database or a second tool.

### Typical workflow

1. Mount the evidence image read-only.
2. Open BrowsingHistoryView, press F9, choose "Load history from the specified profiles folder" pointing at `X:\Users`, disable the time filter, and tick all browsers.
3. Sort by Visit Time and filter by the incident window.
4. Use Visit Type to separate typed or linked navigation from automatic subframe noise.
5. Export to CSV and HTML, hash the exports, and record the settings.
6. Move to deeper tools for downloads, cache, and storage.

---

## 5. Manual Browser Analysis

Tools make you fast, but manual analysis makes you correct. Doing it by hand lets you verify tool output, handle new schema versions tools don't support yet, and explain your findings under cross-examination.

### Toolkit

- **SQLite:** DB Browser for SQLite (use read-only mode), the `sqlite3` CLI, and SQLiteStudio.
- **Batch parsing:** SQLECmd (Eric Zimmerman), which runs community "maps" of SQL queries against every SQLite database it finds. It is great with KAPE output.
- **JSON:** any viewer, `jq`, or VS Code.
- **LevelDB and IndexedDB:** `ccl_chromium_reader` (Alex Caithness, CCL Solutions), the reference Python library for Chromium LevelDB, IndexedDB, Local and Session Storage, cache, and SNSS session files.
- **mozLz4:** decompress with Python's `lz4` library. Strip the 8-byte `mozLz40\0` magic and 4-byte size, then decompress the block. Or use tools like `dejsonlz4`.
- **Timestamp conversion:** DCode (Digital Detective), CyberChef, or simple Python.
- **URL decoding and parsing:** CyberChef and Unfurl.
- **Timelining:** plaso/log2timeline has parsers for Chrome, Firefox, Safari, and MSIE. Timeline Explorer is good for reviewing CSVs.

### Step 1: Scope the environment

- **Identify browsers:**
  - Program Files and AppData installs.
  - Uninstall registry keys; per-user installs are common for Chrome.
  - Prefetch, Amcache, and ShimCache for execution.
  - Portable browser folders on USB drives (check LNK files and ShellBags).
- **Identify profiles:**
  - Chromium's `Local State`: `profile.info_cache` maps `Profile 1` → "Work", `user@company.com`.
  - Firefox's `profiles.ini`.
- **Check sync and accounts:** look in `Preferences` under `account_info` and `google.services`, and in Firefox's `prefs.js` for `services.sync.username`.
- **Record browser version:** `Last Version` in the User Data folder, and `Local State`. It tells you which schema to expect.

### Step 2: Chromium history queries

**Full visit timeline with transitions:**

```sql
SELECT
  v.id                                   AS visit_id,
  datetime(v.visit_time/1000000 - 11644473600, 'unixepoch') AS visit_utc,
  u.url,
  u.title,
  v.transition & 0xFF                    AS core_transition,
  CASE v.transition & 0xFF
    WHEN 0 THEN 'LINK'        WHEN 1 THEN 'TYPED'
    WHEN 2 THEN 'AUTO_BOOKMARK' WHEN 3 THEN 'AUTO_SUBFRAME'
    WHEN 4 THEN 'MANUAL_SUBFRAME' WHEN 5 THEN 'GENERATED'
    WHEN 6 THEN 'AUTO_TOPLEVEL' WHEN 7 THEN 'FORM_SUBMIT'
    WHEN 8 THEN 'RELOAD'      WHEN 9 THEN 'KEYWORD'
    WHEN 10 THEN 'KEYWORD_GENERATED' END AS transition_name,
  (v.transition & 0x80000000) != 0       AS server_redirect,
  (v.transition & 0x40000000) != 0       AS client_redirect,
  v.visit_duration/1000000.0             AS duration_sec,
  v.from_visit
FROM visits v
JOIN urls u ON v.url = u.id
ORDER BY v.visit_time;
```

**Local vs. synced visits.** Visits that don't appear in `visit_source` are local.

```sql
SELECT v.id, u.url,
       datetime(v.visit_time/1000000 - 11644473600, 'unixepoch') AS visit_utc,
       COALESCE(vs.source, 1) AS source  -- 0 = synced, 1 = local
FROM visits v
JOIN urls u ON v.url = u.id
LEFT JOIN visit_source vs ON vs.id = v.id
ORDER BY v.visit_time;
```

**Downloads with their full redirect chains:**

```sql
SELECT
  d.id,
  datetime(d.start_time/1000000 - 11644473600, 'unixepoch') AS start_utc,
  datetime(d.end_time/1000000 - 11644473600, 'unixepoch')   AS end_utc,
  d.target_path, d.received_bytes, d.total_bytes,
  CASE d.state WHEN 0 THEN 'IN_PROGRESS' WHEN 1 THEN 'COMPLETE'
               WHEN 2 THEN 'CANCELLED' WHEN 3 THEN 'INTERRUPTED' END AS state,
  d.danger_type, d.interrupt_reason, d.opened,
  d.mime_type, d.referrer, d.tab_url,
  c.chain_index, c.url AS chain_url
FROM downloads d
LEFT JOIN downloads_url_chains c ON c.id = d.id
ORDER BY d.start_time, c.chain_index;
```

**Search terms (intent):**

```sql
SELECT k.term,
       u.url,
       datetime(u.last_visit_time/1000000 - 11644473600, 'unixepoch') AS last_visit_utc
FROM keyword_search_terms k
JOIN urls u ON u.id = k.url_id
ORDER BY u.last_visit_time;
```

**Omnibox typing evidence (`Shortcuts` database):**

```sql
SELECT text, fill_into_edit, url, contents,
       datetime(last_access_time/1000000 - 11644473600, 'unixepoch') AS last_access_utc,
       number_of_hits
FROM omni_box_shortcuts
ORDER BY last_access_time;
```

**Cookie metadata (`Network\Cookies`), which needs no decryption:**

```sql
SELECT host_key, name, path,
       datetime(creation_utc/1000000 - 11644473600, 'unixepoch')    AS created_utc,
       datetime(last_access_utc/1000000 - 11644473600, 'unixepoch') AS last_access,
       datetime(expires_utc/1000000 - 11644473600, 'unixepoch')     AS expires,
       is_secure, is_httponly, is_persistent
FROM cookies
ORDER BY creation_utc;
```

**Autofill (`Web Data`):**

```sql
SELECT name, value, count,
       datetime(date_created, 'unixepoch')   AS first_used_utc,
       datetime(date_last_used, 'unixepoch') AS last_used_utc
FROM autofill
ORDER BY date_last_used;
```

Autofill times here are Unix seconds, not WebKit microseconds. This inconsistency within a single browser is exactly why you should confirm the epoch of every field.

**Saved logins metadata (`Login Data`):**

```sql
SELECT origin_url, action_url, username_value,
       datetime(date_created/1000000 - 11644473600, 'unixepoch')  AS created_utc,
       datetime(date_last_used/1000000 - 11644473600, 'unixepoch') AS last_used_utc,
       times_used
FROM logins;
```

### Step 3: Firefox queries

**Visit timeline:**

```sql
SELECT datetime(v.visit_date/1000000, 'unixepoch') AS visit_utc,
       p.url, p.title,
       CASE v.visit_type
         WHEN 1 THEN 'LINK' WHEN 2 THEN 'TYPED' WHEN 3 THEN 'BOOKMARK'
         WHEN 4 THEN 'EMBED' WHEN 5 THEN 'REDIRECT_PERMANENT'
         WHEN 6 THEN 'REDIRECT_TEMPORARY' WHEN 7 THEN 'DOWNLOAD'
         WHEN 8 THEN 'FRAMED_LINK' WHEN 9 THEN 'RELOAD' END AS visit_type,
       v.from_visit
FROM moz_historyvisits v
JOIN moz_places p ON p.id = v.place_id
ORDER BY v.visit_date;
```

**Downloads, which are stored as annotations:**

```sql
SELECT p.url AS source_url,
       n.name AS attribute,
       a.content,
       datetime(a.dateAdded/1000000, 'unixepoch') AS added_utc
FROM moz_annos a
JOIN moz_anno_attributes n ON n.id = a.anno_attribute_id
JOIN moz_places p ON p.id = a.place_id
WHERE n.name LIKE 'downloads/%'
ORDER BY a.dateAdded;
```

`downloads/destinationFileURI` gives the local path. `downloads/metaData` is JSON containing the state, end time, and file size.

**Typed input to selected URL:**

```sql
SELECT i.input, p.url, i.use_count
FROM moz_inputhistory i JOIN moz_places p ON p.id = i.place_id;
```

**Form history:**

```sql
SELECT fieldname, value, timesUsed,
       datetime(firstUsed/1000000, 'unixepoch') AS first_utc,
       datetime(lastUsed/1000000, 'unixepoch')  AS last_utc
FROM moz_formhistory ORDER BY lastUsed;
```

**Session store decompression in Python:**

```python
import lz4.block, json
with open("recovery.jsonlz4", "rb") as f:
    assert f.read(8) == b"mozLz40\0"
    data = lz4.block.decompress(f.read())
session = json.loads(data)
for w in session["windows"]:
    for tab in w["tabs"]:
        for entry in tab["entries"]:
            print(entry.get("url"), entry.get("title"))
```

Also look at `_closedWindows`, `_closedTabs`, and form data captured per entry. Text typed into web forms that were never submitted can show up here.

### Step 4: Safari query

```sql
SELECT datetime(v.visit_time + 978307200, 'unixepoch') AS visit_utc,
       i.url, v.title, v.load_successful, v.origin,
       v.redirect_source, v.redirect_destination
FROM history_visits v
JOIN history_items i ON i.id = v.history_item
ORDER BY v.visit_time;
```

### Step 5: Cache, storage, and extensions

**Cache:**

- Use ChromeCacheView or MozillaCacheView, or `ccl_chromium_reader` for Chromium cache.
- The HTTP response headers include the server `Date:` header, which is an independent clock you can use to check system clock tampering.
- Cached images and documents can reconstruct what the user actually saw.

**Local Storage and IndexedDB:**

- Use `ccl_chromium_reader`, which handles LevelDB-encoded values, including deleted records still present in `.ldb` and `.log` files.
- This is where you find web versions of chat apps (Teams, Slack, WhatsApp Web, Discord), webmail state, and cloud drive metadata.

**Extensions:**

- Enumerate `Extensions\<id>` folders and read each `manifest.json` for the name and requested permissions.
- Cross-check against `Preferences` → `extensions.settings`, which includes install time and source.
- Malicious extensions are a common way to steal credentials and cookies in IR cases. Look for extensions installed outside the Web Store, heavy permissions like `<all_urls>`, `cookies`, or `webRequest`, and recent install times near the incident.

**Session files (Chromium SNSS):**

- Parse with `ccl_chromium_reader` or Hindsight.
- They recover tabs and navigation entries, sometimes including pages no longer in history.

### Step 6: Recovery of deleted records

1. Check whether the database has freelist pages (`PRAGMA freelist_count;` on a copy).
2. Run the SQLite CLI's `.recover` on a copy: `sqlite3 copy.db ".recover" > recovered.sql`.
3. Parse WAL frames with a WAL parser. Older versions of pages may contain deleted rows.
4. Carve for SQLite headers (`SQLite format 3\0`) and page patterns in unallocated space, VSS, and the pagefile using FQLite, bulk_extractor, or commercial tools.
5. Compare against Favicons, Top Sites, Shortcuts, cache, and Visited Links for traces of cleared history.

### Step 7: Correlate and build the timeline

Merge browser events with file system activity ($MFT, USN journal), Prefetch, event logs, LNK and Jump Lists, `Zone.Identifier` streams, and SRUM network usage. A defensible narrative typically looks like this:

1. The user searched for X (`keyword_search_terms`, TYPED).
2. They clicked a result (LINK visit with `from_visit` → the search).
3. They downloaded Y (`downloads` + `downloads_url_chains`).
4. The file landed on disk (USN journal, `Zone.Identifier` with HostUrl).
5. They executed it (Prefetch, Amcache).
6. Network activity followed (SRUM, EDR).

### Common interpretation pitfalls

- **Visit count ≠ user intent.** Redirects, reloads, and auto-loaded frames inflate counts. Use transition types.
- **Visit duration is approximate** and can be misleading when tabs sit idle.
- **Synced visits** may come from a different device, so check `visit_source`. For Safari, check the `origin` field.
- **Autocomplete:** "TYPED" includes accepting an omnibox suggestion after typing a few characters.
- **Title changes:** `urls.title` reflects the *latest* title for that URL, not necessarily what was shown at the earlier visit.
- **Timezone and epoch errors** are the most common source of wrong conclusions.
- **Prefetching and preloading:** Chromium can prefetch pages, but prefetched pages don't generally create visit records.
- **Shared accounts:** a browser profile does not equal a person. Corroborate with logon sessions and other attribution evidence.

---

## 6. Hindsight Framework

### What it is

**Hindsight** is a free, open-source tool by **Ryan Benson** (Obsidian Forensics) for in-depth analysis of **Chromium-based browsers**: Chrome, Edge, Brave, Opera, and others, including Chromium-based Electron apps in many cases.

Its core value is that it understands Chrome's schema history. It inspects the databases to infer the Chrome version range, then applies the correct parsing logic for that version. This matters because columns and file locations have changed many times over the years.

Hindsight parses many artifacts into **one chronological timeline**:

- URL visits, with decoded transitions.
- Downloads.
- Cache records, including HTTP header info.
- Cookies (metadata, and values when decryptable).
- Autofill entries.
- Saved login records (metadata).
- Bookmarks and bookmark folders.
- Preferences, including timestamps buried in `Preferences` such as site engagement, content settings, and profile creation.
- Local Storage, Session Storage, and IndexedDB (via `ccl_chromium_reader`).
- File System API storage.
- Extensions, with their names and details.
- Session and tab data, site characteristics, and other version-dependent artifacts.

### Installation and forms

Hindsight comes in several forms:

- A Python package: `pip install pyhindsight`, which provides the `hindsight.py` and `hindsight_gui.py` entry points.
- Compiled Windows executables (`hindsight.exe`, `hindsight_gui.exe`) from the project's GitHub releases.
- A browser-based GUI. `hindsight_gui.py` starts a small local web server, typically at `http://localhost:8080`. You set the input path, choose plugins and output format, run it, and download the results.

### Command-line usage

A typical run against an extracted profile:

```
hindsight.py -i "E:\Case001\Users\jdoe\AppData\Local\Google\Chrome\User Data\Default" -o jdoe_chrome_default -f xlsx -t UTC -l jdoe_hindsight.log
```

The main arguments are:

- `-i` / `--input`: the profile directory. Point it at the **profile folder** (`Default`, `Profile 1`), not `User Data`.
- `-o` / `--output`: the output file name.
- `-f` / `--format`: `xlsx` (default), `jsonl`, or `sqlite`.
- `-b` / `--browser_type`: Chrome or Brave, for Brave-specific handling.
- `-c` / `--cache`: a custom cache location, if the cache is stored elsewhere. On Windows, Chrome's cache is inside the profile, but on some platforms it is separate.
- `-t` / `--timezone`: display timezone.
- `-l` / `--log`: log file. Keep it for your case notes.
- `--temp_dir`: a working location for copies of the input files.
- Decryption-related options, which apply mainly to Linux and macOS cookie and password decryption where the key material is available.

Arguments change between releases, so run `hindsight.py --help` for your version and record it.

### Output

The **XLSX output** is the most commonly used. It typically includes:

- **Timeline sheet:** every timestamped event in one sorted list, with columns such as:
  - Type (url, download, cookie, autofill, bookmark, preference, etc.).
  - Timestamp, URL, Title/Name/Status, Data/Value/Path.
  - An **Interpretation** column filled in by plugins.
  - Visit-specific fields like transition and duration.
  - The profile and the source file for provenance.
- **Storage sheet(s):** Local Storage, Session Storage, IndexedDB, and file system entries.
- **Installed Extensions** and other supporting sheets, depending on the version.

The **SQLite** output is useful if you want to run your own queries over the normalized data. **JSONL** is ideal for loading into Timesketch, Elastic, Splunk, or other pipelines.

### Plugins

Hindsight's plugin system adds interpretation on top of the raw values. It ships with plugins such as:

- **Chrome Extension Names:** maps extension IDs to readable names.
- **Google Analytics cookie parser:** decodes `__utma`, `__utmb`, `__utmz`, and similar cookies. `__utma` embeds first, previous, and current visit timestamps; `__utmz` can include campaign and search referral data. These can show visits to a site even after history is cleared.
- **Google Searches:** extracts search terms from Google URLs.
- **Query String Parser:** breaks URL parameters out into readable form.
- **Unfurl integration:** Unfurl, also by Ryan Benson, deconstructs URLs. It decodes embedded timestamps (Twitter/X snowflake IDs, Discord IDs, Google `ei`/`ved` parameters, UUIDv1), base64 segments, redirect wrappers, and more.
- **Generic Timestamp Decoder:** identifies timestamp-like values in cookies and storage.
- **Load Balancer Cookies decoder:** some load balancer cookies encode internal IPs and ports.
- **Quantcast cookies** and other tracking cookie parsers.
- **Time Discrepancy Finder:** flags inconsistencies that may indicate clock changes.

You can also write custom plugins in Python, which is handy for recurring case types such as extracting IDs from a specific web app's storage.

### Hindsight in a workflow

1. Acquire the profile folder completely, including `-wal`, `-journal`, `Cache`, `Local Storage`, `IndexedDB`, and `Sessions`, from the image or KAPE output.
2. Run Hindsight on **each profile separately** (`Default`, `Profile 1`, and so on). For Edge and Brave, point at their profile folders the same way.
3. Open the XLSX and filter the Timeline by your incident window and artifact types.
4. Pivot on key events. For example, a download of `invoice.iso` has a referrer URL. From there you find the preceding visit to a webmail domain, then the cookies set for the phishing domain, then the Local Storage keys created by the phishing kit.
5. Validate critical rows against the raw SQLite with the queries from Section 5.
6. Export JSONL into your super-timeline alongside plaso and EZ Tools output.

### Strengths and limitations

**Strengths:**

- Deep, version-aware Chromium parsing.
- A unified timeline across many artifact types, not just history.
- Interpretation plugins that turn opaque values into evidence.
- Free and open source, so it's peer-reviewable. Methodology you can explain is a real advantage in court.
- Actively maintained, with support for LevelDB-based storage.

**Limitations:**

- **Chromium only.** Use other tools for Firefox and Safari: plaso, Dumpzilla or custom scripts for Firefox, mac_apt or APOLLO-style tools for Safari, or commercial suites.
- **Not a deleted-record carver.** Pair it with SQLite recovery tools for cleared history.
- **Decryption of Windows cookies and passwords** depends on having DPAPI material, and App-Bound Encryption complicates that further.
- **Very new Chrome versions** may introduce artifacts before Hindsight supports them, so check release notes and validate manually.

### How Hindsight compares to BrowsingHistoryView

| | BrowsingHistoryView | Hindsight |
|---|---|---|
| Scope | History only | History, downloads, cache, cookies, autofill, logins, bookmarks, preferences, storage, extensions, sessions |
| Browsers | Chromium, Gecko, IE/Edge legacy, Safari (Win) | Chromium family only |
| Depth | Surface-level, fast | Deep, version-aware, interpreted |
| Best for | Rapid multi-browser triage, quick exhibits, cross-validation | Full examination of Chromium profiles, IR on phishing and malware, detailed timelines |
| Platform | Windows GUI/CLI | Python (Win/macOS/Linux), CLI + web GUI |
| Cost / source | Free, closed source | Free, open source |

In practice, examiners often use both. BrowsingHistoryView gives a fast overview across every browser and user. Hindsight goes deep on the Chromium profiles that matter. Manual SQL queries confirm the key findings.

---

## Putting It All Together: A Reference Methodology

1. **Preserve:** capture RAM if the system is live, then image the disk or run a targeted collection (KAPE or Velociraptor) that includes WAL, journal, and VSS copies. Hash everything.
2. **Scope:** identify browsers, users, profiles, versions, and sync accounts (`Local State`, `profiles.ini`, registry, Prefetch).
3. **Triage:** run BrowsingHistoryView across all users and browsers on a read-only mounted image to find the time windows and sites of interest.
4. **Deep parse:**
   - Chromium profiles: Hindsight.
   - Firefox: SQL queries plus session store decompression.
   - Safari: `History.db` plus plists.
   - Legacy IE: ESEDatabaseView.
   - Cache: ChromeCacheView or MozillaCacheView.
   - LevelDB: `ccl_chromium_reader`.
5. **Recover:** use SQLite `.recover`, WAL analysis, and carving from unallocated space, VSS, and the pagefile. Check the secondary databases that survive clearing.
6. **Correlate:** combine with `Zone.Identifier`, $MFT/USN, Prefetch/Amcache, LNK/Jump Lists, SRUM, event logs, and network logs, and build a super-timeline.
7. **Interpret carefully:** confirm epochs and timezones, use transition types to separate intent from noise, check `visit_source` for sync, and attribute to a person, not just a profile.
8. **Validate and report:** cross-check key facts with a second method, document tool versions and commands, and present findings in plain language with raw-source references (file path and record ID) for every claim.
