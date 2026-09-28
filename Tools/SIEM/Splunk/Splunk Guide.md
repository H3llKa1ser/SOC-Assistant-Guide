# Splunk: A Complete Deep Dive

This guide covers Splunk from the ground up, from what it is and how it's built, through installation, data onboarding, searching, reporting, alerting, dashboards, health monitoring, and user administration. Commands and configuration examples reflect Splunk Enterprise 9.x/10.x. Always check the official documentation for your specific version, because defaults and UI paths shift between releases.

---

## 1. Introduction to Splunk

### What Splunk is

Splunk is a platform for collecting, indexing, searching, analyzing, and visualizing machine-generated data. That includes logs, metrics, events, and any other timestamped text that servers, applications, network devices, cloud services, and security tools produce. Its core idea is "schema on read." You ingest raw data mostly as-is, and structure (fields) is applied at search time rather than being forced into a rigid database schema up front. This lets you onboard messy, heterogeneous data quickly and decide later what questions to ask of it.

Splunk was founded in 2003, and Cisco completed its acquisition of Splunk in March 2024. Common use cases include IT operations monitoring and troubleshooting, security (SIEM, threat hunting, compliance), application performance and observability, business analytics, and IoT/OT monitoring.

### The product family

**Splunk Enterprise** is the self-managed software you install on your own servers or cloud VMs. **Splunk Cloud Platform** is the same core engine delivered as a SaaS service managed by Splunk. On top of the core platform sit premium solutions. **Splunk Enterprise Security (ES)** is the SIEM. **Splunk ITSI (IT Service Intelligence)** provides service-level monitoring with KPIs. **Splunk SOAR** handles security orchestration and automated response. **Splunk Observability Cloud** covers APM, infrastructure monitoring, RUM, and synthetics. There are also thousands of free apps and add-ons on **Splunkbase** (splunkbase.splunk.com). These provide parsing, field extractions, and dashboards for specific technologies such as Windows, Linux, AWS, Palo Alto, and Cisco.

### Licensing

Splunk Enterprise is traditionally licensed by **ingest volume**, measured in GB of data indexed per day. Searching data costs nothing extra. Only indexing counts. Splunk also offers **workload-based** licensing, which is based on compute capacity rather than data volume and is common in Splunk Cloud. A new Enterprise download starts as a **60-day trial** with 500 MB/day of indexing. After the trial it can be converted to **Splunk Free**, which keeps 500 MB/day but removes authentication (everyone is admin), alerting, scheduled searches, distributed search, and forwarding to third parties. If you exceed your license volume repeatedly within a rolling window, Splunk raises license warnings, and on older versions or some license types search can be restricted. Enterprise licenses in modern versions generally keep search working even under violation.

### Core architecture and components

Splunk is built from a single binary (`splunkd`) that can take on different roles depending on configuration.

The **forwarder** collects data at the source and sends it on. The **Universal Forwarder (UF)** is a lightweight, separate package with no UI and minimal parsing. The **Heavy Forwarder (HF)** is a full Splunk Enterprise instance configured to forward. It can parse, filter, mask, and route data before sending it on.

The **indexer** receives data, parses it into events, and writes it to disk in indexes. It also executes the search-time work against its local data when a search head asks.

The **search head** is where users log in, run searches, and build reports, alerts, and dashboards. In distributed environments it dispatches searches to indexers (the "search peers") and merges the results.

Supporting management roles include the **Deployment Server**, which pushes configuration apps to forwarders. The **Cluster Manager** (formerly "master node") manages indexer clusters for data replication. The **Search Head Cluster Deployer** distributes configuration to search head cluster members. The **License Manager** centrally tracks license usage. The **Monitoring Console** provides health and performance visibility.

A small deployment can run everything on one server (a "standalone" instance). Larger deployments split roles: many forwarders feed an indexer cluster, and one or more search heads (possibly a search head cluster) sit on top.

### The data pipeline

Data moves through four conceptual tiers. **Input** is where data is acquired (files, network ports, APIs, scripts) and tagged with metadata. **Parsing** is where the stream is broken into individual events, timestamps are identified, and index-time transforms apply (masking, routing, dropping). **Indexing** is where events are compressed and written to disk along with a keyword index (the "tsidx" files). **Search** is where users query indexed data using SPL (Search Processing Language).

Internally, the parsing and indexing stages run as a series of queues: parsingQueue, aggQueue (line merging and timestamping), typingQueue (regex transforms), and indexQueue. Blocked queues are one of the most important health signals you'll learn to watch.

### Key default fields

Every event in Splunk carries some metadata fields. `_raw` is the original event text. `_time` is the event timestamp, stored as epoch time. `host` is the originating machine. `source` is the file path, port, or input name the data came from. `sourcetype` identifies the format of the data (for example `access_combined`, `WinEventLog:Security`, `syslog`) and drives how it's parsed. `index` is the index the event was stored in. There are also internal fields like `_indextime`, `splunk_server`, `linecount`, and `punct`.

### Indexes and buckets

An **index** is a logical data store, a collection of directories on disk. Splunk ships with internal indexes: `_internal` holds Splunk's own logs, `_audit` holds audit trail data, `_introspection` holds resource usage data, and `_telemetry` and `_configtracker` serve other internal purposes. `main` is the default index for data that doesn't specify one. You should create dedicated indexes for your data, separated by retention needs, access control, and data type.

Inside an index, data is stored in **buckets** that age through stages:

| Stage | Description |
|---|---|
| Hot | Actively being written to; searchable |
| Warm | Rolled from hot, read-only, still on fast storage |
| Cold | Older data, often moved to cheaper storage |
| Frozen | Past retention; deleted by default, or archived if configured |
| Thawed | Frozen archives manually restored for searching |

Retention is controlled by settings such as `frozenTimePeriodInSecs` (age-based) and `maxTotalDataSizeMB` (size-based) in `indexes.conf`. Splunk Enterprise can also use **SmartStore**, which keeps warm buckets in S3-compatible object storage with a local cache.

### Configuration files and precedence

Almost everything in Splunk is controlled by `.conf` files in `$SPLUNK_HOME/etc`. Key files include `inputs.conf` (data inputs), `outputs.conf` (forwarding), `props.conf` and `transforms.conf` (parsing and field extraction), `indexes.conf` (index definitions), `savedsearches.conf` (reports and alerts), `authorize.conf` (roles), `authentication.conf` (auth methods), `server.conf` (server settings), and `web.conf` (Splunk Web).

Each file can exist in many places, and Splunk merges them with a precedence order. In the global context, `etc/system/local` wins first, then app `local` directories, then app `default` directories, and finally `etc/system/default` is lowest. **Never edit files in any `default` directory.** They're overwritten on upgrade. Put your changes in `local`, ideally inside a custom app. To see the effective merged configuration and which file each setting comes from, use btool:

```bash
$SPLUNK_HOME/bin/splunk btool inputs list --debug
$SPLUNK_HOME/bin/splunk btool props list access_combined --debug
```

### Default network ports

| Port | Purpose |
|---|---|
| 8000 | Splunk Web (browser UI) |
| 8089 | splunkd management/REST API (also used by deployment server) |
| 9997 | Conventional receiving port for forwarder traffic (must be enabled) |
| 8088 | HTTP Event Collector (HEC) |
| 8191 | KV Store |
| 8080 | Indexer cluster replication (common default) |
| 514 | Syslog (if you configure a UDP/TCP input for it) |

---

## 2. Splunk Installation on Windows

### Prerequisites

Check the system requirements for your version. Splunk Enterprise runs on supported 64-bit Windows Server versions and Windows 10/11. For anything beyond a lab, Splunk's reference hardware for an indexer is roughly 12+ CPU cores, 12+ GB RAM, and fast storage delivering around 800 IOPS. A test instance runs fine on far less. You need local administrator rights to install. Decide which account Splunk will run as. The **Local System** account works for most local data collection. A **domain account** (or managed service account) is needed if Splunk must read remote resources such as network shares, remote event logs via WMI, or remote performance counters. Newer installers also offer a lower-privileged virtual account option.

### Download

Log in to splunk.com, go to the Splunk Enterprise free trial/download page, choose Windows, and download the `.msi` installer, which looks like `splunk-<version>-<build>-windows-x64.msi`.

### GUI installation

Run the MSI as administrator and accept the license agreement. Click **Customize Options** if you want to change the install path (default `C:\Program Files\Splunk`), choose the service account, or skip creating a Start Menu shortcut. Create the administrator username and password when prompted. Modern Splunk requires you to set these at install time rather than using the old default `admin/changeme`. Complete the installation. Splunk installs two Windows services, `Splunkd Service` (the core engine) and, on older versions, `splunkweb` (legacy). Modern versions run the web interface within splunkd. Once installation finishes, open `http://localhost:8000` and log in with the admin credentials you created.

### Silent/command-line installation

For automated deployments, use `msiexec` from an elevated command prompt:

```cmd
msiexec.exe /i splunk-10.x.x-xxxx-windows-x64.msi ^
  AGREETOLICENSE=Yes ^
  SPLUNKUSERNAME=admin ^
  SPLUNKPASSWORD="Str0ngP@ssw0rd!" ^
  INSTALLDIR="D:\Splunk" ^
  WEB_PORT=8000 ^
  SPLUNKD_PORT=8089 ^
  LAUNCHSPLUNK=1 ^
  /quiet /L*v splunk_install.log
```

The `/L*v` log file is invaluable if the install fails silently.

### Managing Splunk on Windows

From an elevated prompt:

```cmd
cd "C:\Program Files\Splunk\bin"
splunk status
splunk start
splunk stop
splunk restart
splunk version
```

You can also manage the `Splunkd` service through `services.msc` or PowerShell (`Restart-Service splunkd`).

### Post-install tasks

Open Windows Firewall for the ports you need. Port 8000 is for web access, 8089 for management, and 9997 if the instance will receive forwarder data. For example:

```powershell
New-NetFirewallRule -DisplayName "Splunk Web" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
New-NetFirewallRule -DisplayName "Splunk Receiving" -Direction Inbound -Protocol TCP -LocalPort 9997 -Action Allow
```

Exclude the Splunk installation and index directories from antivirus real-time scanning. AV scanning Splunk's bucket files causes serious performance problems and can corrupt buckets. Apply a license under **Settings > Licensing** if you have one. Consider enabling HTTPS for Splunk Web under **Settings > Server settings > General settings**.

---

## 3. Splunk Installation on Linux

### Prerequisites and OS tuning

Splunk supports major 64-bit distributions: RHEL, Rocky, Alma, Oracle Linux, CentOS Stream, Ubuntu, Debian, SUSE, and Amazon Linux. Before installing a production instance, apply a few OS tunings that Splunk explicitly recommends.

First, raise ulimits for the Splunk user. Open files should be at least 64000, and user processes at least 16000. With systemd-managed Splunk, these are set in the unit file (`LimitNOFILE`, `LimitNPROC`).

Second, disable Transparent Huge Pages (THP), which degrades Splunk performance:

```bash
echo never > /sys/kernel/mm/transparent_hugepage/enabled
echo never > /sys/kernel/mm/transparent_hugepage/defrag
```

Make this persistent through a systemd unit, tuned profile, or kernel boot parameter (`transparent_hugepage=never`).

Third, keep time synchronized with chrony or NTP. Timestamps are central to everything Splunk does.

### Create a dedicated user

Never run Splunk as root in production.

```bash
sudo useradd -m -r -s /bin/bash splunk
```

(Recent RPM/DEB packages can create a `splunk` user automatically, but creating it yourself gives you control.)

### Option A: Tarball (.tgz) install

This is the most flexible and most common method.

```bash
cd /tmp
wget -O splunk.tgz "<download-link-from-splunk.com>"
sudo tar -xzvf splunk.tgz -C /opt
sudo chown -R splunk:splunk /opt/splunk
```

### Option B: RPM (RHEL-family)

```bash
sudo rpm -ivh splunk-10.x.x-xxxx.x86_64.rpm
# or
sudo dnf install ./splunk-10.x.x-xxxx.x86_64.rpm
```

### Option C: DEB (Debian/Ubuntu)

```bash
sudo dpkg -i splunk-10.x.x-xxxx-linux-amd64.deb
```

All three methods install to `/opt/splunk` by default. That path is `$SPLUNK_HOME`.

### First start

```bash
sudo -u splunk /opt/splunk/bin/splunk start --accept-license
```

You'll be prompted to create the admin username and password. To make this non-interactive (for automation), create a seed file *before* first start:

```ini
# /opt/splunk/etc/system/local/user-seed.conf
[user_info]
USERNAME = admin
PASSWORD = Str0ngP@ssw0rd!
```

Then start with `--accept-license --answer-yes --no-prompt`. Splunk hashes the password into `etc/passwd` and deletes the seed file. You can also use `HASHED_PASSWORD` instead of a plaintext password.

### Enable boot-start with systemd

Stop Splunk first, then run as root:

```bash
sudo /opt/splunk/bin/splunk stop
sudo /opt/splunk/bin/splunk enable boot-start -user splunk -systemd-managed 1
sudo systemctl start Splunkd
sudo systemctl status Splunkd
```

This creates `/etc/systemd/system/Splunkd.service`. Once systemd manages Splunk, prefer `systemctl` for start/stop so the service state stays consistent. You can still use `splunk restart` as the splunk user in most versions, because newer releases route it through systemd. To grant the splunk user permission to control the service without full root, configure sudoers or polkit.

### Firewall

```bash
# firewalld (RHEL family)
sudo firewall-cmd --permanent --add-port={8000,8089,9997}/tcp
sudo firewall-cmd --reload

# ufw (Ubuntu)
sudo ufw allow 8000/tcp
sudo ufw allow 8089/tcp
sudo ufw allow 9997/tcp
```

If SELinux is enforcing and you use non-standard paths or ports, you may need to adjust contexts.

### Useful commands

```bash
/opt/splunk/bin/splunk status
/opt/splunk/bin/splunk version
/opt/splunk/bin/splunk restart
/opt/splunk/bin/splunk show web-port
/opt/splunk/bin/splunk show splunkd-port
/opt/splunk/bin/splunk btool check     # validates .conf syntax
```

It's handy to add `export SPLUNK_HOME=/opt/splunk` and `export PATH=$SPLUNK_HOME/bin:$PATH` to the splunk user's `.bashrc`.

### Upgrading

Stop Splunk, back up `$SPLUNK_HOME/etc` (configuration), then install the new version over the old one. For tarball installs, extract over the existing directory. For RPM, use `rpm -Uvh`. Start Splunk and accept the migration prompts. Always read the release notes for the upgrade path. Some version jumps require intermediate upgrades, and in distributed environments there's a required component order: typically the cluster manager first, then search heads, then indexers, then forwarders.

---

## 4. Splunk Universal Forwarders

### What the Universal Forwarder is

The Universal Forwarder (UF) is a separate, lightweight Splunk package designed to run on the machines that generate data. It has no web interface, doesn't index data locally, and does almost no parsing. It reads data (files, Windows Event Logs, performance metrics, scripts, network ports), attaches metadata (host, source, sourcetype, index), and streams it securely and reliably to indexers. It uses little CPU and memory, which makes it suitable for deployment on thousands of endpoints and servers. The UF doesn't consume license. License is counted when data is indexed.

### Universal vs. Heavy Forwarder

A **Universal Forwarder** does minimal processing. Event line-breaking and timestamping happen on the indexer, except for structured data like CSV/JSON when you use `INDEXED_EXTRACTIONS`. It's the right choice for nearly all endpoint collection.

A **Heavy Forwarder** is a full Splunk Enterprise install configured to forward. It fully parses data, so it can filter out events, mask sensitive fields, and route events to different indexes or destinations before they reach indexers. It's also used to run add-ons that pull data from APIs (cloud services, databases via DB Connect) and as an intermediate aggregation tier. The trade-off is that it's heavier and it's another server to manage.

### Step 1: Configure the indexer to receive

On the indexer (or all indexers), enable a receiving port. In the UI, go to **Settings > Forwarding and receiving > Configure receiving > New Receiving Port**, and enter `9997`. Or use the CLI:

```bash
/opt/splunk/bin/splunk enable listen 9997 -auth admin:password
```

This writes to `inputs.conf`:

```ini
[splunktcp://9997]
disabled = 0
```

Also create the indexes the forwarders will send to (for example `linux`, `windows`, `web`). Data sent to a nonexistent index is dropped, and Splunk logs a warning.

### Step 2a: Install the UF on Linux

```bash
sudo tar -xzvf splunkforwarder-10.x.x-xxxx-linux-amd64.tgz -C /opt
# RPM alternative: sudo rpm -ivh splunkforwarder-10.x.x-xxxx.x86_64.rpm
```

Recent UF versions (9.1+) default to running as a dedicated low-privilege user named `splunkfwd`. That user needs read access to the logs you want to collect, for example by adding it to the `adm` group on Ubuntu, or through ACLs (`setfacl -m u:splunkfwd:r /var/log/secure`).

```bash
sudo chown -R splunkfwd:splunkfwd /opt/splunkforwarder
sudo -u splunkfwd /opt/splunkforwarder/bin/splunk start --accept-license
sudo /opt/splunkforwarder/bin/splunk stop
sudo /opt/splunkforwarder/bin/splunk enable boot-start -user splunkfwd -systemd-managed 1
sudo systemctl start SplunkForwarder
```

Point it at the indexer and add a monitor:

```bash
cd /opt/splunkforwarder/bin
sudo -u splunkfwd ./splunk add forward-server 10.0.0.10:9997 -auth admin:password
sudo -u splunkfwd ./splunk add monitor /var/log/secure -index linux -sourcetype linux_secure
sudo -u splunkfwd ./splunk list forward-server
```

### Step 2b: Install the UF on Windows

Run `splunkforwarder-<version>-x64-release.msi`. The wizard lets you choose the service account, set a local admin username/password, select Windows inputs to enable (Application, Security, and System event logs, performance monitoring, Active Directory), and specify a deployment server and/or receiving indexer.

Silent install example:

```cmd
msiexec.exe /i splunkforwarder-10.x.x-x64-release.msi ^
  AGREETOLICENSE=Yes ^
  SPLUNKUSERNAME=admin SPLUNKPASSWORD="Str0ngP@ss!" ^
  RECEIVING_INDEXER="10.0.0.10:9997" ^
  DEPLOYMENT_SERVER="10.0.0.20:8089" ^
  WINEVENTLOG_SEC_ENABLE=1 WINEVENTLOG_SYS_ENABLE=1 WINEVENTLOG_APP_ENABLE=1 ^
  /quiet
```

The default install directory is `C:\Program Files\SplunkUniversalForwarder`, and the service is `SplunkForwarder`.

### The key configuration files

**outputs.conf** tells the forwarder where to send data:

```ini
[tcpout]
defaultGroup = primary_indexers

[tcpout:primary_indexers]
server = idx1.example.com:9997, idx2.example.com:9997
useACK = true
```

Listing multiple servers enables **automatic load balancing**. The forwarder switches between indexers periodically (every 30 seconds by default, controlled by `autoLBFrequency`), which spreads data evenly. `useACK = true` enables **indexer acknowledgment**: the forwarder keeps data in memory until the indexer confirms it was written, which protects against data loss if an indexer crashes. For indexer clusters, you can use **indexer discovery**, where forwarders ask the cluster manager for the current list of peers instead of hardcoding them.

**inputs.conf** defines what to collect:

```ini
# Linux file monitoring
[monitor:///var/log/messages]
index = linux
sourcetype = syslog
disabled = 0

[monitor:///var/log/nginx/*.log]
index = web
sourcetype = nginx:access
blacklist = \.gz$

# Windows event logs
[WinEventLog://Security]
index = windows
disabled = 0
renderXml = true

[perfmon://CPU]
object = Processor
counters = % Processor Time
instances = _Total
interval = 60
index = windows_perf
```

The UF tracks how far it has read each file in its **fishbucket** (a small internal database of file checksums and offsets). This lets it resume correctly after a restart and avoid re-sending data. It also handles log rotation gracefully.

Where do these files go? The CLI writes them into `etc/system/local` or `etc/apps/search/local`. Best practice is to package configurations in **apps** (for example `etc/apps/org_all_forwarder_outputs/local/outputs.conf`) so they can be managed centrally.

### Securing forwarder traffic

Forwarder-to-indexer traffic can be encrypted with TLS. Configure `sslPassword`, `clientCert`, and related settings in `outputs.conf` on the forwarder, and use a `[splunktcp-ssl:9997]` stanza plus an `[SSL]` stanza with server certificates in `inputs.conf` on the indexer. Splunk ships default certificates, but you should replace them with your own CA-signed certificates in production.

### Deployment Server: managing forwarders at scale

Manually configuring thousands of forwarders is unworkable. The **Deployment Server (DS)** is a Splunk Enterprise instance that distributes apps (bundles of configuration) to forwarders, which are called deployment clients.

On each forwarder, point it at the DS:

```bash
./splunk set deploy-poll ds.example.com:8089 -auth admin:password
./splunk restart
```

This creates `deploymentclient.conf`:

```ini
[target-broker:deploymentServer]
targetUri = ds.example.com:8089
```

On the DS, place apps in `$SPLUNK_HOME/etc/deployment-apps/`. Then, in **Settings > Forwarder Management** (renamed "Agent Management" in newer versions), create **server classes**. These are groups of clients defined by hostname, IP, machine type, or other filters. Assign apps to them. For example, a server class "linux_web_servers" matching `web-*` hosts could receive the `org_nginx_inputs` app. Clients poll the DS periodically, download changed apps, and restart if the app is configured to trigger a restart. The underlying configuration lives in `serverclass.conf`. After manually editing apps, run `splunk reload deploy-server`.

### Troubleshooting forwarders

On the forwarder, check `$SPLUNK_HOME/var/log/splunk/splunkd.log` for connection errors (search for `TcpOutputProc`). Run `splunk list forward-server` to see active vs. configured-but-inactive destinations, and `splunk list monitor` / `splunk list inputstatus` to see which files are being read. On the indexer or search head, a forwarder's own internal logs arrive in `_internal`, so this search confirms the forwarder is connected even if your inputs are wrong:

```spl
index=_internal host=myforwarder sourcetype=splunkd
```

A common gotcha is sending to an index that doesn't exist. Another is a permissions problem, where the UF user can't read the file. In that case splunkd.log shows `Insufficient permissions to read file`.

---

## 5. Add Data to Splunk

### The Add Data wizard

In Splunk Web, go to **Settings > Add Data** (or the "Add Data" icon on the home page). You get three paths. **Upload** is a one-time upload of a file from your computer, good for testing or ad-hoc analysis. **Monitor** continuously collects data that the Splunk instance itself can access: files and directories, HTTP Event Collector, TCP/UDP ports, Windows event logs, performance counters, registry, Active Directory, and scripts. **Forward** configures inputs on forwarders that are connected to this instance as a deployment server.

The wizard walks you through selecting the source and previewing how Splunk will break the data into events and extract timestamps. The **Set Source Type** screen is critical. Here you choose an existing sourcetype or create a new one and adjust event-breaking and timestamp settings while watching the preview update. You then set the host value and destination index, review, and submit.

### Input types in detail

**Files and directories (monitor)** are the most common input. Splunk tails files continuously, handles rotation, and can recurse through directories with whitelists and blacklists (regex on file paths).

**HTTP Event Collector (HEC)** lets applications and services send events over HTTP/HTTPS with a token, with no forwarder required. It's ideal for cloud services, containers, serverless functions, and custom apps. To set it up, enable it under **Settings > Data Inputs > HTTP Event Collector > Global Settings**, then create a **New Token** with a default sourcetype and allowed indexes. Test it with curl:

```bash
curl -k https://splunk.example.com:8088/services/collector/event \
  -H "Authorization: Splunk 1a2b3c4d-xxxx-xxxx-xxxx-xxxxxxxxxxxx" \
  -d '{"event": {"action":"login","user":"alice","status":"success"}, "sourcetype":"myapp:json", "index":"app"}'
```

A successful response is `{"text":"Success","code":0}`. There's also a `/services/collector/raw` endpoint for raw text. HEC supports indexer acknowledgment and can sit behind a load balancer.

**TCP/UDP network inputs** listen on a port. They're commonly used for syslog. In production, the recommended practice is *not* to send syslog directly to Splunk. Instead, send it to a dedicated syslog server (rsyslog, syslog-ng, or Splunk Connect for Syslog, SC4S) that writes to files or HEC, so that Splunk restarts don't lose UDP data.

**Scripted inputs** run a script on an interval and index its output, which is useful for polling APIs or running commands. **Modular inputs** are a more structured version provided by add-ons, for example AWS, Microsoft 365, or REST API inputs.

**Windows-specific inputs** include Event Logs (`WinEventLog://`), Performance Monitor (`perfmon://`), registry monitoring, Active Directory monitoring, host monitoring, and WMI (for remote collection, though forwarders are preferred).

### Creating indexes

Create indexes before sending data. In the UI, go to **Settings > Indexes > New Index**, and set the name, max size, and paths. Or define them in `indexes.conf`:

```ini
[web]
homePath   = $SPLUNK_DB/web/db
coldPath   = $SPLUNK_DB/web/colddb
thawedPath = $SPLUNK_DB/web/thaweddb
maxTotalDataSizeMB = 500000
frozenTimePeriodInSecs = 7776000   # 90 days
```

Or use the CLI: `splunk add index web`. On an indexer cluster, you define indexes on the cluster manager in `manager-apps` and push the bundle.

### Sourcetypes and parsing (props.conf)

Correct parsing is the foundation of data quality. For any custom sourcetype, Splunk strongly recommends defining the "Great Eight" settings in `props.conf` on the indexers (or the heavy forwarder, whichever parses first). Explicit settings are far more efficient than letting Splunk guess:

```ini
[myapp:log]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)\d{4}-\d{2}-\d{2}
TRUNCATE = 10000
TIME_PREFIX = ^
TIME_FORMAT = %Y-%m-%d %H:%M:%S.%3N
MAX_TIMESTAMP_LOOKAHEAD = 25
EVENT_BREAKER_ENABLE = true
EVENT_BREAKER = ([\r\n]+)\d{4}-\d{2}-\d{2}
```

`LINE_BREAKER` defines where one event ends and the next begins. The first capture group is discarded. With `SHOULD_LINEMERGE = false`, each break is a new event, which is fast. `TIME_PREFIX`, `TIME_FORMAT` (strptime format), and `MAX_TIMESTAMP_LOOKAHEAD` tell Splunk exactly where and how to read the timestamp. `TRUNCATE` caps event length. `EVENT_BREAKER` settings live on the *universal forwarder* and let it split streams on event boundaries, which improves load balancing. You can also set `TZ` when a source's timestamps lack time zone information.

For structured data, `INDEXED_EXTRACTIONS = json` or `csv` makes the forwarder parse the structure. Alternatively, `KV_MODE = json` extracts JSON fields at search time.

### Index-time vs. search-time field extraction

**Search-time extractions** are the default and the recommended approach. They're defined in `props.conf` on search heads using `EXTRACT-`, `REPORT-`, `FIELDALIAS-`, `EVAL-`, and `LOOKUP-` settings, or created in the UI with the Field Extractor. They're flexible, can be changed anytime, and don't increase index size.

**Index-time transformations** apply as data is written and are set via `TRANSFORMS-` in `props.conf` with `transforms.conf`. Use them for routing events to different indexes, overriding sourcetype or host, masking sensitive data (credit card numbers, passwords), and dropping unwanted events to the `nullQueue` to save license. For example, dropping debug logs:

```ini
# props.conf
[myapp:log]
TRANSFORMS-drop_debug = drop_debug_events

# transforms.conf
[drop_debug_events]
REGEX = \sDEBUG\s
DEST_KEY = queue
FORMAT = nullQueue
```

Masking with SEDCMD (props.conf):

```ini
SEDCMD-mask_cc = s/\d{4}-\d{4}-\d{4}-(\d{4})/XXXX-XXXX-XXXX-\1/g
```

Newer Splunk versions also offer **Ingest Actions** (a UI-driven way to filter, mask, and route data) and **Edge Processor / Ingest Processor** for pipeline-based processing.

### Use Technology Add-ons (TAs)

Before building parsing from scratch, check Splunkbase. The official add-ons (Splunk Add-on for Unix and Linux, Splunk Add-on for Microsoft Windows, Splunk Add-on for AWS, vendor TAs for firewalls, and so on) provide correct sourcetypes, parsing, field extractions, and mapping to the **Common Information Model (CIM)**. The CIM is a standardized field-naming scheme (`src`, `dest`, `user`, `action`) that lets searches and apps like Enterprise Security work across different vendors' data.

---

## 6. Search on Splunk

### The Search & Reporting app

Searching happens in the **Search & Reporting** app. The search bar takes SPL. The **time range picker** is the single most important performance control, because Splunk organizes data by time and narrowing the time range dramatically reduces work. Results appear in tabs. **Events** shows raw events with a timeline histogram and field sidebar. **Patterns** groups similar events. **Statistics** shows tabular results from transforming commands. **Visualization** charts those statistics.

There are three **search modes**. **Fast** skips field discovery for speed. **Smart** (the default) discovers fields for event searches but not for transforming searches. **Verbose** returns all fields and events and is the slowest.

### Search fundamentals

The simplest search is keywords, which are matched against the indexed terms:

```spl
index=web error
```

Always specify `index=` and, where possible, `sourcetype=`. Searches without an index are slow and may search only your role's default indexes.

Boolean operators must be uppercase: `AND` (implied between terms), `OR`, `NOT`. Parentheses group terms. Quotes match exact phrases. Wildcards use `*`, and trailing wildcards are efficient while leading wildcards like `*error` are very slow.

```spl
index=web sourcetype=access_combined (status=500 OR status=503) NOT host=test*
```

Field-value comparisons: `status=404`, `status!=200`, `bytes>10000`. Note that `field!=value` excludes events where the field is missing, whereas `NOT field=value` includes them.

Field names are case-sensitive. Field values in the base search are not. Commands are chained with the **pipe** (`|`). Each command operates on the results of the previous one, like a Unix pipeline.

### Essential SPL commands

**Filtering and shaping:**

```spl
... | search status=500                  (filter further)
... | where bytes > 1000000 AND like(uri, "/api/%")
... | fields host, status, uri           (keep only these fields; improves performance)
... | fields - _raw                      (remove fields)
... | table _time, host, status, uri     (display as a table)
... | rename clientip AS "Client IP"
... | dedup user                         (remove duplicates)
... | sort - count                       (descending; `sort 0 field` removes the 10k limit)
... | head 20  /  ... | tail 20
```

**eval** creates or modifies fields, with a large function library (`if`, `case`, `round`, `strftime`, `strptime`, `len`, `lower`, `coalesce`, `mvcount`, `cidrmatch`, and many more):

```spl
index=web sourcetype=access_combined
| eval MB = round(bytes/1024/1024, 2)
| eval status_class = case(status>=500, "Server Error", status>=400, "Client Error", status>=300, "Redirect", true(), "Success")
| eval hour = strftime(_time, "%H")
```

**stats** is the workhorse aggregation command:

```spl
index=web sourcetype=access_combined
| stats count, avg(bytes) AS avg_bytes, dc(clientip) AS unique_visitors, values(method) AS methods BY host, status
```

Common functions include `count`, `dc` (distinct count), `sum`, `avg`, `min`, `max`, `median`, `perc95`, `stdev`, `values`, `list`, `earliest`, `latest`, `first`, and `last`.

**timechart** aggregates over time buckets. It's ideal for line and area charts:

```spl
index=web sourcetype=access_combined status>=500
| timechart span=5m count BY host limit=10
```

**chart** aggregates with a row-split and column-split:

```spl
index=web | chart count OVER host BY status
```

**top / rare** give quick frequency analysis:

```spl
index=web | top limit=10 uri
index=linux sourcetype=linux_secure | rare user
```

**rex** extracts fields inline using regex with named capture groups:

```spl
index=linux sourcetype=linux_secure "Failed password"
| rex "Failed password for (invalid user )?(?<user>\S+) from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count BY user, src_ip
| where count > 5
```

(`rex mode=sed` can also rewrite field values.)

**bin** groups numeric or time values into buckets: `| bin _time span=1h`.

**eventstats and streamstats** add aggregate values to each event without collapsing results. `eventstats` computes over all results, and `streamstats` computes cumulatively, which is useful for running totals, moving averages, and detecting sequences:

```spl
index=web | stats count BY host | eventstats avg(count) AS avg_count | where count > 2*avg_count
```

**lookup** enriches events from CSV files or KV Store collections:

```spl
index=web | lookup geo_country_codes code AS country OUTPUT country_name
| inputlookup assets.csv                    (read a lookup table directly)
| outputlookup blocked_ips.csv              (write results to a lookup)
```

The built-in **iplocation** command adds geographic fields from IPs, and **geostats** feeds map visualizations.

**transaction** groups related events into a single transaction (for example all events for a session). It's powerful but expensive, so prefer `stats` where possible:

```spl
index=web | transaction clientip maxspan=30m maxpause=5m
| stats avg(duration) AS avg_session_seconds
```

**join and append** combine result sets. `join` is limited (subsearches cap at 50,000 results and time out by default), so experienced users usually restructure with `stats` over multiple sourcetypes instead:

```spl
(index=web sourcetype=access_combined) OR (index=app sourcetype=app:orders)
| stats values(status) AS web_status, values(order_id) AS orders BY session_id
```

**Subsearches** run in square brackets first and feed results into the outer search:

```spl
index=firewall [ search index=threat_intel | fields src_ip ]
```

**tstats** searches the indexed metadata (tsidx files) and accelerated data models directly. It's often 10–100× faster than raw searches for counting:

```spl
| tstats count WHERE index=* BY index, sourcetype
| tstats count WHERE index=web BY _time span=1h, host
```

### Time modifiers

You can set time within the search itself, which overrides the time picker:

```spl
index=web earliest=-24h latest=now
index=web earliest=-7d@d latest=@d          (last 7 full days, snapped to midnight)
index=web earliest="09/01/2026:00:00:00"
```

`@` means "snap to": `-1h@h` means one hour ago, rounded down to the hour.

### Knowledge objects

Splunk lets you save reusable search logic. **Field extractions** can be created visually with the **Field Extractor** (from the event actions menu or "Extract New Fields" in the fields sidebar), using a regex or delimiter method. **Event types** are saved searches that categorize events (for example `failed_login`), which you then search with `eventtype=failed_login`. **Tags** are labels applied to field-value pairs (`tag=authentication`). **Macros** are reusable SPL snippets, optionally with arguments, called with backticks: `` `web_errors(500)` ``. **Lookups** are defined under **Settings > Lookups**. **Calculated fields** are eval expressions applied automatically at search time. **Field aliases** map different field names to a common name. **Workflow actions** are right-click links from field values to external systems. **Data models** are hierarchical, structured representations of data that power Pivot and can be accelerated for fast `tstats` queries. The CIM is a set of data models.

### Search performance best practices

Filter as early as possible: specify index, sourcetype, and specific terms in the base search, before the first pipe. Use the narrowest time range that answers the question. Use `fields` early to reduce data transferred. Prefer `stats` over `transaction` and `join`. Avoid leading wildcards and `NOT` on high-cardinality fields where possible. Use `tstats` for counting and metadata questions. Use the **Job Inspector** (Job menu > Inspect Job) to see where time is spent, including how many events were scanned versus returned and which phase (dispatch, parsing, command execution) is slowest.

---

## 7. Creating and Managing Splunk Reports

### What a report is

A report is a saved search, plus optional visualization, schedule, and permissions. Reports let you rerun analyses consistently, share them with others, schedule them, and use them as dashboard panels.

### Creating a report

Run a search in Search & Reporting. Choose a visualization if you want one. Click **Save As > Report**. Give it a title and description. Choose whether to include a **time range picker** (so viewers can change the time) and what to display (statistics table or visualization). Save. After saving, Splunk offers quick actions to set permissions, schedule, accelerate, add to a dashboard, or embed.

### Managing reports

Reports live under the **Reports** tab of an app, and all saved searches across apps are visible at **Settings > Searches, reports, and alerts**. From there you can edit the search string, description, permissions, schedule, and acceleration settings, as well as clone, move, reassign ownership, disable, or delete reports. Under the hood, reports are stanzas in `savedsearches.conf` within the app's `local` directory (or `etc/users/<user>/<app>/local` for private objects).

### Permissions

Every knowledge object has an owner and a sharing level. **Private** means only the owner can see it. **App** means it's shared with users of that app. **Global (All apps)** means it's visible everywhere. Within the sharing level, you grant **Read** and **Write** access per role. A report can also **run as Owner or User**. "Owner" means the search runs with the owner's permissions, so viewers see data the owner can access (convenient, but be careful with sensitive indexes). "User" means it runs with the viewer's own permissions.

### Scheduling reports

Click **Edit > Edit Schedule**. Choose a frequency: hourly, daily, weekly, monthly, or a **cron expression** for full control. For example, `0 7 * * 1-5` means 7:00 AM on weekdays, and `*/15 * * * *` means every 15 minutes. Set the time range the report covers, which should normally match the schedule interval, such as "last 24 hours" for a daily report. Two further settings matter at scale. **Schedule Priority** can be Default, Higher, or Highest. **Schedule Window** lets Splunk delay the run within a window to spread load, which reduces skipped searches.

Scheduled reports can trigger actions such as **sending email** with results inline, attached as CSV, or attached as PDF, as well as **writing results to a lookup**, and others. The most recent results of a scheduled report are cached, so dashboard panels that reference scheduled reports load instantly without rerunning the search.

You can reference saved reports in SPL:

```spl
| savedsearch "Daily Web Errors"
| loadjob savedsearch="admin:search:Daily Web Errors"   (loads cached results without rerunning)
```

### Report acceleration

For reports using transforming commands (`stats`, `timechart`, `chart`, `top`) over large data, enable **Report Acceleration** under **Edit > Edit Acceleration**. Splunk builds and maintains a summary in the background, which makes subsequent runs far faster. You choose the summary range, such as 7 days, 1 month, or 1 year. Requirements: the search must be transforming and qualify for acceleration, and the user needs the `schedule_search` and `accelerate_search` capabilities. The power and admin roles have these by default.

### Summary indexing

For long-term trending, a scheduled search can write its aggregated results to a **summary index**. You then run later reports against this much smaller dataset:

```spl
index=web sourcetype=access_combined
| stats count AS hits, dc(clientip) AS visitors BY host
| collect index=summary_web
```

Alternatively, enable "Log Event" or "summary indexing" in the scheduled report's settings. Summary index data generally doesn't count against license when written with the default `stash` sourcetype.

### Embedding and exporting

Scheduled reports can be **embedded** in external web pages through an iframe link (**Edit > Embed**), though anyone with the link can view the results, so use this with care. Results can be exported to CSV, JSON, XML, or raw format from the Export button, or PDF from the report view.

---

## 8. Alerts on Splunk

### What an alert is

An alert is a saved search that runs on a schedule or in real time, evaluates a **trigger condition** against the results, and performs one or more **actions** when that condition is met.

### Creating an alert

Write and test a search that returns results when something is wrong. For example, brute-force detection:

```spl
index=linux sourcetype=linux_secure "Failed password"
| rex "from (?<src_ip>\d+\.\d+\.\d+\.\d+)"
| stats count BY src_ip, host
| where count >= 10
```

Click **Save As > Alert**, then configure the settings described below.

**Alert type:** **Scheduled** runs on a cron schedule, such as every 5 minutes over the last 5 minutes. This is the recommended type for almost all alerts. **Real-time** runs continuously. There are "per-result" real-time alerts (which trigger instantly on each matching event) and "rolling window" real-time alerts (for example, "more than 10 events in any 5 minutes"). Real-time searches hold resources permanently on the search head and indexers, so use them sparingly. Many environments disable them entirely.

**Trigger conditions** include number of results, number of hosts, number of sources (each with a comparison such as "is greater than 0"), or a **custom condition** expressed as a secondary search on the results, such as `search count > 100`. A common, clean pattern is to put the logic in the SPL itself (the `where count >= 10` above) and trigger on "number of results > 0".

**Trigger mode:** **Once** fires one action for the whole result set. **For each result** fires a separate action per result row, for example one email per offending IP.

**Throttling (suppression)** prevents alert storms. You can suppress triggering for a period (for example 60 minutes) globally, or per field value when using "for each result". For example, suppress by `src_ip` for 1 hour so the same attacker doesn't generate an email every 5 minutes, while new IPs still alert.

**Severity** ranges from Info through Low, Medium, High, to Critical, and is used for organization in the Triggered Alerts view.

### Alert actions

Built-in actions include **Add to Triggered Alerts** (records the firing in **Activity > Triggered Alerts**), **Send email**, **Webhook** (HTTP POST of JSON results to a URL, which is useful for chat tools, ITSM systems, and automation platforms), **Log Event** (writes an event back into an index), and **Output results to lookup**. **Run a script** is deprecated in favor of custom alert actions. Splunkbase offers custom alert action add-ons for Slack, Microsoft Teams, PagerDuty, ServiceNow, Jira, and many more. You can also build your own using the custom alert action framework.

Email configuration requires a mail server, set under **Settings > Server settings > Email settings** (SMTP host, port, TLS, credentials, and sender address).

### Tokens in alert actions

Alert messages can include dynamic values through tokens. `$name$` is the alert name. `$trigger_time$` is when it fired. `$results_link$` links to the results. `$result.fieldname$` gives a field value from the first result row, or from each row in "for each result" mode. `$job.resultCount$` is the result count. Example email subject:

```
[$alert.severity$] Brute force from $result.src_ip$ on $result.host$ ($result.count$ failures)
```

### Alert design best practices

Align the schedule and time range, with a small lag to allow for ingestion delay. A common pattern is running every 5 minutes with `earliest=-10m@m latest=-5m@m`, which avoids missing late-arriving events and avoids double counting. Keep alert searches efficient, because they run constantly. Use throttling to avoid fatigue. Monitor for **skipped searches**, which happen when too many scheduled searches compete for concurrency slots. Document each alert's purpose and response procedure in its description. You can manage all alerts under **Settings > Searches, reports, and alerts**, filtering by type.

---

## 9. Dashboards

Dashboards combine multiple panels (charts, tables, single values, maps) with interactive inputs into a single view. Splunk currently has two dashboard frameworks.

### Classic dashboards (Simple XML)

This is the long-standing framework. Dashboards are defined in XML. It has a mature feature set, extensive community examples, and supports custom JavaScript and CSS extensions, although custom JS is increasingly restricted for security reasons. Scheduled PDF delivery is supported.

### Dashboard Studio

This is the newer framework. It's defined in JSON and offers a far more flexible visual editor with absolute layout (pixel-precise placement, images, shapes, backgrounds) or grid layout, richer visualizations, and better styling. Splunk is steering new development toward Studio, and it has steadily gained parity features such as tokens, drilldowns, inputs, chain searches, conditional visibility, and scheduled export.

### Creating a dashboard

Go to **Dashboards > Create New Dashboard**, enter a title and ID, set permissions, and choose Classic or Dashboard Studio (and, in Studio, the layout type). You can add panels by editing the dashboard directly and adding searches, or from any search by choosing **Save As > Existing Dashboard / New Dashboard**. Panels can use an **inline search**, which is defined in the dashboard itself, or reference a **saved report**, which can be scheduled so the panel loads cached results.

### Inputs and tokens

Inputs let viewers filter the dashboard. Types include time picker, dropdown, multiselect, radio, text box, link list, and checkbox. Each input sets a **token**, a variable referenced in searches as `$token_name$`. Dropdowns can be populated dynamically by a search.

### Base searches (post-process / chain searches)

To avoid running similar expensive searches for every panel, define one **base search** and have panels **post-process** it. This is a major performance technique. The base search should be a transforming search, or use `fields` to limit data.

### Classic Simple XML example

```xml
<form version="1.1" theme="dark">
  <label>Web Server Overview</label>
  <search id="base">
    <query>index=web sourcetype=access_combined host=$host_tok$
      | fields _time, host, status, uri, bytes, clientip</query>
    <earliest>$time_tok.earliest$</earliest>
    <latest>$time_tok.latest$</latest>
  </search>

  <fieldset submitButton="false">
    <input type="time" token="time_tok">
      <label>Time Range</label>
      <default><earliest>-24h@h</earliest><latest>now</latest></default>
    </input>
    <input type="dropdown" token="host_tok">
      <label>Host</label>
      <choice value="*">All</choice>
      <default>*</default>
      <fieldForLabel>host</fieldForLabel>
      <fieldForValue>host</fieldForValue>
      <search>
        <query>| tstats count WHERE index=web BY host</query>
        <earliest>-7d</earliest><latest>now</latest>
      </search>
    </input>
  </fieldset>

  <row>
    <panel>
      <title>Total Requests</title>
      <single>
        <search base="base"><query>| stats count</query></search>
      </single>
    </panel>
    <panel>
      <title>Requests by Status Over Time</title>
      <chart>
        <search base="base"><query>| timechart count BY status</query></search>
        <option name="charting.chart">line</option>
      </chart>
    </panel>
  </row>

  <row>
    <panel>
      <title>Top URIs</title>
      <table>
        <search base="base"><query>| top limit=10 uri</query></search>
        <drilldown>
          <link target="_blank">search?q=index=web uri="$row.uri$"</link>
        </drilldown>
      </table>
    </panel>
  </row>
</form>
```

Note that a dashboard with inputs uses `<form>` rather than `<dashboard>` as its root element.

### Dashboard Studio structure

A Studio dashboard's JSON has distinct sections. `dataSources` holds searches, including `ds.chain` for post-process. `visualizations` holds panels, each referencing a data source. `inputs` holds the input definitions. `defaults` holds shared settings, such as a default time range applied to all searches. `layout` holds the positions. A simplified fragment:

```json
{
  "dataSources": {
    "ds_base": { "type": "ds.search", "options": { "query": "index=web sourcetype=access_combined | fields _time status uri" } },
    "ds_status": { "type": "ds.chain", "options": { "extend": "ds_base", "query": "| timechart count by status" } }
  },
  "visualizations": {
    "viz_status": { "type": "splunk.line", "title": "Requests by Status", "dataSources": { "primary": "ds_status" } }
  },
  "inputs": {
    "input_time": { "type": "input.timerange", "options": { "token": "global_time", "defaultValue": "-24h@h,now" } }
  },
  "layout": { "type": "grid", "structure": [ { "item": "viz_status", "position": { "x": 0, "y": 0, "w": 1200, "h": 300 } } ] }
}
```

### Visualizations and drilldowns

Available visualizations include line, area, column, bar, pie, scatter, bubble, single value (with trend and sparkline), radial and filler gauges, tables with conditional formatting, choropleth and marker maps, and more, plus custom visualizations from Splunkbase. **Drilldowns** define what happens when a user clicks a panel element: open a search, link to another dashboard (passing tokens), set a token to reveal or filter other panels on the same dashboard, or open a URL. Tokens like `$click.value$`, `$row.fieldname$`, and `$click.name2$` carry the clicked values.

### Dashboard best practices

Use base/chain searches to reduce load. Point heavy panels at scheduled or accelerated reports. Keep default time ranges modest. Limit the number of panels (each is a concurrent search). Use `tstats` for populating dropdowns. Design around questions your audience actually asks, rather than displaying every possible metric. Set permissions deliberately, and remember that "run as owner" behavior applies only to saved reports, not to inline dashboard searches.

---

## 10. Splunk Health Status Check

### The Health Report (splunkd health)

Since Splunk 7.2, Splunk Web shows a **health status indicator** in the top bar: green, yellow, or red. Clicking it opens the **Health Report**, a tree of features such as data forwarding, file monitor input, index processor, search scheduler, search lag, skipped searches, buckets, disk space, KV Store, and cluster status. Each feature has indicators with thresholds, and the report explains the root cause and suggests fixes when something turns yellow or red. The thresholds are configurable in `health.conf`, and you can also configure health report alerts. It's available via REST too:

```bash
curl -k -u admin:password https://localhost:8089/services/server/health/splunkd/details
```

Or in SPL:

```spl
| rest /services/server/health/splunkd/details
```

### The Monitoring Console

The **Monitoring Console (MC)**, found under **Settings > Monitoring Console**, is Splunk's built-in health and performance app. On a standalone instance it works out of the box. In a distributed environment, configure it on a dedicated instance (or the license manager in smaller setups), add all instances as search peers, then go to **Settings > General Setup**, switch to **Distributed mode**, assign server roles (indexer, search head, cluster manager, and so on), and apply the changes.

Key views include the **Overview** of the whole deployment, **Indexing Performance** (throughput, queue fill ratios, and blocked queues by instance), **Search Activity and Search Usage Statistics** (concurrency, runtimes, and skipped searches), **Scheduler Activity**, **Resource Usage** (CPU, memory, and disk I/O per machine and per process), **Indexes and Volumes** (sizes, bucket counts, and retention), **Indexer Clustering and Search Head Clustering** status, **KV Store** status, **License Usage**, and **Forwarders**. The Forwarders view requires enabling **Forwarder Monitoring** under **Settings > Forwarder Monitoring Setup**. It shows connected, missing, and inactive forwarders and their throughput.

The MC also includes **Health Check** (**Monitoring Console > Health Check**). It runs a suite of best-practice checks, such as THP status, ulimits, time sync, version consistency, and outdated configurations, and flags problems with remediation advice. It also ships a set of **platform alerts** that you can enable, for example for near-critical disk usage, missing forwarders, license violations, and abnormal search head status.

### CLI health checks

```bash
splunk status                         # is splunkd running
splunk version
splunk btool check                    # detect typos/invalid settings in .conf files
splunk btool <conf> list --debug      # effective config and origin
splunk list inputstatus               # file input status (tailing progress, errors)
splunk show cluster-status --verbose  # on cluster manager
splunk show kvstore-status            # KV Store health
splunk diag                           # creates a diagnostic tarball for Splunk Support
```

Key log files live in `$SPLUNK_HOME/var/log/splunk/`. These include `splunkd.log` (the main log), `metrics.log` (throughput and queue metrics), `scheduler.log`, `license_usage.log`, `web_service.log`, `audit.log`, and `mongod.log` (KV Store). All of these are also indexed into `_internal`.

### Essential health-check searches

**Blocked or filling queues** are an early sign of indexing bottlenecks:

```spl
index=_internal source=*metrics.log group=queue blocked=true
| stats count BY host, name
```

For queue fill ratio over time:

```spl
index=_internal source=*metrics.log group=queue
| eval fill_pct = round(current_size_kb/max_size_kb*100, 1)
| timechart span=5m perc90(fill_pct) BY name
```

**Skipped scheduled searches:**

```spl
index=_internal sourcetype=scheduler status=skipped
| stats count BY savedsearch_name, app, reason
| sort - count
```

**Daily license usage by index:**

```spl
index=_internal source=*license_usage.log type=Usage
| eval GB = b/1024/1024/1024
| timechart span=1d sum(GB) AS GB BY idx
```

**Forwarders or hosts that have stopped sending data:**

```spl
| tstats latest(_time) AS last_seen WHERE index=* BY host
| eval minutes_since = round((now()-last_seen)/60, 0)
| where minutes_since > 60
| convert ctime(last_seen)
| sort - minutes_since
```

**Errors and warnings in Splunk's own logs:**

```spl
index=_internal sourcetype=splunkd (log_level=ERROR OR log_level=WARN)
| stats count BY host, component, log_level
| sort - count
```

**Indexing lag** (the gap between event time and index time, which reveals delays or timestamp problems):

```spl
index=* earliest=-1h
| eval lag_sec = _indextime - _time
| stats avg(lag_sec) AS avg_lag, max(lag_sec) AS max_lag BY index, sourcetype
```

**Resource usage** from introspection data:

```spl
index=_introspection sourcetype=splunk_resource_usage component=Hostwide
| timechart span=5m avg(data.cpu_system_pct) AS sys_cpu, avg(data.mem_used) AS mem_used BY host
```

**Disk space:** Splunk stops indexing when free disk space drops below `minFreeSpace` (5000 MB by default, set in `server.conf` under `[diskUsage]`). Watch disk usage closely on indexers.

### A routine health checklist

On a regular basis, a Splunk administrator typically confirms the following: the health report is green; no queues are blocked; license usage is within limits; skipped searches are near zero; all expected forwarders are reporting; indexing lag is normal; disk space is healthy on indexers; cluster status shows search and replication factors met (if clustered); KV Store is ready; SSL certificates aren't near expiry; and the versions are consistent and supported.

---

## 11. User Management on Splunk

### Authentication methods

Splunk supports several ways to authenticate users. **Native Splunk authentication** stores users locally, with hashed passwords in `$SPLUNK_HOME/etc/passwd`. **LDAP/Active Directory** authenticates against a directory and maps LDAP groups to Splunk roles. **SAML 2.0** provides single sign-on with identity providers like Okta, Microsoft Entra ID (Azure AD), Ping, and ADFS, and maps SAML groups to roles. **Scripted authentication** handles custom back ends. **Multi-factor authentication** is available through integrations such as Duo and RSA, or through the SAML IdP. You can combine native auth (for break-glass admin accounts) with LDAP or SAML. Configuration is under **Settings > Authentication Methods** and stored in `authentication.conf`.

### Roles and capabilities

Splunk uses **role-based access control (RBAC)**. Users are assigned one or more roles, and roles grant **capabilities** (what actions a user can perform) and **index access** (what data they can search). The built-in roles are as follows:

| Role | Purpose |
|---|---|
| admin | Full control of the instance |
| power | Create and share knowledge objects, schedule searches, real-time search, accelerate reports |
| user | Run searches, create private knowledge objects, edit own preferences |
| can_delete | Only grants the `delete_by_keyword` capability (use of the `delete` command) |
| splunk-system-role | Internal system role; don't assign to people |

In Splunk Cloud, customers use `sc_admin` rather than `admin`.

Examples of capabilities include `schedule_search`, `rtsearch` (real-time search), `accelerate_search`, `edit_user`, `admin_all_objects`, `list_settings`, `edit_tcp`, `indexes_edit`, and `delete_by_keyword`. Grant the minimum needed.

A note on `can_delete`: the `delete` command doesn't free disk space. It only makes events unsearchable, and even admins don't have this capability by default. Assign it temporarily and deliberately.

### Creating a custom role

Go to **Settings > Roles > New Role** and configure four tabs. Under **Inheritance**, inherit from an existing role such as `user`, which gives you its capabilities and index access. Under **Capabilities**, add or remove specific capabilities. Under **Indexes**, choose which indexes the role can search and which are searched by default when a user doesn't specify `index=`. Under **Restrictions**, set a search filter that's automatically appended to every search. For example, `host=web*` limits a team to its own hosts, which gives you row-level restriction. Under **Resources**, set quotas: concurrent search jobs, disk space for search results, the maximum time window a search can cover, and cumulative job limits.

The equivalent in `authorize.conf`:

```ini
[role_soc_analyst]
importRoles = user
srchIndexesAllowed = security;firewall;linux;windows
srchIndexesDefault = security
srchFilter = NOT sourcetype=hr_confidential
srchJobsQuota = 6
rtSrchJobsQuota = 0
srchDiskQuota = 500
srchTimeWin = 2592000
schedule_search = enabled
```

(`srchTimeWin` is in seconds, so 30 days here.) When a user has multiple roles, capabilities and index access combine additively, as a union. Search filters from multiple roles are combined with OR, which can widen access unexpectedly, so design roles with care.

### Creating and managing users

In the UI, go to **Settings > Users > New User** and enter the username, full name, email, password, default app, time zone, and roles. You can require a password change at first login.

From the CLI:

```bash
splunk add user jdoe -password 'Str0ngP@ss!' -role user -full-name "John Doe" -email jdoe@example.com -auth admin:password
splunk edit user jdoe -role power -auth admin:password
splunk edit user jdoe -password 'N3wP@ss!' -auth admin:password
splunk list user -auth admin:password
splunk remove user jdoe -auth admin:password
```

Via the REST API:

```bash
curl -k -u admin:password https://localhost:8089/services/authentication/users \
  -d name=jdoe -d password='Str0ngP@ss!' -d roles=user
```

For LDAP or SAML users, you don't create accounts in Splunk. You map groups to roles, and users appear after their first login. With LDAP, go to **Settings > Authentication Methods > LDAP Settings**, configure the strategy (host, port 389 or 636 for LDAPS, bind DN, user and group base DNs, and attribute names), then click **Map groups** to assign Splunk roles to directory groups. Remember to reload authentication or wait for the cache refresh after directory changes.

### Password policy and lockout

Under **Settings > Password Management** (for native accounts), you can configure minimum length, complexity requirements (digits, uppercase, lowercase, special characters), password expiration, password history to prevent reuse, and lockout after failed attempts along with the lockout duration.

### Authentication tokens

Users or admins can create **authentication tokens** (JSON Web Tokens) under **Settings > Tokens** for scripted access to the REST API, instead of embedding passwords. Token authentication must be enabled first, and tokens can have expiration dates.

### Knowledge object ownership

When a user leaves, their private reports, alerts, and dashboards become orphaned. Scheduled searches owned by deleted users can fail. Use **Settings > All configurations > Reassign Knowledge Objects** to transfer ownership before or after removing users. The Monitoring Console's health check also detects orphaned scheduled searches.

### Auditing user activity

All logins, searches, and configuration changes are recorded in the `_audit` index:

```spl
index=_audit action="login attempt"
| stats count BY user, info, src
```

```spl
index=_audit action=search info=granted search=*
| table _time, user, search
```

```spl
index=_audit action=edit_user OR action=edit_roles
| table _time, user, action, info, object
```

### Recovering a lost admin password

If you're locked out of a native admin account on Splunk Enterprise, follow these steps. Stop Splunk. Rename `$SPLUNK_HOME/etc/passwd` to something like `passwd.bak`. Create `$SPLUNK_HOME/etc/system/local/user-seed.conf` containing:

```ini
[user_info]
USERNAME = admin
PASSWORD = NewStr0ngP@ss!
```

Then start Splunk. The admin account is recreated from the seed. Be aware that renaming `passwd` removes all other *local* users from the file, although their roles and knowledge objects remain on disk. You can restore their entries by copying their lines from `passwd.bak` back into the new `passwd` file, then restarting.

---

## Where to go next

Once you're comfortable with these fundamentals, natural next steps include indexer clustering and search head clustering for high availability, data models and the CIM, SmartStore, Splunk Enterprise Security, and the official Splunk certification path: Splunk Core Certified User, then Power User, then Enterprise Certified Admin, then Architect. The free **Splunk Fundamentals / Splunk Education** courses, the Splunk Docs site, Splunk Lantern (practical guidance articles), and the Splunk Community forums are all excellent resources. The **Splunk Boss of the SOC (BOTS)** datasets are great for hands-on search practice.
