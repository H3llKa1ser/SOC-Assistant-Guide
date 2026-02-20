# Networking

Tools:

1) KAPE

2) SRUMDump https://github.com/MarkBaggett/srum-dump

3) Netstat

4) Pktmon (Packet Monitor)

### 1) List TCP Connections

    Get-NetTCPConnection | select Local*, Remote*, State, OwningProcess,` @{n="ProcName";e={(Get-Process -Id $_.OwningProcess).ProcessName}},` @{n="ProcPath";e={(Get-Process -Id $_.OwningProcess).Path}} | sort State | ft -Auto | tee tcp-conn.txt

OR

    Get-NetTCPConnection | select LocalAddress,localport,remoteaddress,remoteport,state,@{name="process";Expression={(get-process -id $_.OwningProcess).ProcessName}}, @{Name="cmdline";Expression={(Get-WmiObject Win32_Process -filter "ProcessId = $($_.OwningProcess)").commandline}} | sort Remoteaddress -Descending | ft -wrap -autosize

### 2) List UDP Connections

    Get-NetUDPEndpoint | select local*,creationtime, remote* | ft -autosize

### 3) List Network Shares

    Get-CimInstance -Class Win32_Share | tee net-shares.txt

### 4) Firewall Configuration

    Get-NetFirewallProfile | ft Name, Enabled, DefaultInboundAction, DefaultOutboundAction | tee fw-profiles.txt

### 5) Firewall Rules

    Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" } | Sort-Object -Property DisplayName | ft -Property DisplayName,
    @{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}},
    @{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}},
    @{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}},
    @{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}}, Direction, Action,
    @{Name='Program';Expression={($PSItem | Get-NetFirewallApplicationFilter).Program}}

Firewall logs location

    C:\Windows\System32\LogFiles\Firewall

### 6) Dump contents of the SRUDB.dat (System Resource Usage Monitor SRUM)

Use KAPE to export the file

    .\kape.exe --tsource C:\Windows\System32\sru --tdest C:\Users\CMNatic\Desktop\SRUM --tflush --mdest C:\Users\CMNatic\Desktop\MODULE --mflush --module SRUMDump --target SRUM

Use SRUMDump tool and fill the relevant information:

    Path to SRUDB.dat
    Output folder for SRUM_DUMP_OUTPUT.xlsx
    Path to SRUM_DUMP Template
    Path to registry SOFTWARE hive (Optional)

### 7) Sort and Unique remote IPs

    (Get-NetTCPConnection).remoteaddress | Sort-Object -Unique

### 8) Check information about an IP Address

    Get-NetTCPConnection -remoteaddress IP_ADDRESS | select state, creationtime, localport,remoteport | ft -autosize

### 9) Retrieve DNS Cache

    Get-DnsClientCache | ? Entry -NotMatch "workst|servst|memes|kerb|ws|ocsp" | out-string -width 1000

### 10) View Hosts file

    gc -tail 4 "C:\Windows\System32\Drivers\etc\hosts"

### 11) Query RDP logs

    qwinsta

### 12) List SMB Connections and Shares

    Get-SmbConnection
    Get-SmbShare

## Pktmon Commands

| Command              | Description                                                                |
|----------------------|----------------------------------------------------------------------------|
| `pktmon start`       | Start a PacketMonitor capture.                                             |
| `pktmon stop`        | Stop a PacketMonitor capture.                                              |
| `pktmon reset`       | Reset the count of packets that PacketMonitor has captured.                |
| `pktmon counters`    | View the amount of packets PacketMonitor has captured across the interfaces.|
| `pktmon etl2txt`     | Convert a PacketMonitor capture file to a text file.                       |
| `pktmon etl2pcap`    | Convert a PacketMonitor capture file to a pcap.                            |

## Netstat

### 1) Main commands to display connections

    netstat -ano
    netstat -antp
    netstat -anob
