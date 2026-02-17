# Networking

### 1) List TCP Connections

    Get-NetTCPConnection | select Local*, Remote*, State, OwningProcess,` @{n="ProcName";e={(Get-Process -Id $_.OwningProcess).ProcessName}},` @{n="ProcPath";e={(Get-Process -Id $_.OwningProcess).Path}} | sort State | ft -Auto | tee tcp-conn.txt

### 2) List Network Shares

    Get-CimInstance -Class Win32_Share | tee net-shares.txt

### 3) Firewall Configuration

    Get-NetFirewallProfile | ft Name, Enabled, DefaultInboundAction, DefaultOutboundAction | tee fw-profiles.txt

## 4) Firewall Rules

    Get-NetFirewallRule | Where-Object { $_.Enabled -eq "True" } | Sort-Object -Property DisplayName | ft -Property DisplayName,
    @{Name='Protocol';Expression={($PSItem | Get-NetFirewallPortFilter).Protocol}},
    @{Name='LocalPort';Expression={($PSItem | Get-NetFirewallPortFilter).LocalPort}},
    @{Name='RemotePort';Expression={($PSItem | Get-NetFirewallPortFilter).RemotePort}},
    @{Name='RemoteAddress';Expression={($PSItem | Get-NetFirewallAddressFilter).RemoteAddress}}, Direction, Action,
    @{Name='Program';Expression={($PSItem | Get-NetFirewallApplicationFilter).Program}}
