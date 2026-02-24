# Networking

### 1) Network Interfaces

    cat /Library/Preferences/SystemConfiguration/NetworkInterfaces.plist

### 2) DHCP Settings

    sudo cat /private/var/db/dhcpclient/leases/en0.plist

### 3) Wireless Connections

    sudo plutil -p /Library/Preferences/com.apple.wifi.known-networks.plist

### 4) Network Usage

    log show --info --predicate 'senderImagePath contains "IPConfiguration" and (eventMessage contains "SSID" or eventMessage contains "Lease" or eventMessage contains "network changed")'            

### 5) Convert the Unified Logs to CSV

    ./unifiedlog_parser -i system_logs.logarchive -o logs/output1.csv
