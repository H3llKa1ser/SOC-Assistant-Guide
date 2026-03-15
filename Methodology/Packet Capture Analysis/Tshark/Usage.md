# Usage

### 1) Capture live traffic on a specific interface

    sudo tshark -i INTERFACE

### 2) List available network interfaces

    sudo tshark -D

### 3) Read data from a .pcap file

    tshark -r file.pcap

### 4) Write output to another file from sniffed traffic

    tshark -r file.pcap -w output.pc

### 5) Packet count (Stop after capturing a specified number of packets.)

    tshark -r file.pcap -c NUM

### 6) Verbose output (Packet filtering in Wireshark)

    tshark -r file.pcap -c NUM -V

### 7) Show packet details in hex and ASCII dump for each packet

    tshark -r file.pcap -x

### 8) Start sniffing the traffic and stop after NUM seconds, and save the dump into NUM files, each NUMkb

    tshark -w output.pcap -a duration:NUM -a filesize:NUM -a files:NUM

## Capture Filters

### 1) Filtering a host

    tshark -f "host 10.10.10.10"

### 2) Filtering a network range 

    tshark -f "net 10.10.10.0/24"

### 3) Filtering a Port

    tshark -f "port 80"

### 4) Filtering a port range

    tshark -f "portrange 80-100"

### 5) Filtering source address

    tshark -f "src host 10.10.10.10"

### 6) Filtering destination address

    tshark -f "dst host 10.10.10.10"

### 7) Filtering TCP

    tshark -f "tcp"

### 8) Filtering MAC address

    tshark -f "ether host F8:DB:C5:A2:5D:81"

### 9) Filtering IP Protocols 1 (ICMP)

    tshark -f "ip proto 1"
