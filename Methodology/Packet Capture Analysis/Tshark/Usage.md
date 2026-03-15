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
