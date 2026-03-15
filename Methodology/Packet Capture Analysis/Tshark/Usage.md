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

### 9) Colored output (Wireshark Style)

    tshark -r file.pcap --color

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

## Display Filters

### 1) Filtering an IP without specifying a direction.

    tshark -r file.pcap -Y 'ip.addr == 10.10.10.10'

### 2) Filtering a network range 

    tshark -r file.pcap -Y 'ip.addr == 10.10.10.0/24'

### 3) Filtering a source IP

    tshark -r file.pcap -Y 'ip.src == 10.10.10.10'

### 4) Filtering a destination IP

    tshark -r file.pcap -Y 'ip.dst == 10.10.10.10'

### 5) Filtering TCP port

    tshark -r file.pcap -Y 'tcp.port == 80'

### 6) Filtering source TCP port

    tshark -r file.pcap -Y 'tcp.srcport == 80'

### 7) Filtering HTTP packets

    tshark -r file.pcap -Y 'http'

### 8) Filtering HTTP packets with response code "200"

    tshark -r file.pcap -Y "http.response.code == 200"

### 9) Filtering DNS packets

    tshark -r file.pcap -Y 'dns'

### 10) Filtering all DNS "A" packets

    tshark -r file.pcap -Y 'dns.qry.type == 1'

## Statistics

### 1) Protocol Hierarchy

    tshark -r file.pcapng -z io,phs -q

### 2) View a specific protocol in Protocol Hierarchy

    tshark -r file.pcapng -z io,phs,udp -q

### 3) Packet Length Tree

    tshark -r file.pcapng -z plen,tree -q

### 4) Endpoints

Endpoints: ip, ipv6, wlan, tcp, udp, eth

    tshark -r file.pcapng -z endpoints,ip -q

### 5) Conversations

Same parameters as endpoints

    tshark -r file.pcapng -z conv,ip -q 

### 6) Expert Info

    tshark -r file.pcapng -z expert -q

### 7) IP protocol types

    tshark -r file.pcapng -z ptype,tree -q

### 8) Available Hosts

    tshark -r file.pcapng -z ip_hosts,tree -q

### 9) Source and Destination IPs

IPv4

    tshark -r file.pcapng -z ip_srcdst,tree -q

IPv6

    tshark -r file.pcapng -z ipv6_srcdst,tree -q

### 10) Destination and Ports

IPv4

    tshark -r file.pcapng -z dests,tree -q

IPv6

    tshark -r file.pcapng -z ipv6_dests,tree -q

### 11) DNS

    tshark -r file.pcapng -z dns,tree -q

### 12) HTTP

HTTP

    tshark -r file.pcapng -z http,tree -q

HTTP2

    tshark -r file.pcapng -z http2,tree -q

Load Distribution

    tshark -r file.pcapng -z http_srv,tree -q

Requests

    tshark -r file.pcapng -z http_req,tree -q

Requests and Responses

    tshark -r file.pcapng -z http_seq,tree -q
