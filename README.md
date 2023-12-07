# THIS IS A MARKDOWN FILE
---
Role: MSc Student
Name: Ioannis Lamprou
Student ID: 2023039016
Email: ilamprou1@tuc.gr
---

# Pcap Monitor

This project is a packet sniffer and analyzer that uses the pcap library to capture packets from a network interface or read packets from a pcap file. It provides detailed information about the Ethernet, IP, TCP, and UDP headers, as well as the payload of each packet. It also keeps track of TCP and UDP flows and identifies TCP retransmissions.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Building

To build the project, use the provided Makefile. In the project directory, run:

```bash
make
```

This will compile the source code and produce an executable named `pcap_ex`.

## Usage

You can run the program with the following command:

```bash
sudo ./pcap_ex -i interface_name -f filter_exp
```

or

```bash
./pcap_ex -r file_name -f filter_exp
```

Here, `interface_name` is the name of the network interface from which to capture packets, `file_name` is the name of a pcap file from which to read packets, and `filter_exp` is a filter expression that specifies which packets to capture or read.

The `-i` and `-r` options are mutually exclusive. If you provide both, the program will print a help message and exit. If you do not provide either, the program will also print a help message and exit.

The filter expression is optional. If you do not provide it, the program will capture or read all packets.

## Filter Expressions

The program supports the following filter expressions:
(You can find more information about filter expressions [here](https://www.tcpdump.org/manpages/pcap-filter.7.html).)

- `dst host ip_address`
- `src host ip_address`
- `host ip_address`
- `ether dst mac_address`
- `ether src mac_address`
- `ether host mac_address`
- `gateway ip_address`
- `dst net network`
- `src net network`
- `net network`
- `dst port port_number`
- `src port port_number`
- `port port_number`
- `tcp`
- `udp`
- `icmp`
- `less size`
- `greater size`

## Implementation Details

The program uses a hash map to keep track of TCP and UDP flows and to identify TCP retransmissions. Each entry in the hash map represents a flow and contains a key and a value. The key is a string that consists of the source IP address, destination IP address, source port number, destination port number, and sequence number, separated by colons. The value is an integer that represents the number of packets in the flow.

When the program captures or reads a packet, it constructs the key from the packet's header fields and checks if the key is in the hash map. If the key is in the hash map, the program increments the value associated with the key. If the key is not in the hash map, the program adds a new entry to the hash map with the key and a value of 1.

The program uses the pcap library to capture packets from a network interface or read packets from a pcap file. It uses the pcap_next_ex function to get the next packet, and then it processes the packet's headers and payload.

The program prints detailed information about each packet, including the Ethernet, IP, TCP, and UDP headers, as well as the payload. It also prints statistics about the total number of packets, the total number of TCP and UDP packets, the total number of TCP and UDP bytes, the total number of TCP retransmissions, and the total number of TCP and UDP flows.
