# TCP in UDP

Middleboxes can mess up with TCP flows, e.g. intercepting the connections and
dropping MPTCP options. Using an TCP-in-UDP tunnel will force such middleboxes
not to modify such TCP connections. The idea here is inspired by an old [IETF
draft](https://datatracker.ietf.org/doc/html/draft-cheshire-tcp-over-udp-00.html).

This "tunnel" is done in BPF, from the TC hooks.

## Headers

[UDP](https://www.ietf.org/rfc/rfc768.html):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

[TCP](https://www.ietf.org/rfc/rfc9293.html):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |       |C|E|U|A|P|R|S|F|                               |
| Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
|       |       |R|E|G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           [Options]                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

TCP-in-UDP:

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |       |C|E|U|A|P|R|S|F|                               |
| Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
|       |       |R|E|G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                           [Options]                           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Build

Build the binary using `make`. CLang and `libbpf` is required, e.g.

```
sudo apt install clang llvm libelf-dev build-essential libc6-dev-i386 libbpf-dev
```

## Setup

Load it with `tc` command:

```
tc qdisc add dev ${IFACE} clsact
tc filter add dev ${IFACE} egress bpf object-file tcp_in_udp_tc.o section tc_client_egress direct-action
tc filter add dev ${IFACE} ingress bpf object-file tcp_in_udp_tc.o section tc_client_ingress direct-action

tc qdisc add dev ${IFACE} clsact
tc filter add dev ${IFACE} egress bpf object-file tcp_in_udp_tc.o section tc_server_egress direct-action
tc filter add dev ${IFACE} ingress bpf object-file tcp_in_udp_tc.o section tc_server_ingress direct-action
```

GRO/TSO cannot be used on this interface, because each UDP packet will carry a
part of the TCP headers, not part of the data that can be merged:

```
ethtool -K ${IFACE} gro off lro off gso off tso off ufo off sg off
```

## Identification

### Client side:

- Ingress: A specific sport in TCP-in-UDP
- Egress: A specific dport in TCP

### Server side:

- Ingress: A specific dport in TCP-in-UDP
- Egress: A specific sport in TCP

## Packet Data Modification

```
tcphdr
bit 0 - 15	Source Port
bit 16 - 31	Destination Port
bit 32 - 47	Sequence Number First Half
bit 48 - 63	Sequence Number Second Half
bit 64 - 79	Acknowledgment Number First Half
bit 80 - 95	Acknowledgment Number Second Half
bit 96 - 111	Data Offset and Flags
bit 112 - 127	Window
bit 128 - 143	Checksum
bit 144 - 159	Urgent Pointer

tcphdr to tinuhdr
bit 0 - 15	Source Port
bit 16 - 31	Destination Port
bit 32 - 47	Length (A change, must be calculated)
bit 48 - 63	Checksum (A change, nothing needed to do, BPF helper will calculate)
bit 64 - 79	Acknowledgment Number First Half
bit 80 - 95	Acknowledgment Number Second Half
bit 96 - 111	Data Offset and Flags
bit 112 - 127	Window
bit 128 - 143	Sequence Number First Half (A change, read it from tcphdr_addr->seq)
bit 144 - 159	Sequence Number Second Half (A change, read it from tcphdr_addr->seq)

tinuhdr to tcphdr
bit 0 - 15	Source Port
bit 16 - 31	Destination Port
bit 32 - 47	Sequence Number First Half (A change, read it from tinuhdr->seq)
bit 48 - 63	Sequence Number Second Half (A change, read it from tinuhdr->seq)
bit 64 - 79	Acknowledgment Number First Half
bit 80 - 95	Acknowledgment Number Second Half
bit 96 - 111	Data Offset and Flags
bit 112 - 127	Window
bit 128 - 143	Checksum (A change, nothing needed to do, BPF helper will calculate)
bit 144 - 159	Urgent Pointer (A change, set it to 0)
```

## Checksum Computation

### TCP
```
                  0      7 8     15 16    23 24    31
                 +--------+--------+--------+--------+
                 |          source address           |
                 +--------+--------+--------+--------+
                 |        destination address        |
                 +--------+--------+--------+--------+
                 |  zero  |   TCP  |   UDP length    |
                 +--------+--------+--------+--------+

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |       |C|E|U|A|P|R|S|F|                               |
| Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
|       |       |R|E|G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |         Urgent Pointer        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### TCP-in-UDP
```
                  0      7 8     15 16    23 24    31
                 +--------+--------+--------+--------+
                 |          source address           |
                 +--------+--------+--------+--------+
                 |        destination address        |
                 +--------+--------+--------+--------+
                 |  zero  |   UDP  |   UDP length    |
                 +--------+--------+--------+--------+

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Source Port          |       Destination Port        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Length             |           Checksum            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Acknowledgment Number                      |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Data |       |C|E|U|A|P|R|S|F|                               |
| Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
|       |       |R|E|G|K|H|T|N|N|                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                        Sequence Number                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                              ...                              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

```
Modify IPv4 header: change checksum: calculate checksum. old data: bpf_htons(proto_old), new data: bpf_htons(proto)
Modify TCP header: change checksum: calculate checksum. old data: bpf_htons(proto_old), new data: bpf_htons(proto)
Modify TCP-in-UDP header: change checksum: calculate checksum. old data: urgent pointer (0), new data: length

Modify IPv4 header: change protocol: set from TCP to UDP.
Modify TCP-in-UDP header: tinuhdr_addr->udphdr.len = bpf_htons(ip_payload_len);
Modify TCP-in-UDP header: tinuhdr_addr->udphdr.check = tcphdr_addr->check;
Modify TCP-in-UDP header: tinuhdr_addr->seq = tcphdr_addr->seq;
```
