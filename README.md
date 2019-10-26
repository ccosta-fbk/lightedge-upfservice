# Click Modular Router UPF Packages

This repository contains a package of external elements for the
[Click Modular Router](https://github.com/kohler/click),
compiled as shared libraries.

To build them you will need a Click installation somewhere.

# Build Instructions

Assuming Click was installed in the default location
(i.e. `/usr/local/...`), the whole build process is:

```
cd <upfrouter directory>
cmake -DCMAKE_BUILD_TYPE=Release .
make

cd <upfclick directory>
autoconf
./configure --prefix=/usr/local
make
sudo make install
```

This:

1. builds the UPF libraries and sample executables;

2. then it builds the Click Element(s) as a shared library containing
   evertything (it includes the UPF libraries). It also builds an
   element map for Click, describing the new elements;

3. then installs both the shared library and the element map into
   Click's installation directories -- so the Click runtime can find
   them (and load them on startup, if required).

# Click elements

This is a Click external package providing three new Click elements:

1. **UPFRouter** is an element intercepting and routing all traffic
   between eNodeBs, EPC and VNFs (see section [UPFRouter
   logic](#upfrouter-logic) below).

   It has three input/output ports working with L3 traffic:

   1. I/O port 0 for all traffic coming from/directed to the EPC.
      (S1AP traffic, GTPv1U traffic)

   2. I/O port 1 for all traffic coming from/directed to some eNodeB
      (S1AP traffic, GTPv1U traffic)

   3. I/O port 2 for traffic from/to local processing (i.e. VNFs)
      (ordinary L3 traffic)

   There is also a fourth optional output port (port 3) for unknown
   IPv4 traffic neither coming from the EPC nor coming from a eNodeB,
   and figuring as directed (or coming from) an unknown UE. This
   traffic can't be reasonably forwarded anywhere, and normally should
   be dropped.

   Its processing policy is AGNOSTIC for inputs, and PUSH for outputs.

2. **UPFPcapReader** is an element logically similar to the
   standard `fromdump` Click element, but it is able to properly read a
   `.pcap` file containing Ethernet traffic captured via Wireshark or
   similar tools. It is provided just for testing purposes, and it is
   able to read both `.pcap` files containing raw Ethernet frames or
   LinuxCooked packets.

   It has just one output port, and its processing policy is AGNOSTIC.

3. **UPFPcapWriter** is an element logically similar to the
   standard `todump` Click element, but it is able to properly write a
   `.pcap` file containing Ethernet traffic which can be read back
   by Wireshark. It is provided just for testing purposes, and it is
   able to write `.pcap` files containing raw Ethernet frames.

   It has just one input port, and its processing policy is AGNOSTIC.

# Sample Click configuration for UPFRouter

```

require(package "lvnfs2"); ControlSocket("TCP", 7777);

upfr :: UPFRouter()

kt :: KernelTun(ADDR 10.0.0.2/24, DEVNAME tun0);

s_client :: Socket("UDP", ADDR 10.103.173.254, PORT 5555);

s_server :: Socket("UDP", ADDR 0.0.0.0, PORT 5555);

ktgw :: KernelTun(ADDR 10.90.90.1/24, DEVNAME tun1);


s_server
        -> Print("from s_server[0] to [0]CheckIPHeader", MAXLENGTH 0)
        -> CheckIPHeader()
        -> Print("from CheckIPHeader[0] to [0]Print", MAXLENGTH 0)
        -> IPReassembler()
        // -> Queue(50)
        -> Print("from Print[0] to [1]upfr", MAXLENGTH 0)
        -> [1]upfr;

kt
        -> Print("from kt[0] to [0]CheckIPHeader", MAXLENGTH 0)
        -> CheckIPHeader()
        -> IPReassembler()
        // -> Queue(50)
        -> [0]upfr;


upfr[0]
       -> Print("from upfr[0] to [0]kt", MAXLENGTH 0)
       -> IPFragmenter(1000)
       -> kt;

upfr[1]
        -> Print("from upfr[1] to [0]s_client", MAXLENGTH 0)
        -> IPFragmenter(1000)
        -> s_client;

upfr[2]
        -> Print("from upfr[2] to [0]ktgw", MAXLENGTH 0)
        -> IPFragmenter(1000)
        -> ktgw;

ktgw
        -> Print("from ktgw[0] to [2]upfr", MAXLENGTH 0)
        //-> Queue(50)
        -> [2]upfr;
```

# Sample start script

```
#!/bin/sh

click myscript2.click &

sleep 3
# Setup tun device (ensure env variable $enbs_subnet is set)
ip route add $enbs_subnet dev tun0
```

# Sample commands for UPFRouter read/write handlers

Here we assume that the UPFRouter element is named `upfr` in Click configuration.

## Get UEMap
```
read upfr.uemap
```

## Insert MatchMap entries into given position
```
write upfr.matchmapins 0 6-192.168.13.0/24-80
```

## Append MatchMap entries at end (no position)

write upfr.matchmapappend 6-192.168.13.0/24-80

## Delete MatchMap entry at given position
```
write upfr.matchmapdel 0
```

## Get MatchMap
```
read upfr.matchmap
```



## Disable UDP checksums on encapsulated GTPv1-U traffic

```
write upfr.enableudpchecksum false
```

## Disable dumping on console of unknown IPv4 traffic

```
write upfr.enableunknowntrafficdump false
```

# UPFRouter maps and configuration items


1. UEMap: map of known UE -> GTP tunnel endpoints

   ``std::unordered_map<IPv4Address, GTPv1UTunnelInfo>``

   where a GTPv1UTunnelInfo specifies

   * IPv4Address and TEID of a EPC endpoint;
   * IPv4Address and TEID of a eNodeB endpoint;

   UPFRouter Click element builds it on the fly, intercepting and
   analyzing S1AP traffic between the eNodeBs and the EPCs.

   Its content can be read via a read handler (see examples below).

2. MatchMap: a map (actually, a list) of matching rules for
   GTPv1-U-encapsulated IPv4 traffic between the EPC and a eNodeB that
   has to be diverted to local processing (instead of being
   forwarded).

   The matching rule is specified as follows:

   * a protocol number (identifying TCP, UDP, etc.). `0` matches any protocol.
     Example: 6 = TCP, 17 = UDP, 1 = ICMP, etc.

   * a IPv4 CIDR (address + netmask bits) to be matched against the **destination address**.
     '0.0.0.0/0' matches any address.
     Example: `192.168.3.0/24`

   * a TCP/UDP/SCTP/etc. port number (16-bit unsigned integer, to be used only if applicable to the protocol).
     `0` matches any port number.

    Note: for protocols where port number is not applicable
    (e.g. ICMP), the port number in the matching rule has to be 0 to
    match.

   Example of human-readable matching rule:
   `6-192.168.3.0/24-80`

# UPFRouter logic

## S1AP traffic from port 0 or port 1

  The traffic is expected on port 0 and 1 and is analyzed to build the
  UEMap and keep it up-to-date, but other than that it is forwarded
  as-is. Traffic coming from port 0 is directed to port 1 and
  vice-versa.

## GTPv1-U IPv4 traffic from a eNodeB (port 1, look in UEMap and MatchMap)

GTPv1-U Traffic coming from port 1 is decapsulated and matched against
the MatchMap and, if it matches an entry, it is then matched against
the UEMap (for source address)

* if it matches an entry in both maps, the decapsulated L3 traffic is directed
  (unchanged) as plain L3 traffic on port 2;

* otherwise the original GTPv1-U packet is directed unchanged to port
  0 (because it comes from an unknown UE or there is no matching rule).

## GTPv1-U IPv4 traffic from the EPC (port 0, look in UEMap and MatchMap)

GTPv1-U Traffic coming from port 0 is decapsulated and matched against
the MatchMap and, if it matches an entry, it is then matches against
the UEMap (for destination address) to check it is directed
to a known UE:

* if it matches an entry in both maps, the decapsulated traffic is
  directed (unchanged) as plain L3 traffic on port 2;

* otherwise the original GTPv1-U packet is directed unchanged to port
  1.

## Other L3 traffic from port 0 or from port 1

It's directed unchanged to its matching port (i.e. traffic from port
0 is directed to port 1 and vice-versa).

## L3 Traffic coming from port 2

It is matched agains the UEMap for source and for destination address:

* if the source address matches an UE in UEMap, we assume it's traffic
  for the EPC: the traffic is encapsulated in GTPv1-U and directed to
  port 0;

* if the destination address matches an UE in UEMap, we assume it's
  traffic for a eNodeB: the traffic is encapsulated in GTPv1-U and
  directed to port 1;

Otherwise, if there's no match, the traffic is discarded.
