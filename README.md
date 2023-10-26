# Catchpoint traceroute

## Introduction

This is an enhanced version of Dmitry Butskoy traceroute developed by Catchpoint.  
There are a number of improvements.  The main ones are enumerated here:
* Support for "TCP InSession" method. This method opens a TCP connection with
the destination and sends TCP probes within the opened session with incremental
TTL. The aim is to prevent false packet loss introduced by firewall and
router configurations related to security and to ensures that packets follow a
single flow, akin to a normal TCP session, to bypass load-balanced routers.
 - Introduced enhanced TOS (DSCP/ECN) field report. This new option allows to set 
ToS field in outgoing packets and read the ToS field of the expiring probes. It
includes a special output to highlight DSCP and ECN values
 
Full details in ChangeLog [here](https://github.com/catchpoint/Networking.traceroute/blob/develop/ChangeLog).

## Building & Installation
```
make 
make install
```

## Binaries

This tool should build on any modern Linux system.  

Binaries are provided for convenience [here](https://github.com/catchpoint/Networking.traceroute/tree/main/binaries) for common Linux distributions.

## Usage

See `traceroute(8)` for detailed instructions.

## Original Dmitry Butskoy README file

This is a new modern implementation of the traceroute(8)
utility for Linux systems.

Traceroute tracks the route packets taken from an IP network on their
way to a given host. It utilizes the IP protocol's time to live (TTL)
field and attempts to elicit an ICMP TIME_EXCEEDED response from each
gateway along the path to the host.

Main features:
- Full support for both IPv4 and IPv6 protocols
- Several tracerouting methods, including:
  * UDP datagrams (including udplite and udp to particlular port)
  * ICMP ECHO packets (including dgram icmp sockets)
  * TCP SYNs (in general, any TCP request with various flags and options)
  * DCCP Request packets
  * Generic IP datagrams
- UDP methods do not require root privileges
- Ability to send several probe packets at a time
- Ability to compute a proper time to wait for each probe
- perform AS path lookups for returned addresses
- show ICMP extensions, including MPLS
- perform path MTU discovery automatically
- show guessed number of hops in backward direction
- command line compatible with the original traceroute
- and much more, see traceroute(8)

This code was written from the scratch, using some ideas of
Olaf Kirch's traceroute, the original implementation of Van Jacobson
(which was long used before) and some current BSD's ones.

This traceroute requires Linux kernel 2.6 and higher.

You can try to contact the author at <Dmitry at Butskoy dot name> .


Good tracerouting!

Dmitry Butskoy