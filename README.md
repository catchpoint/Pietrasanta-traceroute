# Catchpoint's Pietrasanta traceroute

## Introduction

This is an enhanced version of Dmitry Butskoy traceroute developed by Catchpoint.  

Traceroute is one of the oldest network diagnostic tools. It was first built to answer 
the thorny question, where are the packets going? However, various challenges introduced 
by firewalls and load balancers have made the original traceroute less useful and 
reliable than it once was.

We did a number of improvements to Dmitry's work.  The main ones are enumerated here:
* Support for "TCP InSession" method. This method opens a TCP connection with
the destination and sends TCP probes within the opened session with incremental
TTL. The aim is to prevent false packet loss introduced by firewall and
router configurations related to security and to ensures that packets follow a
single flow, akin to a normal TCP session, to bypass load-balanced routers.
 - Introduced enhanced TOS (DSCP/ECN) field report. This new option allows to set 
ToS field in outgoing packets and read the ToS field of the expiring probes. It
includes a special output to highlight DSCP and ECN values.
- Introduced the QUIC module to perform QUIC traceroute using --quic. This mode
uses QUIC Initial packets as probes.
 
Full details in ChangeLog [here](ChangeLog). 

Following the convention of naming traceroute after the place where they are developed,
we named our traceroute after the tiny town where the Catchpoint Italian branch is based: 
Pietrasanta traceroute.

Happy (Pietrasanta) tracerouting!

## Building & Installation
```
make 
make install
```

### OpenSSL 3 dependency

Since version 0.1.3 (the version that introduced QUIC support), openssl3 (version >= 3.2) is needed to compile
traceroute. If openssl3 libraries are not available, you can still build and enjoy traceroute by disabling
QUIC by passing the argument `DISABLE_OPENSSL=1` to `make`. 

At compile time openssl3 header files are searched by default in `/usr/local/include` 
but the path can be changed via the `LIBSSL3_CFLAGS` argument. 
At linking time and runtime openssl3 libraries are searched in
`/usr/local/lib64` but the path can be changed via the `LIBSSL3_LDFLAGS` argument.

A way to obtain openssl3 libraries is to compile them  from source.
As an example these are the steps to get shared objects in `/usr/local/lib64` and
header files in `/usr/local/include`:

```
git clone -b openssl-3.2 https://github.com/openssl/openssl.git
cd openssl
./Configure
make
make install
```

## Binaries

This tool should build and run on any Linux system running a kernel version 2.6 or higher. This includes systems running on containers, VMs and on the Windows Subsystem for Linux (WSL).

Since version 0.1.14 this tool should also work on MacOS, with the known limitations that TCP and TCP InSession mode are not yet available and Path MTU discovery is not supported for any mode.

Binaries are provided for convenience [here](binaries) for common Linux distributions and they can be directly used into the target system.

A way to use the provided binaries is the following:

* Download the binary from `https://raw.githubusercontent.com/catchpoint/Networking.traceroute/main/binaries/<distro>/traceroute`
* Provide executable permission (e.g. `chmod +x <binary>`)
* Optionally provide `cap_net_raw` capability to make it run without the need of being root for privileged commands (e.g. like traceroute TCP), via `sudo setcap cap_net_raw+ep <binary>`.
* Ensure that openssl3 libraries are available in the system. For example for ubuntu 22.04 they should be installed by default. See `OpenSSL 3 dependency` section for more information about that.

### Building with docker

The binaries provided in the `binaries` folder are obtained compiling the tool on OS-dedicated dockerfiles.
For convenience these dockerfiles are included into the `dockerfiles` folder and a build (bash) script called `build.sh` is provided.
To obtain binaries with QUIC enabled it is , a folder containing `openssl3` source code is requested and
Typically this will be a branch of the official OpenSSL github repositorty containing an openssl 3.2+ version.
If no folder is provided, traceroute binaries with QUIC disabled will be produced (like passing `DISABLE_OPENSSL=1` to `make`).
The script places the binaries into the [binaries] folder for the given platform(s).

The build script takes these options:

* `--build`: build the binaries.
* `--clean`: clean docker images and containers created during the build process.
* `--platform="<space separated list of platforms>"`: build and/or clean for the specified list of platforms. Accepted platforms values are: `ol8` (Oracle Linux 8), `ol9` (Oarcle Linux 9), `debian12` (Debian 12) and `ubuntu24` (Ubuntu 24). By default they are all enabled.
* `--disable-openssl3`: Whether to disable openssl3, in this case QUIC module will not be available.

The build script requires GNU [getopt](https://linux.die.net/man/1/getopt) (which is available by default on Linux).

Example:

```
./build.sh - --build --clean
```

This will produce the binaries for Oracle Linux 8, Oracle Linux 9, Debian 12, Ubuntu 24 and place them into the `binaries` folder.

For convenience an helper script called `build_openssl.sh` is provided into the `build` folder to compile openssl3 libraries for the presupported platforms. 
This script takes in input a source folder of openssl3 and builds openssl for all the presupported
platforms of traceroute, putting them into the `build/<os>/precompiled_openssl` folder.
Optionally a `--platform` parameter can be passed to compile openssl3 for a subset of the presupported platforms.

When it is not invoked with  `--disable-openssl3`, the `build.sh` script will look for the presence of those libraries to build traceroute for a platform.

So the full sequence of builindg traceroute for all the presupported platforms is:

* `./build_openssl.sh -- --openssl3=<openssl3 source folder>`
* `./build.sh - --build --clean`

To build for one specific platform:

* `./build_openssl.sh -- --openssl3=<openssl3 source folder> --platform=ubuntu24`
* `./build.sh - --build --clean --platform=ubuntu24`

Note that the building of openssl3 is required only the first time while subsequent changes to traceroute source code
can be compiled invoking only the `build.sh` script.

## Usage

See [traceroute(8)](traceroute/traceroute.8) for detailed instructions.

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
