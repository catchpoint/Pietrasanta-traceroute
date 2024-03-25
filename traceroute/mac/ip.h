/*
    Copyright(c)  2023   Alessandro Improta, Luca Sani, Catchpoint Systems, Inc.
    
    This is a workaround to use IP header in Mac OS assuming the endianness of the architecture is little endian 

    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#ifndef _APPLE_IP_H
#define _APPLE_IP_H

#include "types.h"

#define __struct_group(TAG, NAME, ATTRS, MEMBERS...) \
    union { \
        struct { MEMBERS } ATTRS; \
        struct TAG { MEMBERS } ATTRS NAME; \
    }

#define IP_MTU_DISCOVER 10
#define IP_RECVERR 11

#define IP_PMTUDISC_DONT 0
#define IP_PMTUDISC_WANT 1
#define IP_PMTUDISC_DO 2
#define IP_PMTUDISC_PROBE 3

#define IPV6_MTU_DISCOVER 23
#define IPV6_RECVERR 25
#define IPV6_HOPLIMIT 52
#define IPV6_RTHDR 57

#define IPV6_PMTUDISC_DONT 0
#define IPV6_PMTUDISC_WANT 1
#define IPV6_PMTUDISC_DO 2
#define IPV6_PMTUDISC_PROBE 3

#ifndef s6_addr32
#define s6_addr32 __u6_addr.__u6_addr32
#endif

struct iphdr {
    __u8 ihl:4, version:4;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __struct_group(/* no tag */, addrs, /* no attrs */,
        __be32 saddr;
        __be32 daddr;
    );
    /*The options start here. */
};

#endif
