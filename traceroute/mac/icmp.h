/*
    Copyright(c)  2023   Alessandro Improta, Luca Sani, Catchpoint Systems, Inc.
    
    This is a workaround to use ICMP header in Mac OS assuming the endianness of the architecture is little endian 

    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include "types.h"

#define ICMP_DEST_UNREACH 3
#define ICMP_SOURCE_QUENCH 4
#define ICMP_TIME_EXCEEDED 11
#define ICMP_PARAMETERPROB 12

#define ICMP_EXC_TTL 0

struct icmphdr {
    __u8 type;
    __u8 code;
    __sum16 checksum;
    union {
        struct {
            __be16 id;
            __be16 sequence;
        } echo;
        __be32 gateway;
        struct {
            __be16 __unused;
            __be16 mtu;
        } frag;
        __u8 reserved[4];
    } un;
};
