/*
    Copyright(c)  2023   Alessandro Improta, Luca Sani, Catchpoint Systems, Inc.
    
    This is a workaround to use Linux errqueue in Mac OS assuming the endianness of the architecture is little endian 

    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#ifndef _APPLE_ERRQUEUE_H
#define _APPLE_ERRQUEUE_H

#include "types.h"

#define SO_EE_ORIGIN_NONE 0
#define SO_EE_ORIGIN_LOCAL 1
#define SO_EE_ORIGIN_ICMP 2
#define SO_EE_ORIGIN_ICMP6 3
#define SO_EE_ORIGIN_TXSTATUS 4
#define SO_EE_ORIGIN_ZEROCOPY 5
#define SO_EE_ORIGIN_TXTIME 6

#define SO_EE_OFFENDER(ee) ((struct sockaddr*)((ee)+1))

#define MSG_ERRQUEUE 0x2000

/* RFC 4884: return offset to extension struct + validation */
struct sock_ee_data_rfc4884 {
    __u16 len;
    __u8 flags;
    __u8 reserved;
};

struct sock_extended_err {
    __u32 ee_errno;    
    __u8 ee_origin;
    __u8 ee_type;
    __u8 ee_code;
    __u8 ee_pad;
    __u32 ee_info;
    union {
        __u32 ee_data;
        struct sock_ee_data_rfc4884 ee_rfc4884;
    };
};

#endif