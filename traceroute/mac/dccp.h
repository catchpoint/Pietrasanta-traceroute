/*
    Copyright(c)  2023   Alessandro Improta, Luca Sani, Catchpoint Systems, Inc.
    
    This is a workaround to use DCCP in Mac OS assuming the endianness of the architecture is little endian 

    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include "types.h"

#define DCCP_PKT_REQUEST 0
#define SOCK_DCCP 6 
#define IPPROTO_DCCP 33

struct dccp_hdr {
    __be16 dccph_sport;
    __be16 dccph_dport;
    __u8 dccph_doff;
    __u8 dccph_cscov:4, dccph_ccval:4;
    __sum16 dccph_checksum;
    __u8 dccph_x:1, dccph_type:4, dccph_reserved:3;
    __u8 dccph_seq2;
    __be16 dccph_seq;
};

struct dccp_hdr_ext {
    __be32 dccph_seq_low;
};

struct dccp_hdr_request {
    __be32 dccph_req_service;
};
