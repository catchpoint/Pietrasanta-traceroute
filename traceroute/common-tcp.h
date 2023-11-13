#ifndef COMMON_TCP_H
#define COMMON_TCP_H

#include <netinet/tcp.h>
#include <stdint.h>
#include <stdlib.h>

#include "traceroute.h"

#define FIN    0x0001
#define SYN    0x0002
#define RST    0x0004
#define PSH    0x0008
#define ACK    0x0010
#define URG    0x0020
#define ECE    0x0040
#define CWR    0x0080
#define AE    0x0100 // AccECN

#define OPT_SACK      0x01
#define OPT_TSTAMP    0x02
#define OPT_WSCALE    0x04

struct tcp_flag {
    const char *name;
    unsigned int flag;
};

extern struct tcp_flag tcp_flags[];

struct tcp_opt {
    const char *name;
    unsigned int option;
};

extern struct tcp_opt tcp_opts[];

extern int flags; // Records which TCP flags are provided in input (via arguments)
extern int flags_supplied; // This is used to remember if the user supplied a TCP flags value. This is needed because the user could supply a value of zero
extern int options; // Records which TCP options are provided in input (via arguments)

char* names_by_flags(uint16_t flags);
uint16_t get_th_flags(struct tcphdr* th);
void set_th_flags(struct tcphdr* th, uint16_t val);
int set_tcp_option(CLIF_option* optn, char* arg);
int set_tcp_flag(CLIF_option* optn, char* arg);
int set_tcp_flags(CLIF_option* optn, char* arg);

#endif
