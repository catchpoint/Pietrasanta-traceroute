/*
    Copyright (c)  2024             Catchpoint Systems, Inc.    
    Copyright (c)  2024             Alessandro Improta, Luca Sani
                    <aimprota@catchpoint.com>    
                    <lsani@catchpoint.com>    
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include "common-tcp.h"

struct tcp_flag tcp_flags[] = {
    { "fin", FIN },
    { "syn", SYN },
    { "rst", RST },
    { "psh", PSH },
    { "ack", ACK },
    { "urg", URG },
    { "ece", ECE },
    { "cwr", CWR },
    { "ae", AE }
};

struct tcp_opt tcp_opts[] = {
    { "sack", OPT_SACK },
    { "timestamps", OPT_TSTAMP },
    { "window_scaling", OPT_WSCALE }
};

int flags = 0;
int flags_provided = 0;
int options = 0;

char* names_by_flags(uint16_t flags)
{
    int i;
    char str[64];    /*  enough...  */
    char* curr = str;
    char* end = str + sizeof(str) / sizeof(*str);

    for(i = 0; i < sizeof(tcp_flags) / sizeof(*tcp_flags); i++) {
        const char* p;

        if(!(flags & tcp_flags[i].flag))  
            continue;

        if(curr > str && curr < end)  
            *curr++ = ',';
        for(p = tcp_flags[i].name; *p && curr < end; *curr++ = *p++);
    }

    *curr = '\0';

    return strdup(str);
}

// Get the flags value from the given TCP header pointer
uint16_t get_th_flags(struct tcphdr* th)
{
    return ((((uint8_t *)th)[12] << 8) | ((uint8_t *)th)[13]) & 0x01ff;
}

// Set the flags into the given TCP header pointer
void set_th_flags(struct tcphdr* th, uint16_t val)
{
    ((uint8_t *)th)[12] = ((val >> 8) & 0x0001); // Only the last bit of the first byte is relevant (the AE flag)
    ((uint8_t *)th)[13] = (val & 0x00ff); // All the last 8 bits are relevant
}

// Record a TCP option provided in input
int set_tcp_option(CLIF_option* optn, char* arg)
{
    for(int i = 0; i < sizeof(tcp_opts) / sizeof(*tcp_opts); i++) {
        if(!strcmp(optn->long_opt, tcp_opts[i].name)) {
            options |= tcp_opts[i].option;
            return 0;
        }
    }

    return -1;
}

// Record a TCP flag provided in input
int set_tcp_flag(CLIF_option* optn, char* arg)
{
    for(int i = 0; i < sizeof(tcp_flags) / sizeof(*tcp_flags); i++) {
        if(!strcmp(optn->long_opt, tcp_flags[i].name)) {
            flags |= tcp_flags[i].flag;
            return 0;
        }
    }

    return -1;
}

// Record the TCP flags value provided in input
int set_tcp_flags(CLIF_option* optn, char* arg)
{
    char* q;
    unsigned long value = strtoul(arg, &q, 0);
    if(q == arg)
        return -1;

    flags = (flags & ~0x01ff) | (value & 0x01ff);
    flags_provided = 1;
    return 0;
}
