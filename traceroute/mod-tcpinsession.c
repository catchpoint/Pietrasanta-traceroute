/*
    Copyright(c)  2023   Alessandro Improta, Luca Sani, Catchpoint Systems, Inc.
    
    This software was updated by Catchpoint Systems, Inc. to incorporate
    InSession algorithm functionality.
    
    Copyright(c)  2006, 2007        Dmitry Butskoy
                    <buc@citadel.stu.neva.ru>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netdb.h>
       
#include "traceroute.h"
#include "flowlabel.h"

#define MAX_CONNECT_TIMEOUT_SEC 5

#ifndef IP_MTU
#define IP_MTU 14
#endif

#ifdef __APPLE__
#include "mac/ip.h"
#include "mac/types.h"
#include <string.h>
#endif

static sockaddr_any dest_addr = {{ 0, }, };
static unsigned int dest_port = 0;

static int raw_icmp_sk = -1;
static int raw_sk = -1;
static int sk = -1;
static int last_ttl = 0;

static int mtu = 0;
static int af = 0;
static int header_len = 0;

static unsigned pseudo_IP_header_size = 0;
static uint8_t* counter_pointer = NULL;
static uint8_t* buf;        /*  enough, enough...  */
static uint8_t tmp_buf[1024];        /*  enough, enough...  */
static size_t* length_p;
static sockaddr_any src;
static uint32_t ts_value_offset = 0;
static struct tcphdr* th = NULL;
static uint16_t* lenp = NULL;

#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80

static int flags = 0;        /*  & 0xff == tcp_flags ...  */
static int sysctl = 0;
static int reuse = 0;
static unsigned mss_received = 0;
static unsigned int mss = 0;
static int info = 0;

#define FL_FLAGS 0x0100
#define FL_ECN 0x0200
#define FL_SACK 0x0400
#define FL_TSTAMP 0x0800
#define FL_WSCALE 0x1000

static struct 
{
    const char* name;
    unsigned int flag;
} tcp_flags[] = {
    { "fin", TH_FIN },
    { "syn", TH_SYN },
    { "rst", TH_RST },
    { "psh", TH_PSH },
    { "ack", TH_ACK },
    { "urg", TH_URG },
    { "ece", TH_ECE },
    { "cwr", TH_CWR },
};

uint32_t initial_seq_num = 0;
uint32_t seq_num = 0;
uint32_t ack_num = 0;
uint32_t ts_value = 0;
uint32_t ts_echo_reply = 0;

static char* names_by_flags(unsigned int flags)
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

static int set_tcp_flag(CLIF_option* optn, char* arg) 
{
    int i;

    for(i = 0; i < sizeof(tcp_flags) / sizeof(*tcp_flags); i++) {
        if(!strcmp(optn->long_opt, tcp_flags[i].name)) {
            flags |= tcp_flags[i].flag;
            return 0;
        }
    }

    return -1;
}

static int set_tcp_flags(CLIF_option* optn, char* arg) 
{
    char* q;
    unsigned long value;

    value = strtoul(arg, &q, 0);
    if(q == arg)
        return -1;

    flags = (flags & ~0xff) | (value & 0xff) | FL_FLAGS;
    return 0;
}

static int set_flag(CLIF_option* optn, char* arg)
{
    flags |= (unsigned long)optn->data;

    return 0;
}

static CLIF_option tcp_options[] = {
    { 0, "syn", 0, "Set tcp flag SYN (default if no other tcp flags specified)", set_tcp_flag, 0, 0, 0 },
    { 0, "ack", 0, "Set tcp flag ACK,", set_tcp_flag, 0, 0, 0 },
    { 0, "fin", 0, "FIN,", set_tcp_flag, 0, 0, 0 },
    { 0, "rst", 0, "RST,", set_tcp_flag, 0, 0, 0 },
    { 0, "psh", 0, "PSH,", set_tcp_flag, 0, 0, 0 },
    { 0, "urg", 0, "URG,", set_tcp_flag, 0, 0, 0 },
    { 0, "ece", 0, "ECE,", set_tcp_flag, 0, 0, 0 },
    { 0, "cwr", 0, "CWR", set_tcp_flag, 0, 0, 0 },
    { 0, "flags", "NUM", "Set tcp flags exactly to value %s", set_tcp_flags, 0, 0, CLIF_ABBREV },
    { 0, "ecn", 0, "Send syn packet with tcp flags ECE and CWR (for Explicit Congestion Notification, rfc3168)", set_flag, (void*)FL_ECN, 0, 0 },
    { 0, "sack", 0, "Use sack,", set_flag, (void*)FL_SACK, 0, 0 },
    { 0, "timestamps", 0, "timestamps,", set_flag, (void*)FL_TSTAMP, 0, CLIF_ABBREV },
    { 0, "window_scaling", 0, "window_scaling option for tcp", set_flag, (void*)FL_WSCALE, 0, CLIF_ABBREV },
    { 0, "sysctl", 0, "Use current sysctl (/proc/sys/net/*) setting for the tcp options and ecn. Always set by default (with \"syn\") if nothing else specified", CLIF_set_flag, &sysctl, 0, 0 },
    { 0, "reuse", 0, "Allow to reuse local port numbers for the huge workloads (SO_REUSEADDR)", CLIF_set_flag, &reuse, 0, 0 },
    { 0, "mss", "NUM", "Use value of %s for maxseg tcp option (when syn)", CLIF_set_uint, &mss, 0, 0 },
    { 0, "info", 0, "Print tcp flags of final tcp replies when target host is reached. Useful to determine whether an application listens the port etc.", CLIF_set_flag, &info, 0, 0 },
    CLIF_END_OPTION
};

#define SYSCTL_PREFIX "/proc/sys/net/ipv4/tcp_"
static int check_sysctl(const char* name) 
{
    int fd;
    int res;
    char buf[sizeof(SYSCTL_PREFIX) + strlen(name) + 1];
    uint8_t ch;

    strcpy(buf, SYSCTL_PREFIX);
    strcat(buf, name);

    fd = open(buf, O_RDONLY, 0);
    if(fd < 0)
        return 0;

    res = read(fd, &ch, sizeof(ch));
    close(fd);

    if(res != sizeof(ch))
        return 0;

    /*  since kernel 2.6.31 "tcp_ecn" can have value of '2'...  */
    if(ch == '1')
        return 1;

    return 0;
}

static int tcpinsession_init(const sockaddr_any* dest, unsigned int port_seq, size_t* packet_len_p) 
{
    initial_seq_num = rand();
    
    af = dest->sa.sa_family;

    if(!port_seq)  
        port_seq = DEF_TCP_PORT;
    dest_port = htons(port_seq);
    
    dest_addr = *dest;
    
    if(af == AF_INET)
        dest_addr.sin.sin_port = dest_port;
    else
        dest_addr.sin6.sin6_port = dest_port;
    
    raw_sk = socket(af, SOCK_RAW, IPPROTO_TCP);
    if(raw_sk < 0)
        error_or_perm("socket");

    tune_socket(raw_sk);
    
    double connect_starttime = get_time();
    
    if(connect(raw_sk, &dest_addr.sa, sizeof(dest_addr)) < 0)
        error("connect");
    
    sk = socket(af, SOCK_STREAM, 0);
    tune_socket(sk);    /*  common stuff  */
    
    if(connect(sk, &dest_addr.sa, sizeof(dest_addr)) < 0)
        if(errno != EINPROGRESS) // note that we don't need to wait the connect to be successful since the loop below will wait for the syn+ack.
            error("connect");

    socklen_t lenmtu = sizeof(mtu);
    if(getsockopt(raw_sk, af == AF_INET ? SOL_IP : SOL_IPV6, af == AF_INET ? IP_MTU : IPV6_MTU, &mtu, &lenmtu) < 0 || mtu < 576)
        mtu = 576;
        
    socklen_t src_len = sizeof(src);
    if(getsockname(sk, &src.sa, &src_len) < 0)
        error("getsockname");
     
    uint8_t ack_buf[1024];
    int found = 0;
    int received = 0;
    sockaddr_any response_src_addr;
    memset(&response_src_addr, 0, sizeof(response_src_addr));
    socklen_t src_addr_len = sizeof(response_src_addr);
    
    do {
        if((received = recvfrom(raw_sk, ack_buf, sizeof(ack_buf), 0, &response_src_addr.sa, &src_addr_len)) >= 0) {
            struct tcphdr* response_tcp_hdr = NULL;
            uint8_t* opt_ptr = NULL;
            uint16_t option_len = 0;
            
            if(af == AF_INET) {
                struct iphdr* response_iphdr = (struct iphdr*)ack_buf;
                response_tcp_hdr = (struct tcphdr*) (ack_buf + (response_iphdr->ihl << 2));
#ifdef __APPLE__
                if(response_tcp_hdr->th_dport == src.sin.sin_port) {
                    if(((((uint8_t*)(response_tcp_hdr))[13]) & TH_SYN) && ((((uint8_t*)(response_tcp_hdr))[13]) & TH_ACK)) { // paranoid
                        response_src_addr.sin.sin_port = response_tcp_hdr->th_sport;
#else
                if(response_tcp_hdr->dest == src.sin.sin_port) {
                    if(((((uint8_t*)(response_tcp_hdr))[13]) & TH_SYN) && ((((uint8_t*)(response_tcp_hdr))[13]) & TH_ACK)) { // paranoid
                        response_src_addr.sin.sin_port = response_tcp_hdr->source;
#endif
                        if(equal_sockaddr(&dest_addr, &response_src_addr)) {
                            found = 1;
                            opt_ptr = ((uint8_t*)response_tcp_hdr)+sizeof(*response_tcp_hdr);
                            option_len = htons(response_iphdr->tot_len)-sizeof(*response_iphdr)-sizeof(*response_tcp_hdr);
                        }
                    }
                }
            } else if(af == AF_INET6) {
                response_tcp_hdr = (struct tcphdr*)ack_buf;
#ifdef __APPLE__
                if(response_tcp_hdr->th_dport == src.sin6.sin6_port) {
                    if(((((uint8_t*)(response_tcp_hdr))[13]) & TH_SYN) && ((((uint8_t*)(response_tcp_hdr))[13]) & TH_ACK)) { // paranoid
                        response_src_addr.sin6.sin6_port = response_tcp_hdr->th_sport;
#else
                if(response_tcp_hdr->dest == src.sin6.sin6_port) {
                    if(((((uint8_t*)(response_tcp_hdr))[13]) & TH_SYN) && ((((uint8_t*)(response_tcp_hdr))[13]) & TH_ACK)) { // paranoid
                        response_src_addr.sin6.sin6_port = response_tcp_hdr->source;
#endif
                        if(equal_sockaddr(&dest_addr, &response_src_addr)) {
                            found = 1;
                            opt_ptr = ((uint8_t*)response_tcp_hdr)+sizeof(*response_tcp_hdr);
                            option_len = received-sizeof(*response_tcp_hdr);
                        }
                    }
                }
            }
                    
            if(found) {
#ifdef __APPLE__
                initial_seq_num = ntohl(response_tcp_hdr->th_ack)+1;
                seq_num = initial_seq_num;
                ack_num = ntohl(response_tcp_hdr->th_seq)+1;
#else
                initial_seq_num = ntohl(response_tcp_hdr->ack_seq)+1;
                seq_num = initial_seq_num;
                ack_num = ntohl(response_tcp_hdr->seq)+1;
#endif          
                int SACK_permitted = 0;
                for(uint16_t i = 0; i < option_len; i++) {
                    uint8_t opt_kind = *opt_ptr;
                    if(opt_kind == TCPOPT_EOL)
                        break;
                    
                    opt_ptr++;
                    if(opt_kind == TCPOPT_NOP)
                        continue;
                    
                    uint8_t opt_len = *opt_ptr;
                    opt_ptr++;
                    if(opt_kind == TCPOPT_SACK_PERMITTED) {
                        SACK_permitted = 1;
                        opt_ptr += opt_len;
                        opt_ptr -= 2; // opt kind and len are included in opt_len
                    } else if(opt_kind == TCPOPT_MAXSEG) {
                        mss_received = ntohs(*(uint16_t*)opt_ptr);
                        opt_ptr += opt_len;
                        opt_ptr -= 2; // opt kind and len are included in opt_len
                    } else if(opt_kind != TCPOPT_TIMESTAMP) {
                        opt_ptr += opt_len;
                        opt_ptr -= 2; // opt kind and len are included in opt_len
                    } else {
                        uint32_t timestamp_value = ntohl(*((uint32_t*)opt_ptr));
                        opt_ptr += sizeof(uint32_t);
                        uint32_t timestamp_echo_reply = ntohl(*((uint32_t*)opt_ptr));
                        
                        ts_value = htonl(timestamp_echo_reply+30);
                        ts_echo_reply = htonl(timestamp_value);
                        break;
                    }
                }
                
                if(SACK_permitted == 0)
                    error("TCP SACK not permitted from destination");
            }
        } else {
            if(get_time() - connect_starttime > MAX_CONNECT_TIMEOUT_SEC)
                break;
            
            usleep(10000);
        }
    } while(!found);
    
    if(!found)
        error("Cannot complete initial TCP handshake");
    
    socklen_t len;
    uint8_t* ptr;
   

    use_recverr(raw_sk);
    add_poll(raw_sk, POLLIN | POLLERR);

    /*  Now create the sample packet.  */

    if(!flags)
        sysctl = 1;

    // Force TCP SACK in mod-tcpinsession
    flags |= FL_SACK;
        
    if(sysctl) {
        if(check_sysctl("ecn"))  
            flags |= FL_ECN;
            
        // Forcing TCP SACK (above), timestamps and Window scale in TCP options. This fix forces the code to generate TCP SYN packets without payload, which eventually would cause the probes to be dropped by regular firewalls. 
        // TCP SYN packets with payload are generated due to an initial hard-coded value of 40B of the probe size which was present in the original code and is now used in the new path MTU discovery process. 
        // Please remove this comment once the bug has been fixed.
            
        flags |= FL_TSTAMP;
        flags |= FL_WSCALE;
    }

    if(!(flags & (FL_FLAGS | 0xff))) {    /*  no any tcp flag set */
        flags |= TH_PSH;
        flags |= TH_ACK;
        if(flags & FL_ECN)
            flags |= TH_ECE | TH_CWR;
    }

    /*  For easy checksum computing:
        saddr
        daddr
        length
        protocol
        tcphdr
        tcpoptions
    */

    ptr = tmp_buf;

    if(af == AF_INET) {
        len = sizeof(src.sin.sin_addr);
        memcpy(ptr, &src.sin.sin_addr, len);
        ptr += len;
        memcpy(ptr, &dest_addr.sin.sin_addr, len);
        ptr += len;
    } else {
        len = sizeof(src.sin6.sin6_addr);
        memcpy(ptr, &src.sin6.sin6_addr, len);
        ptr += len;
        memcpy(ptr, &dest_addr.sin6.sin6_addr, len);
        ptr += len;
    }

    lenp = (uint16_t*)ptr;
    uint16_t delta_len_p = ptr - tmp_buf;
    ptr += sizeof(uint16_t);
    *((uint16_t*)ptr) = htons((uint16_t)IPPROTO_TCP);
    ptr += sizeof(uint16_t);

    /*  Construct TCP header   */

    th = (struct tcphdr*)ptr;
    
    pseudo_IP_header_size = ptr - tmp_buf;

#ifdef __APPLE__
    th->th_sport = 0;        /*  temporary   */
    th->th_dport = dest_port;
    th->th_seq = 0;        /*  temporary   */
    th->th_ack = htonl(ack_num);
    th->th_off = 0;        /*  later...  */
    flags = 0x00;
    flags |= TH_PSH;
    flags |= TH_ACK;
    flags |= FL_TSTAMP;
    (((uint8_t *)(th))[13]) = flags;
    th->th_win = htons(4 * mtu);
    th->th_sum = 0;
    th->th_urp = 0;
#else
    th->source = 0;
    th->dest = dest_port;
    th->seq = 0;
    th->ack_seq = htonl(ack_num);
    th->doff = 0;
    flags = 0x00;
    flags |= TH_PSH;
    flags |= TH_ACK;
    flags |= FL_TSTAMP;
    (((uint8_t*)(th))[13]) = flags;
    th->window = htons(4 * mtu);
    th->check = 0;
    th->urg_ptr = 0;
#endif

    /*  Build TCP options   */

    ptr = (uint8_t*)(th + 1);

    if(flags & TH_SYN) {
        *ptr++ = TCPOPT_MAXSEG;    /*  2   */
        *ptr++ = TCPOLEN_MAXSEG;    /*  4   */
        *((uint16_t*)ptr) = htons(mss ? mss : mtu);
        ptr += sizeof(uint16_t);
    }

    if(flags & FL_TSTAMP) {
        if(flags & FL_SACK) {
            *ptr++ = TCPOPT_SACK_PERMITTED;    /*  4   */
            *ptr++ = TCPOLEN_SACK_PERMITTED;/*  2   */
        } else {
            *ptr++ = TCPOPT_NOP;    /*  1   */
            *ptr++ = TCPOPT_NOP;    /*  1   */
        }
        *ptr++ = TCPOPT_TIMESTAMP;    /*  8   */
        *ptr++ = TCPOLEN_TIMESTAMP;    /*  10  */

        ts_value_offset = ptr - (uint8_t*)th;
        *((uint32_t*)ptr) = ts_value; //random_seq();    /*  really!  */
        
        ptr += sizeof(uint32_t);
        *((uint32_t*)ptr) = ts_echo_reply; //(flags & TH_ACK) ? random_seq() : 0;
        ptr += sizeof(uint32_t);
    } else if(flags & FL_SACK) {
        *ptr++ = TCPOPT_NOP;    /*  1   */
        *ptr++ = TCPOPT_NOP;    /*  1   */
        *ptr++ = TCPOPT_SACK_PERMITTED;    /*  4   */
        *ptr++ = TCPOLEN_SACK_PERMITTED;    /*  2   */
    }

    if(flags & FL_WSCALE) {
        *ptr++ = TCPOPT_NOP;    /*  1   */
        *ptr++ = TCPOPT_WINDOW;    /*  3   */
        *ptr++ = TCPOLEN_WINDOW;    /*  3   */
        *ptr++ = 2;    /*  assume some corect value...  */
    }

    len = ptr - (uint8_t*)th;
    if(len & 0x03)
        error("impossible");    /*  as >>2 ...  */

#ifdef __APPLE__
    th->th_off = len >> 2;
#else
    th->doff = len >> 2;
#endif
    
    length_p = packet_len_p;
    *lenp = htons(*length_p);
    
    if(*length_p && !(buf = malloc(*length_p+pseudo_IP_header_size)))
        error("malloc");

    memcpy(buf, tmp_buf, pseudo_IP_header_size+len);
    th = (struct tcphdr*)(buf + pseudo_IP_header_size);

    counter_pointer = buf + pseudo_IP_header_size + len;

    for(int i = pseudo_IP_header_size + len; i < pseudo_IP_header_size + (*length_p); i++)
        buf[i] = 0x00;
    
    header_len = len;
    
    raw_icmp_sk = socket(dest_addr.sa.sa_family, SOCK_RAW, (dest_addr.sa.sa_family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6);
    
    if(raw_icmp_sk < 0)
        error("raw icmp socket");
    
    lenp = (uint16_t*)(buf + delta_len_p); // Allow the length in the pseudo IP header to be changed when we send probes 
    
    add_poll(raw_icmp_sk, POLLIN | POLLERR);
    
    return 0;
}

static void tcpinsession_send_probe(probe* pb, int ttl) 
{
#ifdef __APPLE__
    th->th_sport = src.sin.sin_port;
    th->th_seq = htonl(seq_num);
#else
    th->source = src.sin.sin_port;
    th->seq = htonl(seq_num);
#endif

    pb->seq = seq_num;
    
    if(counter_pointer == NULL)
        error("counter pointer uninitialized");
    
    (*counter_pointer)++;
    
    uint8_t* ts_ptr = ((uint8_t*)th)+ts_value_offset;
    uint32_t val = htonl(*((uint32_t*)ts_ptr));
    val++;
    *((uint32_t*)ts_ptr) = htonl(val);
    *lenp = htons(*length_p); 
#ifdef __APPLE__
    th->th_sum = 0;
    th->th_sum = in_csum(buf, (*length_p)+pseudo_IP_header_size);
#else
    th->check = 0;
    th->check = in_csum(buf, (*length_p)+pseudo_IP_header_size);
#endif
    if(ttl != last_ttl) {
        set_ttl(raw_sk, ttl);
        last_ttl = ttl;
    }

    pb->sk = -1;
    pb->send_time = get_time();
    
    int res = do_send(raw_sk, th, *length_p, &dest_addr);
    if(res < 0) {
        error("so bad");
        pb->send_time = 0;
    } else if(res > 0) {
        seq_num += (*length_p - header_len);
    }
}

int compare_desc(const void* a, const void* b)
{
    sack_block* u_a = (sack_block*)a;
    sack_block* u_b = (sack_block*)b;

    if(u_b->sle < u_a->sle)
        return -1;

    if(u_b->sle > u_a->sle)
        return 1;

    return 0;
}

static probe* find_probe_from_sack(struct tcphdr* tcp)
{
    const uint8_t* ptr = (const uint8_t*)(tcp + 1);
    
#ifdef __APPLE__
    int opt_len = (tcp->th_off * 4) - sizeof(struct tcphdr);
#else
    int opt_len = (tcp->doff * 4) - sizeof(struct tcphdr);
#endif
    
    sack_blocks curr_sack_blocks;
    memset(&curr_sack_blocks, 0, sizeof(curr_sack_blocks));
    
    uint8_t sack_block_i = 0;
    uint32_t interval = 0;
    int sack_found = 0;
    while(opt_len > 0) {
        int opcode = *ptr++;
        
        if(opcode == TCPOPT_EOL) // End of options (EOL)
            break;
            
        if(opcode == TCPOPT_NOP) { // NOP with no length
            opt_len--;
            continue;
        }
        
        uint8_t size = *ptr++;
        
        if(opcode != TCPOPT_SACK) {
            ptr += (size - 2);
            opt_len -= size;
            continue;
        }
        
        uint32_t sack_len = size-2;
        if(sack_len % 8 != 0 || sack_len > 24)
            error("Malformed SACK option");
        
        sack_found = 1;
        
        while(sack_len > 0) {
            uint32_t sle = ntohl(*((uint32_t*)ptr));
            curr_sack_blocks.block[sack_block_i].sle = sle;
            
            ptr += sizeof(uint32_t);
            
            uint32_t sre = ntohl(*((uint32_t*)ptr));
            curr_sack_blocks.block[sack_block_i].sre = sre;
            sack_block_i++;
            
            ptr += sizeof(uint32_t);
            
            sack_len -= 2*sizeof(uint32_t);
            
            interval += sre-sle;
        }
        
        opt_len -= size;
    }
    
    if(interval == 0) {
        if(sack_found == 0)
            error("Missing SACK options");
        else
            error("Unexpected overlap of SACK intervals");
    }
    
    // just order them decreasing
    qsort(curr_sack_blocks.block, 3, sizeof(sack_block), compare_desc);
    
    probe* first_avail_probe = NULL;
    
    for(int i = 0; i < num_probes; i++) {
        if(((probes[i].seq >= curr_sack_blocks.block[0].sle && probes[i].seq < curr_sack_blocks.block[0].sre) || (probes[i].seq >= curr_sack_blocks.block[1].sle && probes[i].seq < curr_sack_blocks.block[1].sre) || (probes[i].seq >= curr_sack_blocks.block[2].sle && probes[i].seq < curr_sack_blocks.block[2].sre)) && (probes[i].seq > 0)) {
            probes[i].reply_from_destination = 1;
                
            if(probes[i].done == 0 && probes[i].final == 0) {
                first_avail_probe = &probes[i];
                break;
            }
        }
    }
    
    return first_avail_probe;
}

static probe* tcpinsession_check_reply(int sk, int err, sockaddr_any* from, char* buf, size_t len) 
{
    if(len < 8)
        return NULL;        /*  too short   */

    if(!equal_addr(&dest_addr, from))
        return NULL;
        
    struct tcphdr* tcp = (struct tcphdr*)buf;
    
    if(err) { // got icmp, thus buf contains the TCP header of the offending probe
#ifdef __APPLE__
        uint16_t dport = tcp->th_dport; 
        if(dport != dest_port)
            return NULL;

        uint32_t seq_num_returned = ntohl(tcp->th_seq);
#else
        uint16_t dport = tcp->dest; 
        if(dport != dest_port)
            return NULL;

        uint32_t seq_num_returned = ntohl(tcp->seq);
#endif
        return probe_by_seq(seq_num_returned);
    }
    
#ifdef __APPLE__
    uint16_t dport = tcp->th_sport;
    if(dport != dest_port)
        return NULL;
        
    uint16_t sport = tcp->th_dport;
#else
    uint16_t dport = tcp->source;
    if(dport != dest_port)
        return NULL;
        
    uint16_t sport = tcp->dest;
#endif

    if(src.sa.sa_family == AF_INET6) {
        if(sport != src.sin6.sin6_port) 
            return NULL;
    } else if(src.sa.sa_family == AF_INET) {
        if(sport != src.sin.sin_port) 
            return NULL;
    } else {
        return NULL;
    }
    
    probe* pb = find_probe_from_sack(tcp);
    
    if(!pb)
        return NULL;
        
    pb->final = 1;
    
    if(info)
        pb->ext = names_by_flags((((uint8_t*)(tcp))[13]));
    
    // Note that here we cannot receive the MSS, because it is included only in the initial SYN+ACK
   
    return pb;
}

static void tcpinsession_recv_probe(int sk, int revents) 
{
    if(!(revents & (POLLIN | POLLERR)))
        return;

    recv_reply(sk, !!(revents & POLLERR), tcpinsession_check_reply);
}

static void tcpinsession_expire_probe(probe* pb) 
{
    probe_done(pb);
}

void tcpinsession_close()
{
    print_allowed = 1;
    int start = (first_hop - 1) * probes_per_hop;
    int end = (last_probe == -1) ? num_probes : last_probe;
    for(int i = start; i < end; i++)
        print_probe(&probes[i]);
    close(sk);
    
    printf("\n");
}

static tr_module tcpinsession_ops = {
    .name = "tcpinsession",
    .init = tcpinsession_init,
    .send_probe = tcpinsession_send_probe,
    .recv_probe = tcpinsession_recv_probe,
    .expire_probe = tcpinsession_expire_probe,
    .options = tcp_options,
    .close = tcpinsession_close
};

TR_MODULE(tcpinsession_ops);
