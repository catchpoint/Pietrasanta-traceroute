/*
    Copyright (c)  2023             Catchpoint Systems, Inc.    
    Copyright (c)  2023             Alessandro Improta, Luca Sani
                    <aimprota@catchpoint.com>    
                    <lsani@catchpoint.com>
    
    This software was updated by Catchpoint Systems, Inc. to incorporate
    InSession algorithm functionality.
    
    Copyright(c)  2006, 2007        Dmitry Butskoy
                    <buc@citadel.stu.neva.ru>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/
#ifdef __APPLE__
// TcpInsession is not supported on macOS
#else
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <netdb.h>
       
#include "common-tcp.h"
#include "flowlabel.h"

#define MAX_CONNECT_TIMEOUT_SEC 5

#ifndef IP_MTU
#define IP_MTU 14
#endif

static sockaddr_any dest_addr = {{ 0, }, };
static unsigned int dest_port = 0;

static int raw_icmp_sk = -1;
static int last_ttl = 0;

static int af = 0;
static int header_len = 0;

static unsigned pseudo_IP_header_size = 0;
static uint8_t* counter_pointer = NULL;
static uint8_t* buf;        /*  enough, enough...  */
static size_t* length_p;
static uint32_t ts_value_offset = 0;
static struct tcphdr* th = NULL;
static uint16_t* lenp = NULL;
static int info = 0;
static int print_received_mss = 0;

int print_five_tuple = 0;
extern int use_additional_raw_icmp_socket;
extern int tr_via_additional_raw_icmp_socket;

static unsigned int mss = 0;
// Note that MAX_PROBES means "max probes per hop"
static uint8_t tmp_buf[MAX_PROBES][1024] = {};        /*  enough, enough...  */
static int mtu[MAX_PROBES] = {};
static unsigned mss_received[MAX_PROBES] = {};
static int sk[MAX_PROBES] = {};
static int raw_sk[MAX_PROBES] = {};
uint32_t initial_seq_num[MAX_PROBES] = {};
uint32_t seq_num[MAX_PROBES] = {};
uint32_t ack_num[MAX_PROBES] = {};
uint32_t ts_value[MAX_PROBES] = {};
uint32_t ts_echo_reply[MAX_PROBES] = {};
static sockaddr_any src[MAX_PROBES] = {};
int SACK_permitted = 0;
int handshake_printed = 0;
int sack = 0;
int ecmp = 0;
int n_flows = 0;

static CLIF_option tcp_options[] = {
    { 0, "info", 0, "Print tcp flags of final tcp replies when target host is reached. Useful to determine whether an application listens the port etc.", CLIF_set_flag, &info, 0, 0 },
    { 0, "mss", 0, "Show maxseg tcp option proposed by the destination during handshake,", CLIF_set_flag, &mss, 0, 0 },
    { 0, "sack", 0, "Show sack,", CLIF_set_flag, &sack, 0, 0 },
    { 0, "ecmp", 0, "ECMP,", CLIF_set_flag, &ecmp, 0, 0 },
    { 0, "print-received-mss", 0, "Print the received MSS value from the SYN+ACK packet", CLIF_set_flag, &print_received_mss, 0, 0 },
    { 0, "print-five-tuple", 0, "Print the source IP address and port and the destination IP address and port in each hop", CLIF_set_flag, &print_five_tuple, 0, 0 },
    CLIF_END_OPTION
};

static int tcpinsession_init(const sockaddr_any* dest, unsigned int port_seq, size_t* packet_len_p) 
{
    n_flows = (ecmp) ? probes_per_hop : 1;

    for(int i = 0; i < n_flows; i++)
        initial_seq_num[i] = rand();
    
    af = dest->sa.sa_family;

    if(!port_seq)  
        port_seq = DEF_TCP_PORT;
    dest_port = htons(port_seq);
    
    dest_addr = *dest;
    
    // Even with ECMP we are keeping the destination port fixed
    if(af == AF_INET)
        dest_addr.sin.sin_port = dest_port;
    else
        dest_addr.sin6.sin6_port = dest_port;
    
    // raw_sk is where we receive and parse the SYN+ACK from the destination
    for(int i = 0; i < n_flows; i++) { // we need one per probe we send in case of ECMP
        raw_sk[i] = socket(af, SOCK_RAW, IPPROTO_TCP);
        if(raw_sk[i] < 0)
            error_or_perm("socket");
        tune_socket(raw_sk[i]);
    }
    
    socklen_t src_len = sizeof(src[0]);
    socklen_t lenmtu = sizeof(mtu);
    double connect_starttime[MAX_PROBES] = {};
    
    for(int i = 0; i < n_flows; i++) {
        connect_starttime[i] = get_time();
        if(connect(raw_sk[i], &dest_addr.sa, (af == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0)
            error("connect");

        sk[i] = socket(af, SOCK_STREAM, 0);
        tune_socket(sk[i]);

        if(connect(sk[i], &dest_addr.sa, (af == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0)
            if(errno != EINPROGRESS) // note that we don't need to wait the connect to be successful since the loop below will wait for the syn+ack.
                error("connect");
        
        if(getsockname(sk[i], &src[i].sa, &src_len) < 0)
            error("getsockname");

        if(getsockopt(raw_sk[i], af == AF_INET ? SOL_IP : SOL_IPV6, af == AF_INET ? IP_MTU : IPV6_MTU, &mtu[i], &lenmtu) < 0 || mtu[i] < 576)
            mtu[i] = 576;
    }

    int received = 0;
    sockaddr_any response_src_addr;
    memset(&response_src_addr, 0, sizeof(response_src_addr));
    socklen_t src_addr_len = sizeof(response_src_addr);
    
    struct tcphdr* response_tcp_hdr[MAX_PROBES] = {};

    uint8_t ack_buf[MAX_PROBES][1024];

    printf("\nhand");
    handshake_printed = 1;

    for(int i = 0; i < n_flows; i++) {
        double recv_time = 0;
        int found = 0;
        do {
            if((received = recvfrom(raw_sk[i], ack_buf[i], sizeof(ack_buf[i]), 0, &response_src_addr.sa, &src_addr_len)) >= 0) {
                recv_time = get_time();
                response_tcp_hdr[i] = NULL;
                uint8_t* opt_ptr = NULL;
                uint16_t option_len = 0;

                if(af == AF_INET) {
                    struct iphdr* response_iphdr = (struct iphdr*)ack_buf[i];
                    response_tcp_hdr[i] = (struct tcphdr*) (ack_buf[i] + (response_iphdr->ihl << 2));
                    if(response_tcp_hdr[i]->dest == src[i].sin.sin_port) {
                        uint16_t response_flags = get_th_flags(response_tcp_hdr[i]);
                        if((response_flags & SYN) && (response_flags & ACK)) { // paranoid
                            response_src_addr.sin.sin_port = response_tcp_hdr[i]->source;
                            if(equal_sockaddr(&dest_addr, &response_src_addr)) {
                                found = 1;
                                opt_ptr = ((uint8_t*)response_tcp_hdr[i])+sizeof(*response_tcp_hdr[i]);
                                option_len = htons(response_iphdr->tot_len)-sizeof(*response_iphdr)-sizeof(*response_tcp_hdr[i]);
                            }
                        }
                    }
                } else if(af == AF_INET6) {
                    response_tcp_hdr[i] = (struct tcphdr*)ack_buf[i];
                    if(response_tcp_hdr[i]->dest == src[i].sin6.sin6_port) {
                        uint16_t response_flags = get_th_flags(response_tcp_hdr[i]);
                        if((response_flags & SYN) && (response_flags & ACK)) { // paranoid
                            response_src_addr.sin6.sin6_port = response_tcp_hdr[i]->source;
                            if(equal_sockaddr(&dest_addr, &response_src_addr)) {
                                found = 1;
                                opt_ptr = ((uint8_t*)response_tcp_hdr[i])+sizeof(*response_tcp_hdr[i]);
                                option_len = received-sizeof(*response_tcp_hdr[i]);
                            }
                        }
                    }
                }
                        
                if(found) {
                    initial_seq_num[i] = ntohl(response_tcp_hdr[i]->ack_seq)+1;
                    seq_num[i] = initial_seq_num[i];
                    ack_num[i] = ntohl(response_tcp_hdr[i]->seq)+1;
                    SACK_permitted = 0;
                    for(uint16_t o = 0; o < option_len; o++) {
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
                            mss_received[i] = ntohs(*(uint16_t*)opt_ptr);
                            opt_ptr += opt_len;
                            opt_ptr -= 2; // opt kind and len are included in opt_len
                        } else if(opt_kind != TCPOPT_TIMESTAMP) {
                            opt_ptr += opt_len;
                            opt_ptr -= 2; // opt kind and len are included in opt_len
                        } else {
                            uint32_t timestamp_value = ntohl(*((uint32_t*)opt_ptr));
                            opt_ptr += sizeof(uint32_t);
                            uint32_t timestamp_echo_reply = ntohl(*((uint32_t*)opt_ptr));

                            ts_value[i] = timestamp_echo_reply+30;
                            ts_echo_reply[i] = timestamp_value;

                            options |= OPT_TSTAMP;
                            
                            break;
                        }
                    }
                }
            } else {
                if(get_time() - connect_starttime[i] > MAX_CONNECT_TIMEOUT_SEC)
                    break;
                
                usleep(10000);
            }
        } while(!found);
        
        if(!found) {
            close(sk[i]);
            close(raw_sk[i]);

            if(ecmp)
                ex_error("Cannot complete initial TCP handshake for flow %d", i);
            else
                ex_error("Cannot complete initial TCP handshake", i);
        }

        // Print some info about this handshake
        double diff = (recv_time - connect_starttime[i]) * 1000;

        char* res = NULL;
        
        if(info && response_tcp_hdr[i])
            res = names_by_flags(get_th_flags(response_tcp_hdr[i]));
    
        if((res && strlen(res) > 0) || (sack > 0 && SACK_permitted > 0) || ((mss > 0 || print_received_mss) && mss_received[i] > 0) || print_five_tuple > 0) {
            printf(" <");
        
            int print_comma = 0;
            if(res && strlen(res) > 0) {
                printf("%s", res);
                print_comma = 1;
            }
            
            if((mss > 0 || print_received_mss) && mss_received[i] > 0) {
                if(print_comma == 1)
                    printf(",");
                printf("MSS:%d", mss_received[i]);
                print_comma = 1;
            }

            if(sack > 0 && SACK_permitted > 0) {
                if(print_comma == 1)
                    printf(",");
                printf("SACK");
            }

            if(print_five_tuple) {
                if(print_comma == 1)
                    printf(",");

                char src_str[INET6_ADDRSTRLEN] = {};
                snprintf(src_str, sizeof(src_str), "%s", addr2str(&src[i]));
                printf("%s%s%s:%u->%s%s%s:%u", (dest_addr.sa.sa_family == AF_INET6) ? "[" : "", src_str, (dest_addr.sa.sa_family == AF_INET6) ? "]" : "", ntohs(src[i].sin.sin_port), (dest_addr.sa.sa_family == AF_INET6) ? "[" : "", addr2str(&dest_addr), (dest_addr.sa.sa_family == AF_INET6) ? "]" : "", ntohs(dest_addr.sin.sin_port));
            }

            printf(">");
        }

        printf(" %.3f ms", diff);

        fflush(stdout);
        
        if(res != NULL)
            free(res);
                    
        if(SACK_permitted == 0) {
            close(sk[i]);
            close(raw_sk[i]);
            ex_error("\nTCP SACK not permitted from destination on flow %d", i);
        }

        use_recverr(raw_sk[i]);
        add_poll(raw_sk[i], POLLIN | POLLERR);
    } // for each flow
    
    socklen_t len;
    uint8_t* ptr;

    for(int i = 0; i < n_flows; i++) {
        /*  Now create the sample packet.  */

        flags |= PSH;
        flags |= ACK;
        
        /*  For easy checksum computing:
            saddr
            daddr
            length
            protocol
            tcphdr
            tcpoptions
        */

        ptr = tmp_buf[i];

        if(af == AF_INET) {
            len = sizeof(struct in_addr);
            memcpy(ptr, &src[i].sin.sin_addr, len);
            ptr += len;
            memcpy(ptr, &dest_addr.sin.sin_addr, len);
            ptr += len;
        } else {
            len = sizeof(struct in6_addr);
            memcpy(ptr, &src[i].sin6.sin6_addr, len);
            ptr += len;
            memcpy(ptr, &dest_addr.sin6.sin6_addr, len);
            ptr += len;
        }

        lenp = (uint16_t*)ptr;
        uint16_t delta_len_p = ptr - tmp_buf[i];
        ptr += sizeof(uint16_t);
        *((uint16_t*)ptr) = htons((uint16_t)IPPROTO_TCP);
        ptr += sizeof(uint16_t);

        /*  Construct TCP header   */

        th = (struct tcphdr*)ptr;
        
        pseudo_IP_header_size = ptr - tmp_buf[i];

        th->source = 0;
        th->dest = dest_port;
        th->seq = 0;
        th->doff = 0;
        set_th_flags(th, flags);
        th->check = 0;
        th->urg_ptr = 0;

        ptr = (uint8_t*)(th + 1);

        // Send timestamp only if it was received into the initial SYN+ACK
        // Add also two bytes NOP for a total of 12 bytes to align the options space on 4 bytes.
        if(options & OPT_TSTAMP) {
            *ptr++ = TCPOPT_TIMESTAMP;    /*  8   */
            *ptr++ = TCPOLEN_TIMESTAMP;    /*  10  */
            ts_value_offset = ptr - (uint8_t*)th;
            ptr += sizeof(uint32_t); // skip ts_value
            ptr += sizeof(uint32_t); // skip ts_echo_reply
            *ptr++ = TCPOPT_NOP;    /*  1   */
            *ptr++ = TCPOPT_NOP;    /*  1   */
        }

        len = ptr - (uint8_t*)th;
        if(len & 0x03)
            ex_error("impossible");    /*  as >>2 ...  */

        th->doff = len >> 2;
        
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
        
        lenp = (uint16_t*)(buf + delta_len_p); // Allow the length in the pseudo IP header to be changed when we send probes
    }

    if(use_additional_raw_icmp_socket) {
        raw_icmp_sk = socket(dest_addr.sa.sa_family, SOCK_RAW, (af == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6);
        
        if(raw_icmp_sk < 0)
            error_or_perm("raw icmp socket");
        
        add_poll(raw_icmp_sk, POLLIN | POLLERR);
    }
        
    return 0;
}

static void tcpinsession_send_probe(probe* pb, int ttl, int probe_idx) 
{
    int flow = (ecmp) ? probe_idx % probes_per_hop : 0;
    
    th->source = src[flow].sin.sin_port;
    th->seq = htonl(seq_num[flow]);
    th->ack_seq = htonl(ack_num[flow]);
    th->window = htons(4 * mtu[flow]);

    pb->seq_num = seq_num[flow];
    
    //printf("\nSending probe_idx %d on flow %d with sport=%d and ttl=%d and seq=%u and ack_seq=%u\n", probe_idx, flow, th->source, ttl, htonl(pb->seq_num), htonl(th->ack_seq));
    
    if(counter_pointer == NULL)
        error("counter pointer uninitialized");
    
    (*counter_pointer)++;
    uint8_t* ts_ptr = ((uint8_t*)th)+ts_value_offset; // TS value
    uint8_t* te_ptr = ts_ptr + sizeof(uint32_t); // TS echo reply
    if(ts_value_offset > 0) {
        uint32_t ts_val = ts_value[flow]++;
        *((uint32_t*)ts_ptr) = htonl(ts_val);
        *((uint32_t*)te_ptr) = htonl(ts_echo_reply[flow]);
    }

    *lenp = htons(*length_p); 
    th->check = 0;
    th->check = in_csum(buf, (*length_p)+pseudo_IP_header_size);

    if(ecmp || ttl != last_ttl) {
        set_ttl(raw_sk[flow], ttl);
        last_ttl = ttl;
    }

    pb->sk = -1;
    pb->icmp_done = 0;
    pb->send_time = get_time();
    
    int res = do_send(raw_sk[flow], th, *length_p, &dest_addr);
    if(res < 0) {
        error("so bad");
        pb->send_time = 0;
    } else if(res > 0) {
        seq_num[flow] += (*length_p - header_len);
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
    
    int opt_len = (tcp->doff * 4) - sizeof(struct tcphdr);
    
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
            ex_error("Malformed SACK option");
        
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
        close(sk[0]); // TODO close all
        close(raw_sk[0]);
        ex_error("%s%s", (handshake_printed > 0) ? "\n" : "", (sack_found == 0) ? "Missing SACK options" : "Unexpected overlap of SACK intervals");
    }
    
    // just order them decreasing
    qsort(curr_sack_blocks.block, 3, sizeof(sack_block), compare_desc);
    
    probe* first_avail_probe = NULL;
    
    for(int i = 0; i < num_probes; i++) {
        if(((probes[i].seq_num >= curr_sack_blocks.block[0].sle && probes[i].seq_num < curr_sack_blocks.block[0].sre) || (probes[i].seq_num >= curr_sack_blocks.block[1].sle && probes[i].seq_num < curr_sack_blocks.block[1].sre) || (probes[i].seq_num >= curr_sack_blocks.block[2].sle && probes[i].seq_num < curr_sack_blocks.block[2].sre)) && (probes[i].seq_num > 0)) {
            probes[i].tcpinsession_destination_reply = 1;
                
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
    
    if(!err && (tcp->syn || !tcp->ack)) // Here we cannot receive probes with the SYN flag set and moreover they need to have the ACK flag set, since they are replies to our data probes
        return NULL;

    if(err) { // got icmp, thus buf contains the TCP header of the offending probe
        uint16_t dport = tcp->dest; 
        uint32_t seq_num_returned = ntohl(tcp->seq);
        if(dport != dest_port)
            return NULL;

        probe* pb = probe_by_seq_num(seq_num_returned);
        if(pb && print_five_tuple && pb->five_tuple == NULL) {
            for(int i = 0; i < n_flows; i++) {
                if(tcp->source == src[i].sin.sin_port) {
                    char src_str[INET6_ADDRSTRLEN + 16];
                    char str[128] = {};    /*  enough...  */
                    snprintf(src_str, sizeof(src_str), "%s%s%s:%u", (dest_addr.sa.sa_family == AF_INET6) ? "[" : "", addr2str(&src[i]), (dest_addr.sa.sa_family == AF_INET6) ? "]" : "", ntohs(src[i].sin.sin_port));
                    snprintf(str, sizeof(str), "%s->%s%s%s:%u", src_str, (dest_addr.sa.sa_family == AF_INET6) ? "[" : "", addr2str(&dest_addr), (dest_addr.sa.sa_family == AF_INET6) ? "]" : "", ntohs(dest_addr.sin.sin_port));
                    pb->five_tuple = strdup(str);
                    break;
                }
            }
        }

        return pb;
    }
    
    uint16_t dport = tcp->source;
    if(dport != dest_port)
        return NULL;
        
    uint16_t sport = tcp->dest;

    // Scan all srcs and if no one corresponds, return NULL

    int found = 0;
    int src_index = -1;
    for(int i = 0; i < n_flows; i++) {
        if(src[i].sa.sa_family == AF_INET6) {
            if(sport == src[i].sin6.sin6_port) {
                found = 1;
                src_index = i;
                break;
            }
        } else if(src[i].sa.sa_family == AF_INET) {
            if(sport == src[i].sin.sin_port) {
                found = 1;
                src_index = i;
                break;
            }
        } else {
            return NULL;
        }
    }
    
    if(!found)
        return NULL;

    probe* pb = find_probe_from_sack(tcp);
    
    if(!pb)
        return NULL;

    pb->final = 1;
    
    if(info)
        pb->ext = names_by_flags(get_th_flags(tcp));
    
    if(print_five_tuple && pb->five_tuple == NULL) {
        char str[128] = {};    /*  enough...  */
        char src_str[INET6_ADDRSTRLEN + 16] = {};
        snprintf(src_str, sizeof(src_str), "%s%s%s:%u", (dest_addr.sa.sa_family == AF_INET6) ? "[" : "", addr2str(&src[src_index]), (dest_addr.sa.sa_family == AF_INET6) ? "]" : "", ntohs(src[src_index].sin.sin_port));
        snprintf(str + strlen(str), sizeof(str) - strlen(str), "%s->%s%s%s:%u", src_str, (dest_addr.sa.sa_family == AF_INET6) ? "[" : "", addr2str(&dest_addr), (dest_addr.sa.sa_family == AF_INET6) ? "]" : "", ntohs(dest_addr.sin.sin_port));

        pb->five_tuple = strdup(str);
    }

    // Note that here we cannot receive the MSS, because it is included only in the initial SYN+ACK
    
    return pb;
}

static void tcpinsession_recv_probe(int sk, int revents) 
{
    if(!(revents & (POLLIN | POLLERR)))
        return;

    recv_reply(sk, !!(revents & POLLERR), tcpinsession_check_reply);
}

static int tcpinsession_is_raw_icmp_sk(int sk)
{
    if(sk == raw_icmp_sk)
        return 1;
    return 0;
}

/*
    Here we need to slightly change the logic wrt the same function in other modules.
    Since in this module all the probes share the same five tuple, we recover the probe
    by looking at the sequence number of the offending probe and finding the probe with 
    the same value (as in the check_reply). Furthermore, to be extra-sure that this 
    is a probe for us (since this is a RAW ICMP socket), once the probe is found, we 
    check if the destination and source address of the offending probe matches the ones 
    that we are using to perform the traceroute
*/
static probe* tcpinsession_handle_raw_icmp_packet(char* bufp, uint16_t* overhead, struct msghdr* response_get, struct msghdr* ret)
{
    sockaddr_any offending_probe_dest;
    sockaddr_any offending_probe_src;
    struct tcphdr* offending_probe = NULL;
    int proto = 0;
    int returned_tos = 0;
    extract_ip_info(dest_addr.sa.sa_family, bufp, &proto, &offending_probe_src, &offending_probe_dest, (void **)&offending_probe, &returned_tos); 
    
    if(proto != IPPROTO_TCP)
        return NULL;
    
    offending_probe = (struct tcphdr*)offending_probe;
    
    uint32_t probe_seq_num = ntohl(offending_probe->seq);
    offending_probe_dest.sin.sin_port = offending_probe->dest;
    offending_probe_src.sin.sin_port = offending_probe->source;
    probe* pb = probe_by_seq_num(probe_seq_num);
    
    if(!pb)
        return NULL;
    
    for(int i = 0; i < n_flows; i++) {
        if((loose_match || equal_sockaddr(&src[i], &offending_probe_src)) && equal_sockaddr(&dest_addr, &offending_probe_dest)) {
            if(print_five_tuple && pb->five_tuple == NULL) {
                char str[128] = {};    /*  enough...  */
                char src_str[INET6_ADDRSTRLEN + 16] = {};
                snprintf(src_str, sizeof(src_str), "%s%s%s:%u", (dest_addr.sa.sa_family == AF_INET6) ? "[" : "", addr2str(&src[i]), (dest_addr.sa.sa_family == AF_INET6) ? "]" : "", ntohs(src[i].sin.sin_port));
                snprintf(str + strlen(str), sizeof(str) - strlen(str), "%s->%s%s%s:%u", src_str, (dest_addr.sa.sa_family == AF_INET6) ? "[" : "", addr2str(&dest_addr), (dest_addr.sa.sa_family == AF_INET6) ? "]" : "", ntohs(dest_addr.sin.sin_port));

                pb->five_tuple = strdup(str);
            }

            pb->returned_tos = returned_tos;
            probe_done(pb, &pb->icmp_done);
            if(loose_match || tr_via_additional_raw_icmp_socket)
                *overhead = prepare_ancillary_data(dest_addr.sa.sa_family, bufp, sizeof(struct tcphdr), ret, response_get->msg_name);
        }
    }
    
    return pb;
}

static void tcpinsession_close()
{
    tcpinsession_print_allowed = 1;
    int start = (first_hop - 1) * probes_per_hop;
    for(int i = start; i < last_probe; i++)
        print_probe(&probes[i]);
    
    for(int i = 0; i < n_flows; i++)
        close(sk[i]);

    if(use_additional_raw_icmp_socket)
        close(raw_icmp_sk);
}

static tr_module tcpinsession_ops = {
    .name = "tcpinsession",
    .init = tcpinsession_init,
    .send_probe = tcpinsession_send_probe,
    .recv_probe = tcpinsession_recv_probe,
    .options = tcp_options,
    .is_raw_icmp_sk = tcpinsession_is_raw_icmp_sk,
    .handle_raw_icmp_packet = tcpinsession_handle_raw_icmp_packet,
    .close = tcpinsession_close
};

TR_MODULE(tcpinsession_ops);

#endif
