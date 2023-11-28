/*
    Copyright (c)  2006, 2007        Dmitry Butskoy
                    <buc@citadel.stu.neva.ru>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "traceroute.h"


static sockaddr_any dest_addr = {{ 0, }, };
static uint16_t seq = 1;
static uint16_t ident = 0;

static char *data;
static size_t *length_p;

static int icmp_sk = -1;
static int raw_icmp_sk = -1; // cannot use icmp_sk because it is used with recverr (thus no full ICMP packet is received but only the payload of the offending ICMP packet)
static int last_ttl = 0;
static int raw = 0;
static int dgram = 0;

static CLIF_option icmp_options[] = {
    { 0, "raw", 0, "Use raw sockets way only. Default is try this way first (probably not allowed for unprivileged users), then try dgram", CLIF_set_flag, &raw, 0, CLIF_EXCL },
    { 0, "dgram", 0, "Use dgram sockets way only. May be not implemented by old kernels or restricted by sysadmins", CLIF_set_flag, &dgram, 0, CLIF_EXCL },
    CLIF_END_OPTION
};

extern int use_additional_raw_icmp_socket;

static int icmp_init(const sockaddr_any* dest, unsigned int port_seq, size_t *packet_len_p)
{
    int af = dest->sa.sa_family;
    int protocol;

    dest_addr = *dest;
    dest_addr.sin.sin_port = 0;

    if(port_seq)
        seq = port_seq;

    length_p = packet_len_p;
    if(*length_p < sizeof(struct icmphdr))
        *length_p = sizeof(struct icmphdr);

    data = malloc(*length_p);
    if(!data)
        error("malloc");
        
    for(int i = sizeof(struct icmphdr); i < *length_p; i++)
        data[i] = 0x40 + (i & 0x3f);
        
    protocol = (af == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6;

    if(!raw) {
        icmp_sk = socket(af, SOCK_DGRAM, protocol);
        if(icmp_sk < 0 && dgram)
            error("socket");
    }

    if(!dgram) {
        int raw_sk = socket(af, SOCK_RAW, protocol);
        if(raw_sk < 0) {
            if(raw || icmp_sk < 0)
                error_or_perm("socket");
            dgram = 1;
        } else {
            /*  prefer the traditional "raw" way when possible   */
            if(icmp_sk > 0)
                close(icmp_sk);
            icmp_sk = raw_sk;
        }
    }

    tune_socket(icmp_sk);

    /*  Don't want to catch packets from another hosts   */
    if(raw_can_connect() && connect(icmp_sk, &dest_addr.sa, sizeof(dest_addr)) < 0)
        error("connect");

    use_recverr(icmp_sk);

    if(dgram) {
        sockaddr_any addr;
        socklen_t len = sizeof(addr);

        if(getsockname(icmp_sk, &addr.sa, &len) < 0)
            error("getsockname");
        ident = ntohs(addr.sin.sin_port);    /*  both IPv4 and IPv6   */

    } else {
        ident = getpid() & 0xffff;
    }

    add_poll(icmp_sk, POLLIN | POLLERR);
 
    if(use_additional_raw_icmp_socket) {
        raw_icmp_sk = socket(dest_addr.sa.sa_family, SOCK_RAW, (dest_addr.sa.sa_family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6);
        
        if(raw_icmp_sk < 0)
            error_or_perm("raw icmp socket");
        
        add_poll(raw_icmp_sk, POLLIN | POLLERR);
    }
    
    return 0;
}


static void icmp_send_probe(probe *pb, int ttl)
{
    int af = dest_addr.sa.sa_family;

    if(ttl != last_ttl) {
        set_ttl(icmp_sk, ttl);
        last_ttl = ttl;
    }

    if(af == AF_INET) {
        struct icmp *icmp = (struct icmp*) data;
        icmp->icmp_type = ICMP_ECHO;
        icmp->icmp_code = 0;
        icmp->icmp_cksum = 0;
        icmp->icmp_id = htons(ident);
        icmp->icmp_seq = htons(seq);
        icmp->icmp_cksum = in_csum(data, *length_p);
    } else if(af == AF_INET6) {
        struct icmp6_hdr *icmp6 =(struct icmp6_hdr *) data;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_cksum = 0;
        icmp6->icmp6_id = htons(ident);
        icmp6->icmp6_seq = htons(seq);
        /*  icmp6->icmp6_cksum always computed by kernel internally   */
    }

    pb->send_time = get_time();

    if(do_send(icmp_sk, data, *length_p, &dest_addr) < 0) {
        pb->send_time = 0;
        return;
    }

    pb->seq = seq;
    seq++;

    return;
}


static probe *icmp_check_reply(int sk, int err, sockaddr_any *from, char *buf, size_t len)
{
    int af = dest_addr.sa.sa_family;
    int type;
    uint16_t recv_id, recv_seq;
    probe *pb;

    if(len < sizeof(struct icmphdr))
        return NULL;

    if(af == AF_INET) {
        struct icmp *icmp = (struct icmp *) buf;
        type = icmp->icmp_type;
        recv_id = ntohs(icmp->icmp_id);
        recv_seq = ntohs(icmp->icmp_seq);

    } else {        /*  AF_INET6   */
        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) buf;
        type = icmp6->icmp6_type;
        recv_id = ntohs(icmp6->icmp6_id);
        recv_seq = ntohs(icmp6->icmp6_seq);
    }


    if(recv_id != ident)
        return NULL;

    pb = probe_by_seq(recv_seq);
    if(!pb)
        return NULL;


    if(!err) {
        if(!(af == AF_INET && type == ICMP_ECHOREPLY) && !(af == AF_INET6 && type == ICMP6_ECHO_REPLY)) 
            return NULL;

        pb->final = 1;
    }

    return pb;
}


static void icmp_recv_probe(int sk, int revents)
{
    if(!(revents & (POLLIN | POLLERR)))
        return;

    recv_reply(sk, !!(revents & POLLERR), icmp_check_reply);
}

static int icmp_is_raw_icmp_sk(int sk)
{
    if(sk == raw_icmp_sk)
        return 1;

    return 0;
}

static probe* icmp_handle_raw_icmp_packet(char* bufp, uint16_t* overhead, struct msghdr* response_get, struct msghdr* ret)
{
    probe* pb = NULL;
    
    if(dest_addr.sa.sa_family == AF_INET) {
        struct iphdr* outer_ip = (struct iphdr*)bufp;
        struct icmp* icmp_packet = (struct icmp*) (bufp + (outer_ip->ihl << 2));
        
        int type = icmp_packet->icmp_type;
        uint16_t recv_seq = 0;
        
        if(type == ICMP_ECHOREPLY) {
            uint16_t recv_id = ntohs(icmp_packet->icmp_id);
            
            if(recv_id != ident)
                return NULL;
            
            recv_seq = ntohs(icmp_packet->icmp_seq);
            pb = probe_by_seq(recv_seq);
            
            if(!pb)
                return NULL;
        } else {
            struct iphdr* inner_ip = (struct iphdr*) (bufp + (outer_ip->ihl << 2) + sizeof(struct icmphdr));
            if(inner_ip->protocol != IPPROTO_ICMP)
                return NULL;
            struct icmp* offending_probe = (struct icmp*) (bufp + (outer_ip->ihl << 2) + sizeof(struct icmphdr) + (inner_ip->ihl << 2));
            
            uint16_t recv_id = ntohs(offending_probe->icmp_id);
            
            if(recv_id != ident)
                return NULL;
            
            recv_seq = ntohs(offending_probe->icmp_seq);
            pb = probe_by_seq(recv_seq);
        
            if(!pb)
                return NULL;
            
            pb->returned_tos = inner_ip->tos;
        }
    } else if(dest_addr.sa.sa_family == AF_INET6) {
        struct icmp6_hdr* icmp_packet = (struct icmp6_hdr*)bufp;
        
        int type = icmp_packet->icmp6_type;
        uint16_t recv_seq = 0;
        
        if(type == ICMP6_ECHO_REPLY) {
            uint16_t recv_id = ntohs(icmp_packet->icmp6_id);
            
            if(recv_id != ident)
                return NULL;
            
            recv_seq = ntohs(icmp_packet->icmp6_seq);
            pb = probe_by_seq(recv_seq);
        
            if(!pb)
                return NULL;
        } else {
            struct ip6_hdr* inner_ip = (struct ip6_hdr*) (bufp + sizeof(struct icmp6_hdr));            
            struct icmp6_hdr* offending_probe = (struct icmp6_hdr*) (bufp + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr));
            
            if(inner_ip->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_ICMPV6)
                return NULL;
            
            uint16_t recv_id = ntohs(offending_probe->icmp6_id);
            
            if(recv_id != ident)
                return NULL;
            
            recv_seq = ntohs(offending_probe->icmp6_seq);
            pb = probe_by_seq(recv_seq);
        
            if(!pb)
                return NULL;
            uint32_t tmp = ntohl(inner_ip->ip6_ctlun.ip6_un1.ip6_un1_flow);
            tmp &= 0x0fffffff;
            tmp >>= 20; 
            pb->returned_tos = (uint8_t)tmp;
        }
    }
    
    probe_done(pb, &pb->icmp_done);
    if(loose_match)
        *overhead = prepare_ancillary_data(dest_addr.sa.sa_family, bufp, 0, ret, response_get->msg_name);
    
    return pb;
}

static void icmp_close()
{
    close(icmp_sk);
    if(use_additional_raw_icmp_socket)
        close(raw_icmp_sk);
}

static tr_module icmp_ops = {
    .name = "icmp",
    .init = icmp_init,
    .send_probe = icmp_send_probe,
    .recv_probe = icmp_recv_probe,
    .options = icmp_options,
    .is_raw_icmp_sk = icmp_is_raw_icmp_sk,
    .handle_raw_icmp_packet = icmp_handle_raw_icmp_packet,
    .close = icmp_close
};

TR_MODULE(icmp_ops);
