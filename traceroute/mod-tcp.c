/*
    Copyright(c)  2023   Alessandro Improta, Luca Sani, Catchpoint Systems, Inc.
    
    Copyright(c)  2006, 2007        Dmitry Butskoy
                    <buc@citadel.stu.neva.ru>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include "traceroute.h"

#ifdef __APPLE__
#include "mac/icmp.h"
#include "mac/ip.h"
#include "mac/types.h"
#include <string.h>
#undef TH_FLAGS
#endif 

#ifndef IP_MTU
#define IP_MTU    14
#endif

static sockaddr_any dest_addr = {{ 0, }, };
static unsigned int dest_port = 0;

static int raw_icmp_sk = -1;
static int raw_sk = -1;
static int last_ttl = 0;

static unsigned pseudo_IP_header_size = 0;
static uint8_t* buf;
static uint8_t tmp_buf[1024];        /*  enough, enough...  */
static size_t* length_p;
static sockaddr_any src;
static struct tcphdr *th = NULL;

#define TH_FLAGS(TH)    (((uint8_t *) (TH))[13])
#define TH_FIN    0x01
#define TH_SYN    0x02
#define TH_RST    0x04
#define TH_PSH    0x08
#define TH_ACK    0x10
#define TH_URG    0x20
#define TH_ECE    0x40
#define TH_CWR    0x80


static int flags = 0;        /*  & 0xff == tcp_flags ...  */
static int sysctl = 0;
static int reuse = 0;
static unsigned int mss = 0;
static int info = 0;

#define FL_FLAGS    0x0100
#define FL_ECN        0x0200
#define FL_SACK        0x0400
#define FL_TSTAMP    0x0800
#define FL_WSCALE    0x1000


static struct {
    const char *name;
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

extern int use_additional_raw_icmp_socket;

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

static int tcp_init(const sockaddr_any* dest, unsigned int port_seq, size_t* packet_len_p)
{
    int af = dest->sa.sa_family;
    int mtu;
    socklen_t len;
    uint8_t* ptr;
    uint16_t* lenp;

    dest_addr = *dest;
    dest_addr.sin.sin_port = 0;    /*  raw sockets can be confused   */

    if(!port_seq)
        port_seq = DEF_TCP_PORT;
    dest_port = htons (port_seq);

    /*  Create raw socket for tcp   */

    raw_sk = socket(af, SOCK_RAW, IPPROTO_TCP);
    if(raw_sk < 0)
        error_or_perm ("socket");

	#ifndef __APPLE__
		tune_socket(raw_sk);        /*  including bind, if any   */
		if(connect(raw_sk, &dest_addr.sa, sizeof(struct sockaddr)) < 0)
			error ("connect");
	#endif

    
	#ifndef __APPLE__
    len = sizeof(struct sockaddr);
    if(getsockname(raw_sk, &src.sa, &len) < 0)
        error ("getsockname");
	#else
	if (findsaddr(&dest_addr.sa, &src.sa) != NULL)
		error("findsaddr");
	
	#endif

    len = sizeof(mtu);
    if(getsockopt(raw_sk, af == AF_INET ? SOL_IP : SOL_IPV6, af == AF_INET ? IP_MTU : IPV6_MTU, &mtu, &len) < 0 || mtu < 576)
        mtu = 576;

    /*  mss = mtu - headers   */
    mtu -= af == AF_INET ? sizeof(struct iphdr) : sizeof(struct ip6_hdr);
    mtu -= sizeof(struct tcphdr);

    if(!raw_can_connect()) {    /*  work-around for buggy kernels  */
        close (raw_sk);
        raw_sk = socket (af, SOCK_RAW, IPPROTO_TCP);
        if(raw_sk < 0)  error ("socket");
        tune_socket (raw_sk);
        /*  but do not connect it...  */
    }


    use_recverr (raw_sk);

    add_poll (raw_sk, POLLIN | POLLERR);

    /*  Now create the sample packet.  */

    if(!flags)
        sysctl = 1;

    if(sysctl) {
        if(check_sysctl ("ecn"))
            flags |= FL_ECN;
        
        // Forcing TCP SACK, timestamps and Window scale in TCP options. This fix forces the code to generate TCP SYN packets without payload, which eventually would cause the probes to be dropped by regular firewalls. 
        // TCP SYN packets with payload are generated due to an initial hard-coded value of 40B of the probe size which was present in the original code and is now used in the new path MTU discovery process. 
        // Please remove this comment once the bug has been fixed.
        
        flags |= FL_SACK;
        flags |= FL_TSTAMP;
        flags |= FL_WSCALE;
    }

    if(!(flags & (FL_FLAGS | 0xff))) {    /*  no any tcp flag set   */
        flags |= TH_SYN;
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
        memcpy (ptr, &src.sin.sin_addr, len);
        ptr += len;
        memcpy (ptr, &dest_addr.sin.sin_addr, len);
        ptr += len;
    } else {
        len = sizeof(src.sin6.sin6_addr);
        memcpy (ptr, &src.sin6.sin6_addr, len);
        ptr += len;
        memcpy (ptr, &dest_addr.sin6.sin6_addr, len);
        ptr += len;
    }

    lenp = (uint16_t *) ptr;
    ptr += sizeof(uint16_t);
    *((uint16_t *) ptr) = htons ((uint16_t) IPPROTO_TCP);
    ptr += sizeof(uint16_t);

    /*  Construct TCP header   */

    th = (struct tcphdr *) ptr;

    pseudo_IP_header_size = ptr - tmp_buf;
    
#ifdef __APPLE__
    th->th_sport = 0;        /*  temporary   */
    th->th_dport = dest_port;
    th->th_seq = 0;        /*  temporary   */
    th->th_ack = 0;
    th->th_off = 0;        /*  later...  */
    TH_FLAGS(th) = flags & 0xff;
    th->th_win = htons(4 * mtu);
    th->th_sum = 0;
    th->th_urp = 0;
#else
    th->source = 0;
    th->dest = dest_port;
    th->seq = 0;
    th->ack_seq = 0;
    th->doff = 0;
    TH_FLAGS(th) = flags & 0xff;
    th->window = htons(4 * mtu);
    th->check = 0;
    th->urg_ptr = 0;
#endif


    /*  Build TCP options   */

    ptr = (uint8_t*)(th + 1);

    if(flags & TH_SYN) {
        *ptr++ = TCPOPT_MAXSEG;    /*  2   */
        *ptr++ = TCPOLEN_MAXSEG;    /*  4   */
        *((uint16_t*) ptr) = htons (mss ? mss : mtu);
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

        *((uint32_t*) ptr) = random_seq();    /*  really!  */
        ptr += sizeof(uint32_t);
        *((uint32_t*) ptr) = (flags & TH_ACK) ? random_seq () : 0;
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


    len = ptr - (uint8_t*) th;
    if(len & 0x03)
        error("impossible");    /*  as >>2 ...  */

    *lenp = htons (len);
    #ifdef __APPLE__
		th->th_off = len >> 2;
	#else
		th->doff = len >> 2;
	#endif

    length_p = packet_len_p;
    if(*length_p && !(buf = malloc(*length_p+pseudo_IP_header_size)))
        error("malloc");

    memcpy(buf, tmp_buf, pseudo_IP_header_size+len);
    th = (struct tcphdr*)(buf + pseudo_IP_header_size);

    for(int i = pseudo_IP_header_size+len; i < pseudo_IP_header_size+*length_p; i++)
        buf[i] = 0x40 + (i & 0x3f); // Same as in UDP
    
    if(use_additional_raw_icmp_socket) {
        raw_icmp_sk = socket(dest_addr.sa.sa_family, SOCK_RAW, (dest_addr.sa.sa_family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6);
        
        if(raw_icmp_sk < 0)
            error("raw icmp socket");
        
        add_poll(raw_icmp_sk, POLLIN | POLLERR);
    }
    
    return 0;
}

static void tcp_send_probe(probe* pb, int ttl)
{
    int sk;
    int af = dest_addr.sa.sa_family;
    sockaddr_any addr;
    socklen_t len = sizeof(addr);

    /*  To make sure we have chosen a free unused "source port",
       just create, (auto)bind and hold a socket while the port is needed.
    */

#ifndef __APPLE__
    sk = socket(af, SOCK_STREAM, 0);
    if(sk < 0)
        error ("socket");

    if(reuse && setsockopt (sk, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
        error ("setsockopt SO_REUSEADDR");

    bind_socket(sk);

	
		if(getsockname (sk, &addr.sa, &len) < 0)
			error ("getsockname");
	#endif

    /*  When we reach the target host, it can send us either RST or SYN+ACK.
      For RST all is OK (we and kernel just answer nothing), but
      for SYN+ACK we should reply with our RST.
        It is well-known "half-open technique", used by port scanners etc.
      This way we do not touch remote applications at all, unlike
      the ordinary connect(2) call.
        As the port-holding socket neither connect() nor listen(),
      it means "no such port yet" for remote ends, and kernel always
      send RST in such a situation automatically (we have to do nothing).
    */
	#ifdef __APPLE__
		if(th->th_sport == 0)
			th->th_sport = (getpid() & 0xffff) | 0x8000;
		else
			th->th_sport++;
		th->th_seq = random_seq();
		addr.sin.sin_port = th->th_sport;
	#else
		th->source = src.sin.sin_port;
		th->seq = random_seq();
	#endif

    #ifdef __APPLE__
		th->th_sum = 0;
		th->th_sum = in_csum(buf, (*length_p)+pseudo_IP_header_size);
	#else
		th->check = 0;
		th->check = in_csum(buf, (*length_p)+pseudo_IP_header_size);
	#endif

    if(ttl != last_ttl) {
        set_ttl (raw_sk, ttl);
        last_ttl = ttl;
    }

    pb->send_time = get_time();

    if(do_send(raw_sk, th, *length_p, &dest_addr) < 0) {
        close (sk);
        pb->send_time = 0;
        return;
    }

	#ifdef __APPLE__
		pb->seq = th->th_sport;
		src.sin.sin_port = th->th_sport;
	#else
		size_t len2 = sizeof(src);
		if(getsockname(raw_sk, &src.sa, &len2) < 0)
			error ("getsockname");
		pb->seq = th->source;
	#endif
    
	pb->sk = sk;

    // Note that the dest port is incremented for each probe, so we have to specify it explicitly
    // Note also that the source port is changed for each probe (determined by bind) so we have to specify it explicitly too
    memcpy(&pb->dest, &dest_addr, sizeof(dest_addr));
    pb->dest.sin.sin_port = dest_port; // valid also for IPv6 as we have a union
    memcpy(&pb->src, &src, sizeof(src));
    pb->src.sin.sin_port = addr.sin.sin_port; // valid also for IPv6 as we have a union
    
    return;
}

static probe* tcp_check_reply(int sk, int err, sockaddr_any* from, char* buf, size_t len)
{
    probe* pb;
    struct tcphdr* tcp = (struct tcphdr*) buf;
    uint16_t sport, dport;

    if(len < 8)
        return NULL;        /*  too short   */


	#ifdef __APPLE__
		if(err) {
			sport = tcp->th_sport;
			dport = tcp->th_dport;
		} else {
			sport = tcp->th_dport;
			dport = tcp->th_sport;
		}
	#else
		if(err) {
			sport = tcp->source;
			dport = tcp->dest;
		} else {
			sport = tcp->dest;
			dport = tcp->source;
		}
	#endif

    if(dport != dest_port)
        return NULL;

    if(!equal_addr(&dest_addr, from))
        return NULL;

    pb = probe_by_seq (sport);
    if(!pb)  return NULL;


    if(!err) {
        pb->final = 1;

        if(info)
            pb->ext = names_by_flags(TH_FLAGS(tcp));
    }

    return pb;
}

static void tcp_recv_probe(int sk, int revents)
{
    if(!(revents & (POLLIN | POLLERR)))
        return;

    recv_reply(sk, !!(revents & POLLERR), tcp_check_reply);
}


static void tcp_expire_probe(probe* pb, int* what)
{
    probe_done (pb, what);
}

static int tcp_is_raw_icmp_sk(int sk)
{
    if(sk == raw_icmp_sk)
        return 1;

    return 0;
}

static probe* tcp_handle_raw_icmp_packet(char* bufp, uint16_t* overhead, struct msghdr* response_get, struct msghdr* ret)
{
    probe* pb = NULL;
    
    if(dest_addr.sa.sa_family == AF_INET) {
        struct iphdr* outer_ip = (struct iphdr*)bufp;
        struct icmphdr* outer_icmp = (struct icmphdr*)(bufp + (outer_ip->ihl << 2));
        struct iphdr* inner_ip = (struct iphdr*) (bufp + (outer_ip->ihl << 2) + sizeof(struct icmphdr));
        
        if(inner_ip->protocol != IPPROTO_TCP)
            return NULL;
            
        struct tcphdr* offending_probe = (struct tcphdr*) (bufp + (outer_ip->ihl << 2) + sizeof(struct icmphdr) + (inner_ip->ihl << 2));
        
        sockaddr_any offending_probe_dest;
        memset(&offending_probe_dest, 0, sizeof(offending_probe_dest));
        offending_probe_dest.sin.sin_family = AF_INET;
        #ifndef __APPLE__
			offending_probe_dest.sin.sin_port = offending_probe->dest;
			offending_probe_dest.sin.sin_addr.s_addr = inner_ip->daddr;
        #else 
            offending_probe_dest.sin.sin_port = offending_probe->th_dport;
			offending_probe_dest.sin.sin_addr.s_addr = inner_ip->daddr;
			offending_probe_dest.sin.sin_len = sizeof(offending_probe_dest.sin); // TODO: correct?
        #endif

        sockaddr_any offending_probe_src;
        memset(&offending_probe_src, 0, sizeof(offending_probe_src));
        offending_probe_src.sin.sin_family = AF_INET;
        #ifndef __APPLE__
			offending_probe_src.sin.sin_port = offending_probe->source;
			offending_probe_src.sin.sin_addr.s_addr = inner_ip->saddr;
        #else
			offending_probe_src.sin.sin_port = offending_probe->th_sport;
			offending_probe_src.sin.sin_addr.s_addr = inner_ip->saddr;
            offending_probe_src.sin.sin_len = sizeof(offending_probe_src.sin); // TODO: correct?
        #endif
        // NOTE on TCP:
        // As long as the source port is kept, this mechanism works fine.
        pb = probe_by_src_and_dest(&offending_probe_src, &offending_probe_dest, (loose_match == 0));
        
        if(!pb)
            return NULL;

        pb->returned_tos = inner_ip->tos;
        probe_done(pb, &pb->icmp_done);
        if(loose_match) 
            *overhead = prepare_ancillary_data(outer_ip, outer_icmp, inner_ip, sizeof(struct tcphdr), ret);
            
    } else if(dest_addr.sa.sa_family == AF_INET6) {
        struct icmp6_hdr* outer_icmp = (struct icmp6_hdr*)bufp;
        struct ip6_hdr* inner_ip = (struct ip6_hdr*) (bufp + sizeof(struct icmp6_hdr));
        
        if(inner_ip->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP)
            return NULL;
        
        struct tcphdr* offending_probe = (struct tcphdr*) (bufp + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr));
        
        sockaddr_any offending_probe_dest;
        memset(&offending_probe_dest, 0, sizeof(offending_probe_dest));
        offending_probe_dest.sin6.sin6_family = AF_INET6;
        #ifndef __APPLE__
			offending_probe_dest.sin6.sin6_port = offending_probe->dest;
			memcpy(&offending_probe_dest.sin6.sin6_addr, &inner_ip->ip6_dst, sizeof(offending_probe_dest.sin6.sin6_addr));
        #else
			offending_probe_dest.sin6.sin6_port = offending_probe->th_dport;
			memcpy(&offending_probe_dest.sin6.sin6_addr, &inner_ip->ip6_dst, sizeof(offending_probe_dest.sin6.sin6_addr));
            offending_probe_dest.sin6.sin6_len = sizeof(offending_probe_dest.sin6); // TODO: correct?
        #endif

        sockaddr_any offending_probe_src;
        memset(&offending_probe_src, 0, sizeof(offending_probe_src));
        offending_probe_src.sin6.sin6_family = AF_INET6;
        #ifndef __APPLE__
			offending_probe_src.sin6.sin6_port = offending_probe->source;
			memcpy(&offending_probe_src.sin6.sin6_addr, &inner_ip->ip6_src, sizeof(offending_probe_src.sin6.sin6_addr));
        #else
			offending_probe_src.sin6.sin6_port = offending_probe->th_sport;
			memcpy(&offending_probe_src.sin6.sin6_addr, &inner_ip->ip6_src, sizeof(offending_probe_src.sin6.sin6_addr));
            offending_probe_src.sin6.sin6_len = sizeof(offending_probe_src.sin6); // TODO: correct?
        #endif

        pb = probe_by_src_and_dest(&offending_probe_src, &offending_probe_dest, (loose_match == 0));
        
        if(!pb)
            return NULL;
        
        uint32_t tmp = ntohl(inner_ip->ip6_ctlun.ip6_un1.ip6_un1_flow);
        tmp &= 0x0fffffff;
        tmp >>= 20; 
        
        pb->returned_tos = (uint8_t)tmp;
        probe_done(pb, &pb->icmp_done);
        
        if(loose_match) 
            *overhead = prepare_ancillary_data_v6(response_get->msg_name, outer_icmp, inner_ip, sizeof(struct tcphdr), ret);
    }
    
    return pb;
}

static void tcp_close()
{
    close(raw_sk);
    if(use_additional_raw_icmp_socket)
        close(raw_icmp_sk);
}

static tr_module tcp_ops = {
    .name = "tcp",
    .init = tcp_init,
    .send_probe = tcp_send_probe,
    .recv_probe = tcp_recv_probe,
    .expire_probe = tcp_expire_probe,
    .options = tcp_options,
    .is_raw_icmp_sk = tcp_is_raw_icmp_sk,
    .handle_raw_icmp_packet = tcp_handle_raw_icmp_packet,
    .close = tcp_close
};

TR_MODULE(tcp_ops);
