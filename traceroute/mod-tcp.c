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
#ifdef __APPLE__
#include "mac/icmp.h"
#include "mac/ip.h"
#include "mac/types.h"
#include <string.h>
#include <stdio.h>
#endif
#include <stdio.h>
#include "common-tcp.h"

#ifndef IP_MTU
#define IP_MTU 14
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
static int sysctl = 0;
static int reuse = 0;
static unsigned int mss = 0;
static int info = 0;
static int use_ecn = 0;
static int use_acc_ecn = 0;
extern int use_additional_raw_icmp_socket;
extern int tr_via_additional_raw_icmp_socket;
extern int ecn_input_value;
extern int disable_extra_ping;
extern sockaddr_any src_addr;
static CLIF_option tcp_options[] = {
    { 0, "syn", 0, "Set tcp flag SYN (default if no other tcp flags specified)", set_tcp_flag, 0, 0, 0 },
    { 0, "ack", 0, "Set tcp flag ACK,", set_tcp_flag, 0, 0, 0 },
    { 0, "fin", 0, "FIN,", set_tcp_flag, 0, 0, 0 },
    { 0, "rst", 0, "RST,", set_tcp_flag, 0, 0, 0 },
    { 0, "psh", 0, "PSH,", set_tcp_flag, 0, 0, 0 },
    { 0, "urg", 0, "URG,", set_tcp_flag, 0, 0, 0 },
    { 0, "ece", 0, "ECE,", set_tcp_flag, 0, 0, 0 },
    { 0, "cwr", 0, "CWR", set_tcp_flag, 0, 0, 0 },
    { 0, "ae", 0, "Set tcp flag AE (Accurate ECN)", set_tcp_flag, 0, 0, 0 },
    { 0, "flags", "NUM", "Set tcp flags exactly to value %s", set_tcp_flags, 0, 0, CLIF_ABBREV },
    { 0, "ecn", 0, "Send syn packet with tcp flags ECE and CWR (for Explicit Congestion Notification, rfc3168)", CLIF_set_flag, &use_ecn, 0, 0 },
    { 0, "sack", 0, "Use sack,", set_tcp_option, (void*)OPT_SACK, 0, 0 },
    { 0, "timestamps", 0, "timestamps,", set_tcp_option, (void*)OPT_TSTAMP, 0, CLIF_ABBREV },
    { 0, "window_scaling", 0, "window_scaling option for tcp", set_tcp_option, (void*)OPT_WSCALE, 0, CLIF_ABBREV },
    { 0, "sysctl", 0, "Use current sysctl (/proc/sys/net/*) setting for the tcp options and ecn/acc_ecn. Always set by default (with \"syn\") if nothing else specified", CLIF_set_flag, &sysctl, 0, 0 },
    { 0, "reuse", 0, "Allow to reuse local port numbers for the huge workloads (SO_REUSEADDR)", CLIF_set_flag, &reuse, 0, 0 },
    { 0, "mss", "NUM", "Use value of %s for maxseg tcp option (when syn)", CLIF_set_uint16, &mss, 0, 0 },
    { 0, "info", 0, "Print tcp flags of final tcp replies when target host is reached. Useful to determine whether an application listens the port etc.", CLIF_set_flag, &info, 0, 0 },
    { 0, "acc-ecn", 0, "Send syn packets with tcp flags ECE, CWR and AE (for Accurate ECN check, not yet rfc but draft)", CLIF_set_flag, &use_acc_ecn, 0, 0 },
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
 
  #ifdef __APPLE__
    // This is needed to find the source address to use so that we can prepare the IP pseudo header.
    // We cannot rely on getsockname called after the bind() because the source address for some reasonis not filled
    if(findsaddr(&dest_addr.sa, &src.sa) != NULL)
        error("findsaddr");
    src_addr = src;
    tune_socket(raw_sk);
    if(connect(raw_sk, &dest_addr.sa, (af == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0)
       error ("connect");
  #else
    tune_socket(raw_sk);        /*  including bind, if any   */
    if(connect(raw_sk, &dest_addr.sa, (af == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0)
       error ("connect");
    
    len = (af == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    if(getsockname(raw_sk, &src.sa, &len) < 0)
        error ("getsockname");
  #endif

    len = sizeof(mtu);
    if(getsockopt(raw_sk, af == AF_INET ? SOL_IP : SOL_IPV6, af == AF_INET ? IP_MTU : IPV6_MTU, &mtu, &len) < 0 || mtu < 576)
        mtu = 576;

    /*  mss = mtu - headers   */
    mtu -= af == AF_INET ? sizeof(struct iphdr) : sizeof(struct ip6_hdr);
    mtu -= sizeof(struct tcphdr);

 #ifndef __APPLE__
    if(!raw_can_connect()) {    /*  work-around for buggy kernels  */
        close (raw_sk);
        raw_sk = socket (af, SOCK_RAW, IPPROTO_TCP);
        if(raw_sk < 0)  error ("socket");
        tune_socket(raw_sk);
        /*  but do not connect it...  */
    }
 #endif


    #ifndef __APPLE__
    use_recverr(raw_sk);
    #endif

    add_poll(raw_sk, POLLIN | POLLERR);

    /*  Now create the sample packet.  */

    if(flags == 0) {
        sysctl = 1;
        if(!flags_provided) {   /*  no any tcp flag set and the user didn't explicitly set them to zero   */
            flags |= SYN;
            if(use_ecn)
                flags |= ECE | CWR;
            else if(use_acc_ecn)
                flags |= AE | ECE | CWR;
        }
    }
    
    if(sysctl) {
        if(check_sysctl("ecn") == 1) {
            flags |= (ECE | CWR);
            use_ecn = 1;
        } else if(check_sysctl("ecn") == 3) {
            flags |= AE | ECE | CWR;
            use_acc_ecn = 1;
        }
        
        // Forcing TCP SACK, timestamps and Window scale in TCP options. This fix forces the code to generate TCP SYN packets without payload, which eventually would cause the probes to be dropped by regular firewalls. 
        // TCP SYN packets with payload are generated due to an initial hard-coded value of 40B of the probe size which was present in the original code and is now used in the new path MTU discovery process. 
        // Please remove this comment once the bug has been fixed.
        
        options |= OPT_SACK;
        options |= OPT_TSTAMP;
        options |= OPT_WSCALE;
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
        len = sizeof(struct in_addr);
        memcpy (ptr, &src.sin.sin_addr, len);
        ptr += len;
        memcpy (ptr, &dest_addr.sin.sin_addr, len);
        ptr += len;
    } else {
        len = sizeof(struct in6_addr);
        memcpy (ptr, &src.sin6.sin6_addr, len);
        ptr += len;
        memcpy (ptr, &dest_addr.sin6.sin6_addr, len);
        ptr += len;
    }

    lenp = (uint16_t*)ptr;
    ptr += sizeof(uint16_t);
    *((uint16_t*)ptr) = htons((uint16_t)IPPROTO_TCP);
    ptr += sizeof(uint16_t);

    /*  Construct TCP header   */

    th = (struct tcphdr*)ptr;

    pseudo_IP_header_size = ptr - tmp_buf;
    
#ifdef __APPLE__
    th->th_sport = 0;
    th->th_dport = dest_port;
    th->th_seq = 0;
    th->th_ack = 0;
    th->th_off = 0;
    set_th_flags(th, flags);
    th->th_win = htons(4 * mtu);
    th->th_sum = 0;
    th->th_urp = 0;
#else
    th->source = 0;
    th->dest = dest_port;
    th->seq = 0;
    th->ack_seq = 0;
    th->doff = 0;
    set_th_flags(th, flags);
    th->window = htons (4 * mtu);
    th->check = 0;
    th->urg_ptr = 0;
#endif

    /*  Build TCP options   */

    ptr = (uint8_t*)(th + 1);

    if(flags & SYN) {
        *ptr++ = TCPOPT_MAXSEG;    /*  2   */
        *ptr++ = TCPOLEN_MAXSEG;    /*  4   */
        *((uint16_t*) ptr) = htons (mss ? mss : mtu);
        ptr += sizeof(uint16_t);
    }

    if(options & OPT_TSTAMP) {
        if(options & OPT_SACK) {
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
        *((uint32_t*) ptr) = (flags & ACK) ? random_seq () : 0;
        ptr += sizeof(uint32_t);
    } else if(options & OPT_SACK) {
        *ptr++ = TCPOPT_NOP;    /*  1   */
        *ptr++ = TCPOPT_NOP;    /*  1   */
        *ptr++ = TCPOPT_SACK_PERMITTED;    /*  4   */
        *ptr++ = TCPOLEN_SACK_PERMITTED;    /*  2   */
    }

    if(options & OPT_WSCALE) {
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

    // Allow the filling of the TCP payload only if we are doing mtudisc, otherwise do not do that.
    // This is compliant with original traceroute TCP behavior, which does not send TCP probes with a payload never.
    if(!mtudisc)
        *packet_len_p = len; // Force the length to be only the len of the TCP header. This will avoid the fill loop to fill the payload
    
    length_p = packet_len_p;
    
    if(*length_p && !(buf = malloc(*length_p+pseudo_IP_header_size)))
        error("malloc");

    memcpy(buf, tmp_buf, pseudo_IP_header_size+len);
    th = (struct tcphdr*)(buf + pseudo_IP_header_size);

    for(int i = len; i < *length_p; i++)
        buf[i+pseudo_IP_header_size] = 0x40 + (i & 0x3f); // Same as in UDP
    
    if(use_additional_raw_icmp_socket) {
        raw_icmp_sk = socket(dest_addr.sa.sa_family, SOCK_RAW, (dest_addr.sa.sa_family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6);
        if(raw_icmp_sk < 0)
            error_or_perm("raw icmp socket");
        add_poll(raw_icmp_sk, POLLIN | POLLERR);
    }
 
    return 0;
}

static void tcp_send_probe(probe* pb, int ttl)
{
    int sk;
    int af = dest_addr.sa.sa_family;
    sockaddr_any addr;
    memset(&addr, 0, sizeof(addr));
    
    socklen_t len = sizeof(struct sockaddr);

    /*  To make sure we have chosen a free unused "source port",
       just create, (auto)bind and hold a socket while the port is needed.
    */

    sk = socket(af, SOCK_STREAM, 0);
    if(sk < 0)
        error("socket");

    if(reuse && setsockopt (sk, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
        error ("setsockopt SO_REUSEADDR");

    bind_socket(sk);
    
    if(getsockname (sk, &addr.sa, &len) < 0)
        error ("getsockname");

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
        th->th_sport = addr.sin.sin_port;
        th->th_seq = random_seq();
    #else
        th->source = addr.sin.sin_port;
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
        socklen_t len2 = sizeof(src);
        if(getsockname(raw_sk, &src.sa, &len2) < 0)
            error ("getsockname");
        pb->seq = th->source;
    #endif
    
    pb->sk = sk;

    // Note that the dest port is incremented for each probe, so we have to specify it explicitly
    // Note also that the source port is changed for each probe (determined by bind) so we have to specify it explicitly too
    memcpy(&pb->dest, &dest_addr, sizeof(sockaddr_any));
    pb->dest.sin.sin_port = dest_port; // valid also for IPv6 as we have a union
    memcpy(&pb->src, &src, sizeof(sockaddr_any));
    pb->src.sin.sin_port = addr.sin.sin_port; // valid also for IPv6 as we have a union
}

static probe* tcp_check_reply(int sk, int err, sockaddr_any* from, char* buf, size_t len)
{
    probe* pb;
    struct tcphdr* tcp = (struct tcphdr*) buf;
    uint16_t sport = 0;
    uint16_t dport = 0;

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
    if(!pb)
        return NULL;

    if(!err) {
        pb->final = 1;

        if(info)
            pb->ext = names_by_flags(get_th_flags(tcp));
        
        if(mss > 0) {
          #ifdef __APPLE__
            int length = (th->th_off * 4) - sizeof(struct tcphdr);
          #else
            int length = (th->doff * 4) - sizeof(struct tcphdr);
          #endif
            const unsigned char* ptr = (const unsigned char*)(tcp + 1);
            
            while(length > 0) {
                int opcode = *ptr++;
                if(opcode == 0) // End of options (EOL)
                    break;
                    
                if(opcode == 1) // NOP with no length
                    continue;
                
                uint8_t size = *ptr++;
                if(opcode == 2) {
                    uint16_t mss_received = ntohs(*(uint16_t*)ptr);
                    
                    if(info > 0 && pb->ext && strlen(pb->ext) > 0) {
                        char str[100] = {};    /*  enough...  */
                        sprintf(str, "%s,MSS:%d", pb->ext, mss_received); 
                        free(pb->ext);
                        pb->ext = strdup(str);
                    } else {
                        char str[10] = {};    /*  enough...  */
                        sprintf(str, "MSS:%d", mss_received);
                        pb->ext = strdup(str);
                    }
                    break; // Only need MSS from options
                }

                if(size < 2)
                    break;

                ptr += (size - 2);
                length -= size;
            }
        }
    }

    return pb;
}

static void tcp_recv_probe(int sk, int revents)
{
    if(!(revents & (POLLIN | POLLERR)))
        return;
    recv_reply(sk, !!(revents & POLLERR), tcp_check_reply);
}

static int tcp_is_raw_icmp_sk(int sk)
{
    if(sk == raw_icmp_sk)
        return 1;
    return 0;
}

static probe* tcp_handle_raw_icmp_packet(char* bufp, uint16_t* overhead, struct msghdr* response_get, struct msghdr* ret)
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
    
#ifdef __APPLE__
    offending_probe_dest.sin.sin_port = offending_probe->th_dport;
    offending_probe_src.sin.sin_port = offending_probe->th_sport;
    offending_probe_dest.sin.sin_len = sizeof(offending_probe_dest.sin);
    offending_probe_src.sin.sin_len = sizeof(offending_probe_src.sin);
#else
    offending_probe_dest.sin.sin_port = offending_probe->dest;
    offending_probe_src.sin.sin_port = offending_probe->source;
#endif

    probe* pb = probe_by_src_and_dest(&offending_probe_src, &offending_probe_dest, (loose_match == 0));
    
    if(!pb)
        return NULL;
        
    pb->returned_tos = returned_tos;
    probe_done(pb, &pb->icmp_done);
    
    if(loose_match || tr_via_additional_raw_icmp_socket) 
        *overhead = prepare_ancillary_data(dest_addr.sa.sa_family, bufp, sizeof(struct tcphdr), ret, response_get->msg_name);
    return pb;
}


static void tcp_close()
{
    close(raw_sk);
    if(use_additional_raw_icmp_socket)
        close(raw_icmp_sk);
}

int tcp_need_extra_ping()
{
    if(ecn_input_value > 0 && info && use_ecn)
        return 1;
    return 0;
}

int tcp_setup_extra_ping()
{
    int i = 0;
    if(dest_addr.sa.sa_family == AF_INET) {
        if(setsockopt(raw_sk, SOL_IP, IP_TOS, &i, sizeof(i)) < 0)
            error("setsockopt IP_TOS");
    } else if(dest_addr.sa.sa_family == AF_INET6) {
        // For IPv6 things are a little bit more complicated because for
        // some reaason on CentOS7 setting again IPV6_TCLASS does not have
        // effect. So here we open a dedicated socket just to perform the
        // check about "Classic ECN"
        int extra_ping_sk = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
        if(extra_ping_sk < 0)
            error_or_perm("extra_ping_sk: socket");

        // Setup the dedicated socket by forcing tos = 0
        int save_tos = tos;
        tos = 0;
        tune_socket(extra_ping_sk);
        tos = save_tos;

        if(connect(extra_ping_sk, &dest_addr.sa, sizeof(dest_addr)) < 0)
            error("connect");

        close(raw_sk);
        raw_sk = extra_ping_sk; // in this way do_it() will use the new socket
        add_poll(raw_sk, POLLIN | POLLERR);
    } else {
        ex_error("Unhandled family %d\n", dest_addr.sa.sa_family);
    }
    return 0;
}

static tr_module tcp_ops = {
    .name = "tcp",
    .init = tcp_init,
    .send_probe = tcp_send_probe,
    .recv_probe = tcp_recv_probe,
    .options = tcp_options,
    .is_raw_icmp_sk = tcp_is_raw_icmp_sk,
    .handle_raw_icmp_packet = tcp_handle_raw_icmp_packet,
    .need_extra_ping = tcp_need_extra_ping,
    .setup_extra_ping = tcp_setup_extra_ping,
    .close = tcp_close
};

TR_MODULE(tcp_ops);
