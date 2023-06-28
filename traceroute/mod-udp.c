/*
    Copyright (c)  2006, 2007		Dmitry Butskoy
					<buc@citadel.stu.neva.ru>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#include "traceroute.h"

#ifndef IPPROTO_UDPLITE
#define IPPROTO_UDPLITE	136
#endif

#ifndef UDPLITE_SEND_CSCOV
#define UDPLITE_SEND_CSCOV	10
#define UDPLITE_RECV_CSCOV	11
#endif


static sockaddr_any dest_addr = {{ 0, }, };
static unsigned int curr_port = 0;
static unsigned int protocol = IPPROTO_UDP;

static char *data = NULL;
static size_t *length_p;
static int raw_icmp_sk = -1;

static void fill_data(size_t* packet_len_p) 
{
    int i;

    length_p = packet_len_p;

    if(*length_p && !(data = malloc(*length_p)))
        error("malloc");

    for(i = 0; i < *length_p; i++)
        data[i] = 0x40 + (i & 0x3f);
}


static int udp_default_init(const sockaddr_any* dest, unsigned int port_seq, size_t* packet_len_p)
{
	curr_port = port_seq ? port_seq : DEF_START_PORT;

	dest_addr = *dest;
	dest_addr.sin.sin_port = htons (curr_port);

	fill_data (packet_len_p);

    raw_icmp_sk = socket(dest_addr.sa.sa_family, SOCK_RAW, (dest_addr.sa.sa_family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6);
    
    if(raw_icmp_sk < 0)
        error("raw icmp socket");
    
    add_poll(raw_icmp_sk, POLLIN | POLLERR);
    
	return 0;
}


static int udp_init(const sockaddr_any* dest, unsigned int port_seq, size_t* packet_len_p)
{
	dest_addr = *dest;

	if (!port_seq)
	    port_seq = DEF_UDP_PORT;
	
	dest_addr.sin.sin_port = htons ((uint16_t) port_seq);
	
	fill_data (packet_len_p);
 
	return 0;
}


static unsigned int coverage = 0;
#define MIN_COVERAGE	(sizeof (struct udphdr))

static void set_coverage(int sk) 
{
    int val = MIN_COVERAGE;

    if(setsockopt(sk, IPPROTO_UDPLITE, UDPLITE_SEND_CSCOV, &coverage, sizeof(coverage)) < 0)
        error("UDPLITE_SEND_CSCOV");

    if(setsockopt(sk, IPPROTO_UDPLITE, UDPLITE_RECV_CSCOV, &val, sizeof(val)) < 0)
        error("UDPLITE_RECV_CSCOV");
}
	
static CLIF_option udplite_options[] = {
    { 0, "coverage", "NUM", "Set udplite send coverage to %s (default is " _TEXT(MIN_COVERAGE) ")", CLIF_set_uint, &coverage, 0, CLIF_ABBREV },
    CLIF_END_OPTION
};

static int udplite_init(const sockaddr_any* dest, unsigned int port_seq, size_t* packet_len_p) 
{
    dest_addr = *dest;

    if(!port_seq)
        port_seq = DEF_UDP_PORT;    /*  XXX: Hmmm...   */
    dest_addr.sin.sin_port = htons((uint16_t) port_seq);

    protocol = IPPROTO_UDPLITE;

    if(!coverage)
        coverage = MIN_COVERAGE;
    
    fill_data(packet_len_p);
 
    return 0;
}

static void udp_send_probe(probe* pb, int ttl)
{
	int sk;
	int af = dest_addr.sa.sa_family;


	sk = socket (af, SOCK_DGRAM, protocol);
	if (sk < 0)  error ("socket");

	tune_socket (sk);	/*  common stuff   */

	if (coverage)  set_coverage (sk);	/*  udplite case   */

	set_ttl (sk, ttl);


	if (connect (sk, &dest_addr.sa, sizeof (dest_addr)) < 0)
		error ("connect");

	use_recverr (sk);


	pb->send_time = get_time ();

	if (do_send (sk, data, *length_p, NULL) < 0) {
	    close (sk);
	    pb->send_time = 0;
	    return;
	}


	pb->sk = sk;

	add_poll (sk, POLLIN | POLLERR);

	pb->seq = dest_addr.sin.sin_port;

	if (curr_port) {	/*  traditional udp method   */
	    curr_port++;
	    dest_addr.sin.sin_port = htons (curr_port);	/* both ipv4 and ipv6 */
	}

	return;
}


static probe *udp_check_reply (int sk, int err, sockaddr_any *from,
						    char *buf, size_t len) {
	probe *pb;

	pb = probe_by_sk (sk);
	if (!pb)  return NULL;

	if (pb->seq != from->sin.sin_port)
		return NULL;

	if (!err)  pb->final = 1;

	return pb;
}


static void udp_recv_probe (int sk, int revents) {

	if (!(revents & (POLLIN | POLLERR)))
		return;

	recv_reply (sk, !!(revents & POLLERR), udp_check_reply);
}


static void udp_expire_probe (probe *pb, int* what) 
{
	probe_done (pb, what);
}

static int udp_is_raw_icmp_sk(int sk)
{
    if(sk == raw_icmp_sk)
        return 1;

    return 0;
}

static void udp_handle_raw_icmp_packet(char* bufp)
{
    if(dest_addr.sa.sa_family == AF_INET) {
        struct iphdr* outer_ip = (struct iphdr*)bufp;
        struct iphdr* inner_ip = (struct iphdr*)(bufp + (outer_ip->ihl << 2) + sizeof(struct icmphdr));
        
        if(inner_ip->protocol != IPPROTO_UDP)
            return;
            
        struct udphdr* offending_probe = (struct udphdr*)(bufp + (outer_ip->ihl << 2) + sizeof(struct icmphdr) + (inner_ip->ihl << 2));
        
        sockaddr_any offending_probe_dest;
        memset(&offending_probe_dest, 0, sizeof(offending_probe_dest));
        offending_probe_dest.sin.sin_family = AF_INET;
        offending_probe_dest.sin.sin_port = offending_probe->dest;
        offending_probe_dest.sin.sin_addr.s_addr = inner_ip->daddr;
        
        sockaddr_any offending_probe_src;
        memset(&offending_probe_src, 0, sizeof(offending_probe_src));
        offending_probe_src.sin.sin_family = AF_INET;
        offending_probe_src.sin.sin_port = offending_probe->source;
        offending_probe_src.sin.sin_addr.s_addr = inner_ip->saddr;
        
        probe* pb = probe_by_src_and_dest(&offending_probe_src, &offending_probe_dest);
        
        if(pb) {
            pb->returned_tos = inner_ip->tos;        
            udp_expire_probe(pb, &pb->icmp_done);
        }
    } else if(dest_addr.sa.sa_family == AF_INET6) {
        struct ip6_hdr* inner_ip = (struct ip6_hdr*) (bufp + sizeof(struct icmp6_hdr));
        
        if(inner_ip->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_UDP)
            return;
        
        struct udphdr* offending_probe = (struct udphdr*) (bufp + sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr));
        
        sockaddr_any offending_probe_dest;
        memset(&offending_probe_dest, 0, sizeof(offending_probe_dest));
        offending_probe_dest.sin6.sin6_family = AF_INET6;
        offending_probe_dest.sin6.sin6_port = offending_probe->dest;
        memcpy(&offending_probe_dest.sin6.sin6_addr, &inner_ip->ip6_dst, sizeof(offending_probe_dest.sin6.sin6_addr));
        
        sockaddr_any offending_probe_src;
        memset(&offending_probe_src, 0, sizeof(offending_probe_src));
        offending_probe_src.sin6.sin6_family = AF_INET6;
        offending_probe_src.sin6.sin6_port = offending_probe->source;
        memcpy(&offending_probe_src.sin6.sin6_addr, &inner_ip->ip6_src, sizeof(offending_probe_src.sin6.sin6_addr));
        
        probe* pb = probe_by_src_and_dest(&offending_probe_src, &offending_probe_dest);
        
        if(pb) {
            uint32_t tmp = ntohl(inner_ip->ip6_ctlun.ip6_un1.ip6_un1_flow);
            tmp &= 0x0fffffff;
            tmp >>= 20; 
            
            pb->returned_tos = (uint8_t)tmp;
        
            udp_expire_probe(pb, &pb->icmp_done);
        }
    }
}

/*  All three modules share the same methods except the init...  */

static tr_module default_ops = {
	.name = "default",
	.init = udp_default_init,
	.send_probe = udp_send_probe,
	.recv_probe = udp_recv_probe,
	.expire_probe = udp_expire_probe,
	.header_len = sizeof (struct udphdr),
	.handle_raw_icmp_packet = udp_handle_raw_icmp_packet,
};

TR_MODULE (default_ops);


static tr_module udp_ops = {
	.name = "udp",
	.init = udp_init,
	.send_probe = udp_send_probe,
	.recv_probe = udp_recv_probe,
	.expire_probe = udp_expire_probe,
	.header_len = sizeof (struct udphdr),
	.handle_raw_icmp_packet = udp_handle_raw_icmp_packet,
};

TR_MODULE (udp_ops);


static tr_module udplite_ops = {
	.name = "udplite",
	.init = udplite_init,
	.send_probe = udp_send_probe,
	.recv_probe = udp_recv_probe,
	.expire_probe = udp_expire_probe,
	.header_len = sizeof (struct udphdr),
	.options = udplite_options,
	.is_raw_icmp_sk = udp_is_raw_icmp_sk,
	.handle_raw_icmp_packet = udp_handle_raw_icmp_packet,
};

TR_MODULE (udplite_ops);
