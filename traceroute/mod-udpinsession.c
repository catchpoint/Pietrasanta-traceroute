/*
    Copyright(c)  2026   Alessandro Improta, Luca Sani, Catchpoint Systems, Inc.

    Copyright(c)  2006, 2007        Dmitry Butskoy
                    <buc@citadel.stu.neva.ru>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/in.h>

#ifdef __APPLE__
#include "mac/icmp.h"
#include "mac/ip.h"
#include "mac/udp.h"
#include <string.h>
#else
#include <netinet/udp.h>
#endif

#include "traceroute.h"

static sockaddr_any dest_addr = {{ 0, }, };
static unsigned int curr_port = 0;
static uint8_t tmp_buf[65535] = {};
static size_t *length_p;
static int raw_icmp_sk = -1;
static int raw_sk = -1;
static int port_seq_specified = 0;
static int fix_dest_port = 0;
extern int use_additional_raw_icmp_socket;
extern int tr_via_additional_raw_icmp_socket;
static int print_five_tuple = 0;

static void fill_data(char* data, size_t len, int probe_idx)
{
    struct timeval tv;
    gettimeofday(&tv, NULL);

    // Try to generate a "random" payload based on current time and the probe index to get different checksums for different probes as they are used to match the ICMP reply.
    // Given that time and probe_idx varies per each probe, collision probability is in the order of 1 every ~30 million of probes so we are good for a single traceroute run.
    uint64_t seed = ((uint64_t)tv.tv_sec << 32) ^ (uint64_t)tv.tv_usec;
    seed ^= (uint64_t)probe_idx * 0x9e3779b97f4a7c15ULL; // Golden Ratio constant used for better bit scattering

    for (size_t i = 0; i < len; i++) {
        data[i] = (uint8_t)(seed >> ((i & 7) * 8));
        seed = seed * 6364136223846793005ULL + 1; // LCG for pseudo-randomness
    }
}

static uint32_t ones_complement_sum(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;

    while (len > 1) {
        uint16_t word;
        memcpy(&word, data, sizeof(word));
        sum += ntohs(word);
        data += 2;
        len  -= 2;
    }

    if (len == 1)
        sum += ((uint16_t)data[0]) << 8;  // pad last byte

    return sum;
}

uint16_t udp_checksum_ipv4(struct in_addr src, struct in_addr dst, const struct udphdr *udp, size_t udp_len)
{
    // The UDP checksum is computed on IP pseudo-header + UDP header + UDP payload
    struct {
        uint32_t saddr;
        uint32_t daddr;
        uint8_t  zero;
        uint8_t  protocol;
        uint16_t len;
    } pseudo_header;

    pseudo_header.saddr    = src.s_addr;
    pseudo_header.daddr    = dst.s_addr;
    pseudo_header.zero     = 0;
    pseudo_header.protocol = IPPROTO_UDP;
    pseudo_header.len      = htons((uint16_t)udp_len);

    uint32_t sum = 0;

    sum += ones_complement_sum((const uint8_t *)&pseudo_header, sizeof(pseudo_header));
    sum += ones_complement_sum((const uint8_t *)udp, udp_len);

    // Fold 32-bit sum to 16 bits
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    uint16_t checksum = (uint16_t)~sum;

    // A computed checksum of 0 is transmitted as 0xFFFF (See RFC 768)
    if (checksum == 0)
        checksum = 0xFFFF;

    return checksum;
}

uint16_t udp_checksum_ipv6(const struct in6_addr *src, const struct in6_addr *dst, const struct udphdr *udp, uint32_t udp_len)
{
    struct {
        struct in6_addr saddr;
        struct in6_addr daddr;
        uint32_t len;
        uint8_t zero[3];
        uint8_t next_header;
    } pseudo_header;

    pseudo_header.saddr = *src;
    pseudo_header.daddr = *dst;
    pseudo_header.len = htonl(udp_len);
    pseudo_header.zero[0] = 0;
    pseudo_header.zero[1] = 0;
    pseudo_header.zero[2] = 0;
    pseudo_header.next_header = IPPROTO_UDP;

    uint32_t sum = 0;

    sum += ones_complement_sum((const uint8_t *)&pseudo_header, sizeof(pseudo_header));
    sum += ones_complement_sum((const uint8_t *)udp, udp_len);

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    uint16_t checksum = (uint16_t)~sum;

    // A computed checksum of 0 is transmitted as 0xFFFF (See RFC 768)
    if (checksum == 0)
        checksum = 0xFFFF;

    return checksum;
}

static int udpinsession_init(const sockaddr_any* dest, unsigned int port_seq, size_t* packet_len_p)
{
    if(port_seq) {
        port_seq_specified = 1;
        curr_port = port_seq;
    } else {
        curr_port = DEF_START_PORT;
    }

    if(port_seq_specified == 0 && fix_dest_port)
        ex_error("\n\nfix_dest_port must be used in conjunction with -p/--port\n");
    
    dest_addr = *dest;
    dest_addr.sin.sin_port = htons(curr_port);

    raw_sk = socket(dest_addr.sa.sa_family, SOCK_RAW, IPPROTO_UDP);
    if(raw_sk < 0)
        error_or_perm("raw udp socket");

    use_recverr(raw_sk);

    if(tos) {
        int i = tos;
        if(setsockopt(raw_sk, SOL_IP, IP_TOS, &i, sizeof(i)) < 0)
            error("setsockopt IP_TOS");
    }
    
    add_poll(raw_sk, POLLIN | POLLERR);
    
    if(use_additional_raw_icmp_socket) {
        raw_icmp_sk = socket(dest_addr.sa.sa_family, SOCK_RAW, (dest_addr.sa.sa_family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6);
        
        if(raw_icmp_sk < 0)
            error_or_perm("raw icmp socket");
        
        add_poll(raw_icmp_sk, POLLIN | POLLERR);
    }
    
    length_p = packet_len_p;
    
    bind_socket(raw_sk);

    if(connect(raw_sk, &dest_addr.sa, (dest_addr.sa.sa_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0)
        error_or_perm("connect raw udp socket");

    // When using raw sockets the source port is set to IPPROTO_UDP (17) by the kernel, so we save and restore it if it was explicitly set.
    // See https://www.man7.org/linux/man-pages/man7/ip.7.html (Address format)
    uint16_t save_port = 0;
    if(src_addr.sin.sin_port != 0)
        save_port = src_addr.sin.sin_port;

    socklen_t src_len = sizeof(src_addr);
    if(getsockname(raw_sk, &src_addr.sa, &src_len) < 0)
        error("getsockname");
    
    if(save_port)
        src_addr.sin.sin_port = save_port;

    if(print_five_tuple)
        printf("\n<src=%s:%d dst=%s:%d>\n", addr2str(&src_addr), ntohs(src_addr.sin.sin_port), addr2str(&dest_addr), ntohs(dest_addr.sin.sin_port));
    return 0;
}

static CLIF_option udpinsession_options[] = {
    { 0, "print-five-tuple", 0, "Print the source IP address and port and the destination IP address and port in each hop", CLIF_set_flag, &print_five_tuple, 0, 0 },
    CLIF_END_OPTION
};

static void udpinsession_send_probe(probe* pb, int ttl, int probe_idx)
{
    set_ttl(raw_sk, ttl);
    struct udphdr* uh = (struct udphdr*)&(tmp_buf[0]);
    char* data = (char*)&(tmp_buf[sizeof(struct udphdr)]);
    fill_data(data, *length_p, probe_idx);
    
    // Prepare the UDP packet. Everything is fixed except the Checksum (and thus the payload).
    uh->source = src_addr.sin.sin_port;
    uh->dest = dest_addr.sin.sin_port;
    size_t tot_len = sizeof(struct udphdr) + *length_p;
    uh->len = htons(tot_len);
    uh->check = 0; // be sure to reset the checksum before computing the checksum, otherwise the previous value will be used
    uh->check = (dest_addr.sa.sa_family == AF_INET) ? htons(udp_checksum_ipv4(src_addr.sin.sin_addr, dest_addr.sin.sin_addr, uh, sizeof(struct udphdr) + *length_p)) : htons(udp_checksum_ipv6(&src_addr.sin6.sin6_addr, &dest_addr.sin6.sin6_addr, uh, sizeof(struct udphdr) + *length_p));
    pb->checksum = uh->check;

    if(do_send(raw_sk, tmp_buf, tot_len, NULL) < 0) {
        error("sendto");
        close(raw_sk);
        pb->send_time = 0;
        return;
    }
    pb->send_time = get_time();
    memcpy(&pb->dest, &dest_addr, sizeof(dest_addr));
    pb->src = src_addr;
    pb->seq = dest_addr.sin.sin_port;
}

static probe* udpinsession_check_reply(int sk, int err, sockaddr_any* from, char* buf, size_t len) 
{
    // We should never receive back an UDP reply and even if we do, we can't map it back to the probe that triggered it because the original checksum is not there
    // Instead, we should receive ICMP DEST/PORT UNREACHABLE or similar
    if(!err)
        return NULL;
    
    // "buf" points to the UDP header of the probe that expired/reached the destination, i.e. to the UDP header of the IP packet encapsulated in the ICMP message
    // Now we need to match the checksum with the original probe
    struct udphdr* uh = (struct udphdr*)buf;
    probe* pb = probe_by_checksum(uh->check);
    return pb;
}

static void udpinsession_recv_probe(int sk, int revents) 
{
    if((revents & (POLLIN | POLLERR)))
        recv_reply(sk, !!(revents & POLLERR), udpinsession_check_reply);
}

static int udpinsession_is_raw_icmp_sk(int sk)
{
    if(sk == raw_icmp_sk)
        return 1;

    return 0;
}

static probe* udpinsession_handle_raw_icmp_packet(char* bufp, uint16_t* overhead, struct msghdr* response_get, struct msghdr* ret)
{
    sockaddr_any offending_probe_dest;
    sockaddr_any offending_probe_src;
    struct udphdr* offending_probe = NULL;
    int proto = 0;
    int returned_tos = 0;
    extract_ip_info(dest_addr.sa.sa_family, bufp, &proto, &offending_probe_src, &offending_probe_dest, (void **)&offending_probe, &returned_tos); 
    
    if(proto != IPPROTO_UDP)
        return NULL;
        
    offending_probe = (struct udphdr*)offending_probe;
    offending_probe_dest.sin.sin_port = offending_probe->dest;
    offending_probe_src.sin.sin_port = offending_probe->source;
    
#ifdef __APPLE__
    offending_probe_dest.sin.sin_len = sizeof(offending_probe_dest.sin);
    offending_probe_src.sin.sin_len = sizeof(offending_probe_src.sin);
#endif
    
    probe* pb = probe_by_src_and_dest(&offending_probe_src, &offending_probe_dest, (loose_match == 0));
    
    if(!pb)
        return NULL;
        
    pb->returned_tos = returned_tos;
    probe_done(pb, &pb->icmp_done);
    
    if(loose_match || tr_via_additional_raw_icmp_socket) 
        *overhead = prepare_ancillary_data(dest_addr.sa.sa_family, bufp, sizeof(struct udphdr), ret, response_get->msg_name);
    
    return pb;
}

static void udpinsession_close()
{
    if(use_additional_raw_icmp_socket)
        close(raw_icmp_sk);
}

static tr_module udpinsession_ops = {
    .name = "udpinsession",
    .init = udpinsession_init,
    .send_probe = udpinsession_send_probe,
    .recv_probe = udpinsession_recv_probe,
    .header_len = sizeof(struct udphdr),
    .handle_raw_icmp_packet = udpinsession_handle_raw_icmp_packet,
    .is_raw_icmp_sk = udpinsession_is_raw_icmp_sk,
    .options = udpinsession_options,
    .close = udpinsession_close
};

TR_MODULE(udpinsession_ops);
