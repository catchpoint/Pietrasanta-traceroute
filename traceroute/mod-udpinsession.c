/*
    Copyright (c)  2026             Catchpoint Systems, Inc.    
    Copyright (c)  2026             Alessandro Improta, Luca Sani
                    <aimprota@catchpoint.com>    
                    <lsani@catchpoint.com>

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

static sockaddr_any src[MAX_PROBES] = {};
static sockaddr_any dest_addr[MAX_PROBES] = {};
static int raw_sk[MAX_PROBES] = { -1 };
static int raw_icmp_sk = -1;
static int print_five_tuple = 0;

static uint8_t tmp_buf[65535] = {};
static size_t *length_p;

static int af = 0;
static int fix_dest_port = 0;
extern int use_additional_raw_icmp_socket;
extern int tr_via_additional_raw_icmp_socket;
static int ecmp = 0;
static int n_flows = 0;

static CLIF_option udpinsession_options[] = {
    { 0, "ecmp", 0, "ECMP,", CLIF_set_flag, &ecmp, 0, 0 },
    { 0, "fix_dest_port", 0, "Keep the destination port fixed. This can be used only in conjunction with ecmp", CLIF_set_flag, &fix_dest_port, 0, CLIF_ABBREV },
    { 0, "print-five-tuple", 0, "Print the source IP address and port and the destination IP address and port in each hop", CLIF_set_flag, &print_five_tuple, 0, 0 },
    CLIF_END_OPTION
};

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

    if(len == 1)
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
    if(checksum == 0)
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
    if(checksum == 0)
        checksum = 0xFFFF;

    return checksum;
}

static int udpinsession_init(const sockaddr_any* dest, unsigned int port_seq, size_t* packet_len_p)
{
    int fix_src_port = (src_addr.sin.sin_port != 0) ? 1 : 0;

    if(fix_dest_port && !ecmp)
        ex_error("\n\nfix_dest_port can only be used with ECMP\n");

    // If we are using ecmp mode and moreover we are asked to keep the dest port fixed, we can't fix also the source port (5-tuple need to change in some way)
    if(ecmp && fix_src_port && fix_dest_port) 
        ex_error("\n\nfix_dest_port cannot be used with ECMP when the source port is explicitly set\n");

    n_flows = (ecmp) ? probes_per_hop : 1;
    
    af = dest->sa.sa_family;
    uint16_t dest_port = (port_seq != 0) ? port_seq : DEF_START_PORT;

    for(int i = 0; i < n_flows; i++) {
        dest_addr[i] = *dest;
        
        if(af == AF_INET)
            dest_addr[i].sin.sin_port = htons(dest_port);
        else
            dest_addr[i].sin6.sin6_port = htons(dest_port);
        
        // if we are not asked to keep the destination port fixed, we increment it for each flow
        if(ecmp && !fix_dest_port)
            dest_port++;

        raw_sk[i] = socket(dest_addr[i].sa.sa_family, SOCK_RAW, IPPROTO_UDP);
        if(raw_sk[i] < 0)
            error_or_perm("raw udp socket");

        use_recverr(raw_sk[i]);

        if(tos) {
            int opt = tos;
            if(setsockopt(raw_sk[i], SOL_IP, IP_TOS, &opt, sizeof(opt)) < 0)
                error("setsockopt IP_TOS");
        }

        add_poll(raw_sk[i], POLLIN | POLLERR);
        bind_socket(raw_sk[i]);

        if(connect(raw_sk[i], &dest_addr[i].sa, (af == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0)
            error_or_perm("connect raw udp socket");

        // Here we need to get the source address we are going to use, in particular the src port
        // This depends on whether we need to keep the source port fixed or not and the dest port fixed or not
        socklen_t src_len = sizeof(src_addr);
        if(ecmp) {
            if(fix_src_port) { // This means we need to keep src port fixed (fix_dest_port MUST be true), thus dest port is incremented (see above)
                // When using raw sockets the source port is set to IPPROTO_UDP (17) by the kernel, so we save and restore it if it was explicitly set.
                // See https://www.man7.org/linux/man-pages/man7/ip.7.html (Address format)
                uint16_t save_port = src_addr.sin.sin_port;
                if(getsockname(raw_sk[i], &src_addr.sa, &src_len) < 0)
                    error("getsockname");
                src_addr.sin.sin_port = save_port;
                src[i] = src_addr;
            } else if(fix_dest_port) { // we need to keep the dest fixed, thus src_port need to be incremented
                if(getsockname(raw_sk[i], &src_addr.sa, &src_len) < 0)
                    error("getsockname");
                src[i] = src_addr;
                if(i > 0)
                    src[i].sin.sin_port = htons(ntohs(src[i-1].sin.sin_port) + 1);
            } else { // The dst port varies and we don't have to keep the src fixed, so we can avid to worry
                if(getsockname(raw_sk[i], &src_addr.sa, &src_len) < 0)
                    error("getsockname");
                src[i] = src_addr;
            }
        } else {
            if(getsockname(raw_sk[i], &src_addr.sa, &src_len) < 0)
                error("getsockname");
            src[i] = src_addr;
        }

    }

    if(use_additional_raw_icmp_socket) {
        raw_icmp_sk = socket(af, SOCK_RAW, (af == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6);
        
        if(raw_icmp_sk < 0)
            error_or_perm("raw icmp socket");
        
        add_poll(raw_icmp_sk, POLLIN | POLLERR);
    }
    
    length_p = packet_len_p;

    return 0;
}

static void udpinsession_send_probe(probe* pb, int ttl, int probe_idx)
{
    int flow = (ecmp) ? probe_idx % probes_per_hop : 0;
    
    set_ttl(raw_sk[flow], ttl);
    struct udphdr* uh = (struct udphdr*)&(tmp_buf[0]);
    char* data = (char*)&(tmp_buf[sizeof(struct udphdr)]);
    fill_data(data, *length_p, probe_idx);
    
    // Prepare the UDP packet. Everything is fixed except the Checksum (and thus the payload).
    uh->source = src[flow].sin.sin_port;
    uh->dest = dest_addr[flow].sin.sin_port;
    size_t tot_len = sizeof(struct udphdr) + *length_p;
    uh->len = htons(tot_len);
    uh->check = 0; // be sure to reset the checksum before computing the checksum, otherwise the previous value will be used
    uh->check = (af == AF_INET) ? htons(udp_checksum_ipv4(src[flow].sin.sin_addr, dest_addr[flow].sin.sin_addr, uh, sizeof(struct udphdr) + *length_p)) : htons(udp_checksum_ipv6(&src[flow].sin6.sin6_addr, &dest_addr[flow].sin6.sin6_addr, uh, sizeof(struct udphdr) + *length_p));
    pb->checksum = uh->check;
    
    if(do_send(raw_sk[flow], tmp_buf, tot_len, NULL) < 0) {
        error("sendto");
        close(raw_sk[flow]);
        pb->send_time = 0;
        return;
    }
    pb->send_time = get_time();

    memcpy(&pb->dest, &dest_addr[flow], sizeof(dest_addr[flow]));
    pb->src = src[flow];
    pb->seq = dest_addr[flow].sin.sin_port;
    
    // Record the sk since with (SOCK_RAW, IPPROTO_UDP) kernel does not take in account UDP src/dst port when delivering to sockets, so an ICMP error is delivered to all opened sockets
    // When the probe will be recovered via the matched checksum, then we can check if the socket that matched it is the socket through which was delivered
    pb->flow_sk = raw_sk[flow];
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
    if(pb != NULL && pb->flow_sk != sk) // see udpinsession_send_probe for more details on this check
        return NULL;

    if(pb && print_five_tuple && pb->five_tuple == NULL) {
        char str[128] = {};
        snprintf(str, sizeof(str), "%s%s%s:%u->%s%s%s:%u", af == AF_INET6 ? "[" : "", addr2str(&pb->src), af == AF_INET6 ? "]" : "", ntohs(pb->src.sin.sin_port), af == AF_INET6 ? "[" : "", addr2str(&pb->dest), af == AF_INET6 ? "]" : "", ntohs(pb->dest.sin.sin_port));
        pb->five_tuple = strdup(str);
    }
    
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
    extract_ip_info(af, bufp, &proto, &offending_probe_src, &offending_probe_dest, (void **)&offending_probe, &returned_tos); 
    
    if(proto != IPPROTO_UDP)
        return NULL;
        
    offending_probe = (struct udphdr*)offending_probe;
    offending_probe_dest.sin.sin_port = offending_probe->dest;
    offending_probe_src.sin.sin_port = offending_probe->source;
    
#ifdef __APPLE__
    offending_probe_dest.sin.sin_len = sizeof(offending_probe_dest.sin);
    offending_probe_src.sin.sin_len = sizeof(offending_probe_src.sin);
#endif
    
    probe *pb = probe_by_checksum(offending_probe->check);
    if(!pb)
        return NULL;

    // Since additional_raw_icmp_socket receives ICMP traffic independently of the UDP raw sockets we need to enusre this
    // is traffic for us and not for other appplications
    if(!equal_sockaddr(&offending_probe_dest, &pb->dest))
        return NULL;

    if(loose_match) {
        if(!equal_port(&offending_probe_src, &pb->src))
            return NULL;
    } else {
        if(!equal_sockaddr(&offending_probe_src, &pb->src))
            return NULL;
    }

    if(print_five_tuple && pb->five_tuple == NULL) {
        char str[128] = {};
        char src_str[INET6_ADDRSTRLEN + 16] = {};
        snprintf(src_str, sizeof(src_str), "%s%s%s:%u", af == AF_INET6 ? "[" : "", addr2str(&pb->src), af == AF_INET6 ? "]" : "", ntohs(pb->src.sin.sin_port));
        snprintf(str + strlen(str), sizeof(str) - strlen(str), "%s->%s%s%s:%u", src_str, af == AF_INET6 ? "[" : "", addr2str(&pb->dest), af == AF_INET6 ? "]" : "", ntohs(pb->dest.sin.sin_port));

        pb->five_tuple = strdup(str);
    }
        
    pb->returned_tos = returned_tos;
    probe_done(pb, &pb->icmp_done);
    
    if(loose_match || tr_via_additional_raw_icmp_socket) 
        *overhead = prepare_ancillary_data(af, bufp, sizeof(struct udphdr), ret, response_get->msg_name);
    
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
