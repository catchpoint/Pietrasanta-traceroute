/*
    Copyright(c)  2023   Alessandro Improta, Luca Sani, Catchpoint Systems, Inc.
    
    This software was updated by Catchpoint Systems, Inc. to incorporate
    InSession algorithm functionality.
    
    Copyright(c)  2006, 2007        Dmitry Butskoy
                    <buc@citadel.stu.neva.ru>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sys/time.h>
#include <clif.h>

extern unsigned int probes_per_hop;
extern unsigned int num_probes;
extern int last_probe;
extern unsigned int first_hop;
extern int print_allowed;

union common_sockaddr {
    struct sockaddr sa;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
};

typedef union common_sockaddr sockaddr_any;

struct probe_struct
{
    int done;
    int proto_done;
    int icmp_done;
    int final;
    sockaddr_any res;
    double send_time;
    double recv_time;
    int recv_ttl;
    int sk;
    uint32_t seq;
    int reply_from_destination;
    char *ext;
    sockaddr_any src;
    sockaddr_any dest;
    uint32_t seq_num;
    int returned_tos;
    char err_str[16];    /*  assume enough   */
};

typedef struct probe_struct probe;

extern probe* probes;

struct sack_block_struct {
    uint32_t sle;
    uint32_t sre;
};

typedef struct sack_block_struct sack_block;

struct sack_blocks_struct {
    sack_block block[3];
    probe* original_assigned_probe;
};

typedef struct sack_blocks_struct sack_blocks;

struct tr_module_struct {
    struct tr_module_struct *next;
    const char *name;
    int (*init)(const sockaddr_any *dest, unsigned int port_seq, size_t *packet_len);
    void (*send_probe)(probe *pb, int ttl);
    void (*recv_probe)(int fd, int revents);
    void (*expire_probe)(probe *pb, int* what);
    CLIF_option *options;    /*  per module options, if any   */
    int one_per_time;    /*  no simultaneous probes   */
    size_t header_len;    /*  additional header length (aka for udp)   */
    void(*close)();
    int (*is_raw_icmp_sk)(int sk);
    void (*handle_raw_icmp_packet)(char* bufp);
};

enum {
    DESTINATION_DOES_NOT_SUPPORT_ECN = 0, // We found that during the 3-way handshake the destination does not support ECN (ECE is not set into the SYN+ACK)
    DESTINATION_SUPPORT_ECN = 1,
    DATA_ACK_DOES_NOT_CONTAIN_ECE = 2, // The handshake said that TCP dest supports ECN but despite we send a data packet with CE (11) in the IP header the (S)ACK of that packet does not econtain the ECE flag
    ECN_IS_SUPPORTED = 3,
    WEIRD_ECN_BEHAVIOR = 4
};

typedef struct tr_module_struct tr_module;

#define __TEXT(X)       #X
#define _TEXT(X)        __TEXT(X)

#define DEF_START_PORT    33434    /*  start for traditional udp method   */
#define DEF_UDP_PORT    53    /*  dns   */
#define DEF_TCP_PORT    80    /*  web   */
#define DEF_DCCP_PORT    DEF_START_PORT    /*  is it a good choice?...  */
#define DEF_RAW_PROT    253    /*  for experimentation and testing, rfc3692  */

void error(const char *str) __attribute__((noreturn));
void error_or_perm(const char *str) __attribute__((noreturn));

double get_time(void);
void tune_socket(int sk);
void parse_icmp_res(probe *pb, int type, int code, int info);
void probe_done(probe *pb, int* what);
int check_sysctl(const char* name);

typedef probe *(*check_reply_t)(int sk, int err, sockaddr_any *from, char *buf, size_t len);
void recv_reply(int sk, int err, check_reply_t check_reply);

int equal_addr(const sockaddr_any *a, const sockaddr_any *b);
int equal_sockaddr(const sockaddr_any* a, const sockaddr_any* b);
void print_probe(probe*);

probe *probe_by_seq(uint32_t seq);
probe *probe_by_sk(int sk);
probe* probe_by_src_and_dest(sockaddr_any* src, sockaddr_any* dst);

void bind_socket(int sk);
void use_timestamp(int sk);
void use_recv_ttl(int sk);
void use_recverr(int sk);
void set_ttl(int sk, int ttl);
int do_send(int sk, const void *data, size_t len, const sockaddr_any *addr);

void add_poll(int fd, int events);
void del_poll(int fd);
void do_poll(double timeout, void(*callback)(int fd, int revents));

void handle_extensions(probe *pb, char *buf, int len, int step);
const char *get_as_path(const char *query);

int raw_can_connect(void);

unsigned int random_seq(void);
uint16_t in_csum(const void *ptr, size_t len);

void tr_register_module(tr_module *module);
const tr_module *tr_get_module(const char *name);

void extract_ip_info(int family, char* bufp, int* proto, sockaddr_any* src, sockaddr_any* dst, void** offending_probe, int* probe_tos);

#define TR_MODULE(MOD)    \
static void __init_ ## MOD (void) __attribute__ ((constructor));    \
static void __init_ ## MOD (void) {    \
                \
    tr_register_module (&MOD);    \
}
