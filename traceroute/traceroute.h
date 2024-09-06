/*
    Copyright(c)  2023   Alessandro Improta, Luca Sani, Catchpoint Systems, Inc.
    
    This software was updated by Catchpoint Systems, Inc. to incorporate
    InSession algorithm functionality.
    
    Copyright(c)  2006, 2007        Dmitry Butskoy
                    <buc@citadel.stu.neva.ru>
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <errno.h>
#include <netinet/in.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <sys/time.h>
#include <clif.h>

#define ECN_NOT_ECT 0x00
#define ECN_ECT_0 0x02
#define ECN_ECT_1 0x01
#define ECN_CE    0x03

#ifdef HAVE_OPENSSL3
#define MAX_QUIC_ID_LEN 20 // Source and Dest connection ID MUST not exceed 20 bytes https://www.rfc-editor.org/rfc/rfc9000#section-17.2-3.12.1
#endif

extern unsigned int probes_per_hop;
extern unsigned int num_probes;
extern int last_probe;
extern unsigned int first_hop;
extern int tcpinsession_print_allowed;
extern int loose_match;
extern int mtudisc;
extern unsigned int tos;
extern int ecn_input_value;
extern int disable_extra_ping;
extern int mtudisc_phase;

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
    int seq;
    char *ext;
    int mss;
    int mtu;
    int returned_tos;
    int exit_please;
    sockaddr_any src;
    sockaddr_any dest;
    uint32_t seq_num;
    // quic stuff
#ifdef HAVE_OPENSSL3
    uint8_t dcid[MAX_QUIC_ID_LEN];
    uint8_t dcid_len;
    uint8_t* retry_token;
    uint8_t retry_token_len;
    double retry_rtt;
#endif
    char* proto_details;
    int tcpinsession_destination_reply;
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
    CLIF_option *options;    /*  per module options, if any   */
    int one_per_time;    /*  no simultaneous probes   */
    size_t header_len;    /*  additional header length (aka for udp)   */
    void(*close)();
    int (*is_raw_icmp_sk)(int sk);
    probe* (*handle_raw_icmp_packet)(char* bufp, uint16_t* overhead, struct msghdr* response_get, struct msghdr* ret);
    int (*need_extra_ping)(void);
    int (*setup_extra_ping)(void);
};

typedef struct tr_module_struct tr_module;

#define __TEXT(X)       #X
#define _TEXT(X)        __TEXT(X)

#define DEF_START_PORT    33434    /*  start for traditional udp method   */
#define DEF_UDP_PORT    53    /*  dns   */
#define DEF_TCP_PORT    80    /*  web   */
#define DEF_DCCP_PORT    DEF_START_PORT    /*  is it a good choice?...  */
#define DEF_RAW_PROT    253    /*  for experimentation and testing, rfc3692  */
#ifdef HAVE_OPENSSL3
#define DEF_QUIC_PORT 443

enum {
    QUIC_PRINT_DEST_RTT_ALL = 0,
    QUIC_PRINT_DEST_RTT_FIRST = 1,
    QUIC_PRINT_DEST_RTT_LAST = 2,
    QUIC_PRINT_DEST_RTT_SUM = 3
};

#endif

void error(const char *str) __attribute__((noreturn));
void error_or_perm(const char *str) __attribute__((noreturn));
void ex_error(const char *format, ...);

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

probe* probe_by_seq(int seq);
probe* probe_by_sk(int sk);
probe* probe_by_src_and_dest(sockaddr_any* src, sockaddr_any* dst, int check_source_addr);
probe* probe_by_seq_num(uint32_t seq_num);

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
uint16_t prepare_ancillary_data(int family, char* bufp, uint16_t inner_proto_hlen, struct msghdr* ret, sockaddr_any* offender);
int allowed_icmp(char* buf);

#define TR_MODULE(MOD)    \
static void __init_ ## MOD (void) __attribute__ ((constructor));    \
static void __init_ ## MOD (void) {    \
                \
    tr_register_module (&MOD);    \
}

#ifdef __APPLE__

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>

#define SALEN(sa) ((sa)->sa_len)
#define roundup(x, y)   ((((x)+((y)-1))/(y))*(y))

struct rtmsg {
    struct rt_msghdr rtmsg;
    uint8_t data[512];
};

const char* findsaddr(register const struct sockaddr_in *to, register struct sockaddr_in *from);

#endif 

