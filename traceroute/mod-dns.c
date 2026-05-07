/*
    Copyright(c)  2026   Alessandro Improta, Luca Sani, LogicMonitor
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <stdarg.h>
#include <stdint.h>
#include <sys/socket.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>

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
static unsigned int protocol = IPPROTO_UDP;

static uint8_t* data = NULL;
static size_t *length_p;
static int raw_icmp_sk = -1;
extern int use_additional_raw_icmp_socket;
extern int tr_via_additional_raw_icmp_socket;

#define DNS_HEADER_LEN 12
#define DNS_QCLASS_IN 1
#define DNS_QCLASS_CH 3
#define DNS_MAX_NAME_LEN 256
#define DNS_EXT_LEN 1024
#define DNS_TYPE_OPT 41
#define DNS_OPT_RECORD_LEN 11
#define DNS_OPT_UDP_PAYLOAD 4096
#define DNS_EDNS_DO 0x8000

typedef enum query_t {
    DNS_QUERY_A = 1,
    DNS_QUERY_NS = 2,
    DNS_QUERY_CNAME = 5,
    DNS_QUERY_SOA = 6,
    DNS_QUERY_PTR = 12,
    DNS_QUERY_MX = 15,
    DNS_QUERY_TXT = 16,
    DNS_QUERY_AAAA = 28,
    DNS_QUERY_DS = 43,
    DNS_QUERY_RRSIG = 46,
    DNS_QUERY_NSEC = 47,
    DNS_QUERY_DNSKEY = 48,
    DNS_QUERY_NSEC3 = 50,
    DNS_QUERY_NSEC3PARAM = 51,
    DNS_QUERY_CDS = 59,
    DNS_QUERY_CDNSKEY = 60,
} query_t;

static query_t dns_query = DNS_QUERY_A;
static char* dns_domain = NULL;
static uint8_t dns_qname[255] = {};
static size_t dns_qname_len = 0;

/*
 * Read a 16-bit integer from DNS network byte order.
 */
static uint16_t dns_get16(const uint8_t* p)
{
    return ((uint16_t)p[0] << 8) | p[1];
}

/*
 * Read a 32-bit integer from DNS network byte order.
 */
static uint32_t dns_get32(const uint8_t* p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/*
 * Return whether a query type needs the EDNS DNSSEC OK bit.
 *
 * See https://www.rfc-editor.org/rfc/rfc3225.html
 */
static int dns_query_wants_dnssec(query_t query)
{
    switch(query)
    {
        case DNS_QUERY_DS:
        case DNS_QUERY_RRSIG:
        case DNS_QUERY_NSEC:
        case DNS_QUERY_DNSKEY:
        case DNS_QUERY_NSEC3:
        case DNS_QUERY_NSEC3PARAM:
        case DNS_QUERY_CDS:
        case DNS_QUERY_CDNSKEY:
        {
            return 1;
        }
        default:
        {
            return 0;
        }
    }
}

/*
 * Append formatted text to a bounded output buffer.
 *
 * The current pointer is advanced on success and clamped before the final
 * byte when the formatted text is truncated.
 */
static int dns_appendf(char** curr, char* end, const char* fmt, ...)
{
    if(*curr >= end)
        return 0;

    size_t avail = (size_t)(end - *curr);

    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(*curr, avail, fmt, ap);
    va_end(ap);

    if(n < 0)
        return -1;

    if((size_t)n >= avail)
        *curr = end - 1;
    else
        *curr += n;

    return 0;
}

/*
 * Parse a DNS name from a message, including compressed names.
 *
 * The input offset starts at the encoded name and is updated to the byte after
 * the encoded name in its original location.
 */
static int dns_parse_name(const uint8_t* msg, size_t msg_len, size_t* off_p, char* out, size_t out_len)
{
    size_t off = *off_p; // where the name starts within the message
    size_t end_off = 0; // Where the last name ends
    size_t out_pos = 0;
    size_t jumps = 0;
    int jumped = 0;

    while(off < msg_len) {
        uint8_t label_len = msg[off++];
        if((label_len & 0xc0) == 0xc0) { // In this case the label value is found in another part of the response (see https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4)
            // The offset of the label is encoded into the next 14 bits, i.e. the least six significant bits of the label len and the next 8 bits
            size_t compressed_offset = ((size_t)(label_len & 0x3f) << 8) | msg[off++];

            // error either if the compressed_offset is outside the message or we are looping indefiitely
            // the second check is pedantic: detect loops in compression pointers, i.e. even if the compressed_offset is never outside the length we could be into an infinite loop, so we max it at msg_len
            if(compressed_offset >= msg_len || ++jumps > msg_len)
                return -1;

            // Update end_off so that even if we are parsing one name it is set properly
            // Note that we want to update it only the first time that we jump, because once jumped we are in anotehr part of the message but we want end_off to be where the last name ends into the queries
            if(!jumped) {
                end_off = off;
                jumped = 1;
            }

            off = compressed_offset; // Jump to the compressed label offset
            // At compressed_offset we will find another <label len> that could be again a compressed one or could be followed by an actual name
            // Note that once the compression starts, labels will continue to be encoded from that offset (i.e. we do not need to resume)
            continue;
        }

        if(label_len == 0) { // we reached the end of the current name
            if(!jumped) // If we jumped, end_off is already ok, otherwise record it
                end_off = off;
            break;
        }

        if(off + label_len > msg_len)
            return -1;

        if(out_pos) {
            if(out_pos + 1 >= out_len)
                return -1;
            out[out_pos++] = '.';
        }

        if(out_pos + label_len >= out_len)
            return -1;

        memcpy(out + out_pos, msg + off, label_len);
        out_pos += label_len;
        off += label_len;

        if(!jumped)
            end_off = off;
    }

    if(!out_pos) {
        if(out_len < 2)
            return -1;
        out[out_pos++] = '.';
    }
    out[out_pos] = '\0';
    *off_p = end_off;

    return 0;
}

/*
 * Return the presentation name for a DNS record type.
 *
 * Unknown types are formatted numerically into the caller-provided buffer.
 */
static const char* dns_type_name(uint16_t type, char* buf, size_t len)
{
    switch(type)
    {
        case DNS_QUERY_A:
        {
            return "A";
        }
        case DNS_QUERY_NS:
        {
            return "NS";
        }
        case DNS_QUERY_CNAME:
        {
            return "CNAME";
        }
        case DNS_QUERY_SOA:
        {
            return "SOA";
        }
        case DNS_QUERY_PTR:
        {
            return "PTR";
        }
        case DNS_QUERY_MX:
        {
            return "MX";
        }
        case DNS_QUERY_TXT:
        {
            return "TXT";
        }
        case DNS_QUERY_AAAA:
        {
            return "AAAA";
        }
        case DNS_QUERY_DS:
        {
            return "DS";
        }
        case DNS_TYPE_OPT:
        {
            return "OPT";
        }
        case DNS_QUERY_RRSIG:
        {
            return "RRSIG";
        }
        case DNS_QUERY_NSEC:
        {
            return "NSEC";
        }
        case DNS_QUERY_DNSKEY:
        {
            return "DNSKEY";
        }
        case DNS_QUERY_NSEC3:
        {
            return "NSEC3";
        }
        case DNS_QUERY_NSEC3PARAM:
        {
            return "NSEC3PARAM";
        }
        case DNS_QUERY_CDS:
        {
            return "CDS";
        }
        case DNS_QUERY_CDNSKEY:
        {
            return "CDNSKEY";
        }
        default:
        {
            snprintf(buf, len, "%u", type);
            return buf;
        }
    }
}

/*
 * Return the presentation name for a DNS class.
 *
 * Unknown classes are formatted numerically into the caller-provided buffer.
 */
static const char* dns_class_name(uint16_t class, char* buf, size_t len)
{
    if(class == DNS_QCLASS_IN)
        return "IN";
    else if(class == DNS_QCLASS_CH)
        return "CH";

    snprintf(buf, len, "%u", class);
    return buf;
}

/*
 * Append one DNS TXT character string with quoting and escaping.
 */
static int dns_append_txt_string(char** curr, char* end, const uint8_t* txt, size_t len)
{
    if(dns_appendf(curr, end, "\"") < 0)
        return -1;

    for(size_t i = 0; i < len; i++) {
        uint8_t c = txt[i];

        if(c == '"' || c == '\\') {
            if(dns_appendf(curr, end, "\\%c", c) < 0)
                return -1;
        } else if(c >= 0x20 && c <= 0x7e) {
            if(dns_appendf(curr, end, "%c", c) < 0)
                return -1;
        } else if(dns_appendf(curr, end, "\\x%02x", c) < 0) {
            return -1;
        }
    }

    return dns_appendf(curr, end, "\"");
}

/*
 * Append bytes as lowercase hexadecimal text.
 */
static int dns_append_hex(char** curr, char* end, const uint8_t* data, size_t len)
{
    for(size_t i = 0; i < len; i++)
        if(dns_appendf(curr, end, "%02x", data[i]) < 0)
            return -1;

    return 0;
}

/*
 * Format bytes as lowercase hexadecimal text.
 *
 * Empty data is represented as "-".
 */
static int dns_format_hex(const uint8_t* data, size_t len, char* out, size_t out_len)
{
    if(!out_len)
        return -1;

    char* curr = out;
    char* end = out + out_len;

    *curr = '\0';
    if(!len)
        return dns_appendf(&curr, end, "-");

    return dns_append_hex(&curr, end, data, len);
}

/*
 * Append bytes as base64 text.
 * This is mostly useful to encode DNSSEC-related keys as human readable strings.
 */
static int dns_append_base64(char** curr, char* end, const uint8_t* data, size_t len)
{
    static const char table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    for(size_t i = 0; i < len; i += 3) {
        uint32_t value = (uint32_t)data[i] << 16;
        char out[5] = {};

        if(i + 1 < len)
            value |= (uint32_t)data[i + 1] << 8;
        if(i + 2 < len)
            value |= data[i + 2];

        out[0] = table[(value >> 18) & 0x3f];
        out[1] = table[(value >> 12) & 0x3f];
        out[2] = (i + 1 < len) ? table[(value >> 6) & 0x3f] : '=';
        out[3] = (i + 2 < len) ? table[value & 0x3f] : '=';
        out[4] = '\0';

        if(dns_appendf(curr, end, "%s", out) < 0)
            return -1;
    }

    return 0;
}

/*
 * Format bytes using the DNSSEC base32hex alphabet.
 *
 * Empty data is represented as "-".
 */
static int dns_format_base32hex(const uint8_t* data, size_t len, char* out, size_t out_len)
{
    static const char table[] = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

    if(!out_len)
        return -1;

    char* curr = out;
    char* end = out + out_len;
    unsigned int value = 0;
    unsigned int bits = 0;

    *curr = '\0';
    if(!len)
        return dns_appendf(&curr, end, "-");

    for(size_t i = 0; i < len; i++) {
        value = (value << 8) | data[i];
        bits += 8;

        while(bits >= 5) {
            if(dns_appendf(&curr, end, "%c", table[(value >> (bits - 5)) & 0x1f]) < 0)
                return -1;
            bits -= 5;
        }
    }

    if(bits && dns_appendf(&curr, end, "%c", table[(value << (5 - bits)) & 0x1f]) < 0)
        return -1;

    return 0;
}

/*
 * Decode the type bitmap used by DNSSEC NSEC and NSEC3 records.
 *
 * See https://www.rfc-editor.org/rfc/rfc4034.html#section-4.1
 */
static int dns_format_type_bitmap(const uint8_t* bitmap, size_t bitmap_len, char* out, size_t out_len)
{
    if(!out_len)
        return -1;

    size_t off = 0;
    char* curr = out;
    char* end = out + out_len;
    int any = 0;

    *curr = '\0';
    while(off < bitmap_len) {
        if(bitmap_len - off < 2)
            return -1;

        uint8_t window = bitmap[off++];
        uint8_t len = bitmap[off++];

        if(len == 0 || len > 32 || len > bitmap_len - off)
            return -1;

        for(uint8_t i = 0; i < len; i++) {
            for(uint8_t bit = 0; bit < 8; bit++) {
                if(bitmap[off + i] & (0x80 >> bit)) {
                    uint16_t type = (uint16_t)window * 256 + (uint16_t)i * 8 + bit;
                    char type_buf[16] = {};
                    const char* type_name = dns_type_name(type, type_buf, sizeof(type_buf));

                    if(any && dns_appendf(&curr, end, " ") < 0)
                        return -1;

                    if(dns_appendf(&curr, end, "%s", type_name) < 0)
                        return -1;

                    any = 1;
                }
            }
        }

        off += len;
    }

    if(any == 0)
        return dns_appendf(&curr, end, "-");

    return 0;
}

/*
 * Format the RDATA payload of one DNS answer.
 *
 * The message pointer is the complete DNS response so compressed names inside RDATA can be resolved correctly.
 *
 * RDATA is a variable length string of octets that describes the resource.
 * The format of this information varies according to the TYPE and CLASS of the resource record.
 *
 * See https://www.rfc-editor.org/rfc/rfc1035.html#section-3.2.1
 */
static int dns_format_rdata(const uint8_t* msg, size_t msg_len, uint16_t type, size_t rdata_off, size_t rdlen, char* out, size_t out_len)
{
    if(!out_len)
        return -1;

    switch(type)
    {
        case DNS_QUERY_A:
        {
            if(rdlen != 4 || inet_ntop(AF_INET, msg + rdata_off, out, out_len) == 0)
                return -1;

            return 0;
        }
        case DNS_QUERY_AAAA:
        {
            if(rdlen != 16 || inet_ntop(AF_INET6, msg + rdata_off, out, out_len) == 0)
                return -1;

            return 0;
        }
        case DNS_QUERY_NS:
        case DNS_QUERY_CNAME:
        case DNS_QUERY_PTR:
        {
            size_t name_off = rdata_off;

            if(dns_parse_name(msg, msg_len, &name_off, out, out_len) < 0 || name_off > rdata_off + rdlen)
                return -1;

            return 0;
        }
        case DNS_QUERY_MX:
        {
            if(rdlen < sizeof(uint16_t))
                return -1;

            uint16_t preference = dns_get16(msg + rdata_off);
            size_t name_off = rdata_off + sizeof(uint16_t);
            char exchange[DNS_MAX_NAME_LEN] = {};

            if(dns_parse_name(msg, msg_len, &name_off, exchange, sizeof(exchange)) < 0 || name_off > rdata_off + rdlen)
                return -1;

            snprintf(out, out_len, "%u %s", preference, exchange);
            return 0;
        }
        case DNS_QUERY_TXT:
        {
            size_t off = rdata_off;
            size_t end_off = rdata_off + rdlen;

            if(!rdlen)
                return -1;

            char* curr = out;
            char* end = out + out_len;

            *curr = '\0';
            while(off < end_off) {
                uint8_t txt_len = msg[off++];

                if(txt_len > end_off - off)
                    return -1;

                if(curr != out && dns_appendf(&curr, end, " ") < 0)
                    return -1;

                if(dns_append_txt_string(&curr, end, msg + off, txt_len) < 0)
                    return -1;

                off += txt_len;
            }

            return 0;
        }
        case DNS_QUERY_DS:
        case DNS_QUERY_CDS:
        {
            if(rdlen < 4)
                return -1;

            uint16_t key_tag = dns_get16(msg + rdata_off);
            uint8_t algorithm = msg[rdata_off + 2];
            uint8_t digest_type = msg[rdata_off + 3];

            char digest[DNS_EXT_LEN] = {};
            if(dns_format_hex(msg + rdata_off + 4, rdlen - 4, digest, sizeof(digest)) < 0)
                return -1;

            snprintf(out, out_len, "%u %u %u %s", key_tag, algorithm, digest_type, digest);
            return 0;
        }
        case DNS_QUERY_DNSKEY:
        case DNS_QUERY_CDNSKEY:
        {
            if(rdlen < 4)
                return -1;

            uint16_t flags = dns_get16(msg + rdata_off);
            uint8_t protocol = msg[rdata_off + 2];
            uint8_t algorithm = msg[rdata_off + 3];

            char* curr = out;
            char* end = out + out_len;

            if(dns_appendf(&curr, end, "%u %u %u ", flags, protocol, algorithm) < 0)
                return -1;

            return dns_append_base64(&curr, end, msg + rdata_off + 4, rdlen - 4);
        }
        case DNS_QUERY_RRSIG:
        {
            if(rdlen < 18)
                return -1;

            uint16_t type_covered = dns_get16(msg + rdata_off);
            uint8_t algorithm = msg[rdata_off + 2];
            uint8_t labels = msg[rdata_off + 3];
            uint32_t original_ttl = dns_get32(msg + rdata_off + 4);
            uint32_t expiration = dns_get32(msg + rdata_off + 8);
            uint32_t inception = dns_get32(msg + rdata_off + 12);
            uint16_t key_tag = dns_get16(msg + rdata_off + 16);
            size_t name_off = rdata_off + 18;

            char signer[DNS_MAX_NAME_LEN] = {};
            if(dns_parse_name(msg, msg_len, &name_off, signer, sizeof(signer)) < 0 || name_off > rdata_off + rdlen)
                return -1;

            char* curr = out;
            char* end = out + out_len;
            char type_buf[16] = {};
            const char* type_name = dns_type_name(type_covered, type_buf, sizeof(type_buf));

            if(dns_appendf(&curr, end, "%s %u %u %u %u %u %u %s ", type_name, algorithm, labels, original_ttl, expiration, inception, key_tag, signer) < 0)
                return -1;

            return dns_append_base64(&curr, end, msg + name_off, rdata_off + rdlen - name_off);
        }
        case DNS_QUERY_NSEC:
        {
            char next_name[DNS_MAX_NAME_LEN] = {};
            char types[DNS_EXT_LEN] = {};
            size_t name_off = rdata_off;

            if(dns_parse_name(msg, msg_len, &name_off, next_name, sizeof(next_name)) < 0 || name_off > rdata_off + rdlen)
                return -1;

            if(dns_format_type_bitmap(msg + name_off, rdata_off + rdlen - name_off, types, sizeof(types)) < 0)
                return -1;

            snprintf(out, out_len, "%s %s", next_name, types);
            return 0;
        }
        case DNS_QUERY_NSEC3:
        {
            if(rdlen < 6)
                return -1;

            size_t off = rdata_off;
            size_t end_off = rdata_off + rdlen;
            uint8_t hash_algorithm = msg[off++];
            uint8_t flags = msg[off++];
            uint16_t iterations = dns_get16(msg + off);
            off += sizeof(uint16_t);
            uint8_t salt_len = msg[off++];

            if(salt_len > end_off - off)
                return -1;

            char salt[DNS_EXT_LEN] = {};
            if(dns_format_hex(msg + off, salt_len, salt, sizeof(salt)) < 0)
                return -1;
            off += salt_len;

            if(off >= end_off)
                return -1;

            uint8_t hash_len = msg[off++];
            if(hash_len > end_off - off)
                return -1;

            char next_hash[DNS_EXT_LEN] = {};
            if(dns_format_base32hex(msg + off, hash_len, next_hash, sizeof(next_hash)) < 0)
                return -1;
            off += hash_len;

            char types[DNS_EXT_LEN] = {};
            if(dns_format_type_bitmap(msg + off, end_off - off, types, sizeof(types)) < 0)
                return -1;

            snprintf(out, out_len, "%u %u %u %s %s %s", hash_algorithm, flags, iterations, salt, next_hash, types);
            return 0;
        }
        case DNS_QUERY_NSEC3PARAM:
        {
            if(rdlen < 5)
                return -1;

            size_t off = rdata_off;
            size_t end_off = rdata_off + rdlen;
            uint8_t hash_algorithm = msg[off++];
            uint8_t flags = msg[off++];
            uint16_t iterations = dns_get16(msg + off);
            off += sizeof(uint16_t);
            uint8_t salt_len = msg[off++];

            if(salt_len > end_off - off || salt_len != end_off - off)
                return -1;

            char salt[DNS_EXT_LEN] = {};
            if(dns_format_hex(msg + off, salt_len, salt, sizeof(salt)) < 0)
                return -1;

            snprintf(out, out_len, "%u %u %u %s", hash_algorithm, flags, iterations, salt);
            return 0;
        }
        default:
        {
            return -1;
        }
    }
}

/*
 * Parse DNS answers and return a formatted extension string.
 *
 * The caller owns the returned string. A NULL return means that no printable
 * answer data was found or the response could not be parsed.
 */
static char* dns_parse_answers(const uint8_t* buf, size_t len)
{
    const uint8_t* msg = buf;
 
    if(len < DNS_HEADER_LEN || !(msg[2] & 0x80)) // msg is too short or is not a dns response
        return NULL;

    size_t off = DNS_HEADER_LEN;
    uint16_t qdcount = dns_get16(msg + 4); // number of questions

    // Skip the questions since we are interested only in the answers
    // Example of question
    // Name: google.it
    // Type: NS (2) (authoritative Name Server)
    // Class: IN (0x0001)
    for(uint16_t i = 0; i < qdcount; i++) {
        char qname[DNS_MAX_NAME_LEN] = {};

        if(dns_parse_name(msg, len, &off, qname, sizeof(qname)) < 0) // Parse the name
            return NULL;

        if(off + 4 > len) // malformed response, there must be 4 other bytes: Type and Class
            return NULL;

        off += 4;
    }

    char ext[DNS_EXT_LEN] = {};
    char* curr = ext;
    char* end = ext + sizeof(ext);
    uint16_t ancount = dns_get16(msg + 6); // number of answers

    *curr = '\0';
    for(uint16_t i = 0; i < ancount; i++) {
        char name[DNS_MAX_NAME_LEN] = {};
        char rdata[DNS_EXT_LEN] = {};
        char type_buf[16] = {};
        char class_buf[8] = {};
        
        if(dns_parse_name(msg, len, &off, name, sizeof(name)) < 0 || off + 10 > len)
            return curr == ext ? NULL : strdup(ext);

        uint16_t type = dns_get16(msg + off);
        uint16_t class = dns_get16(msg + off + 2);
        uint32_t ttl = dns_get32(msg + off + 4);
        uint16_t rdlen = dns_get16(msg + off + 8);
        off += 10;

        if(off + rdlen > len)
            return curr == ext ? NULL : strdup(ext);

        size_t rdata_off = off;
        off += rdlen;

        if(dns_format_rdata(msg, len, type, rdata_off, rdlen, rdata, sizeof(rdata)) < 0)
            continue;

        const char* type_name = dns_type_name(type, type_buf, sizeof(type_buf));
        const char* class_name = dns_class_name(class, class_buf, sizeof(class_buf));

        if(curr != ext && dns_appendf(&curr, end, "; ") < 0)
            return curr == ext ? NULL : strdup(ext);

        if(dns_appendf(&curr, end, "%s,%s,%s,%u,%s", name, type_name, class_name, ttl, rdata) < 0)
            return curr == ext ? NULL : strdup(ext);
    }

    return curr == ext ? NULL : strdup(ext);
}

/*
 * Parse and store the query domain in DNS wire-format label encoding.
 */
static int set_dns_domain(CLIF_option* optn, char* arg)
{
    if(!arg || !*arg)
        ex_error("\nDNS domain is required");

    const char* label = arg;
    uint8_t* p = dns_qname;
    size_t qname_len = 0;

    while(*label) {
        const char* dot = strchr(label, '.');
        size_t label_len = dot ? (size_t)(dot - label) : strlen(label);

        if(label_len == 0) {
            if(*label == '.' && label[1] == '\0')
                break;

            ex_error("Malformed DNS domain `%s'", arg);
        }

        if(label_len > 63)
            ex_error("DNS label too long in `%s'", arg);

        if(qname_len + 1 + label_len + 1 > sizeof(dns_qname))
            ex_error("DNS domain too long `%s'", arg);

        *p++ = (uint8_t)label_len;
        memcpy(p, label, label_len);
        p += label_len;
        qname_len += 1 + label_len;

        if(!dot)
            break;

        label = dot + 1;
        if(!*label)
            break;
    }

    *p++ = 0;
    dns_qname_len = (size_t)(p - dns_qname);

    if(optn->data)
        *((char**)optn->data) = arg;
    else
        dns_domain = arg;

    return 0;
}

/*
 * Build the DNS query packet.
 */
static void fill_data(query_t query)
{
    if(!length_p)
        ex_error("DNS packet length pointer is not initialized");

    if(!dns_qname_len)
        ex_error("\nDNS domain is required");

    int use_dnssec = dns_query_wants_dnssec(query);
    size_t max_len = DNS_HEADER_LEN + dns_qname_len + sizeof(uint16_t) + sizeof(uint16_t);
    if(use_dnssec)
        max_len += DNS_OPT_RECORD_LEN;

    uint8_t* packet = malloc(max_len);
    if(!packet)
        error("malloc");

    memset(packet, 0, max_len);

    uint8_t* p = packet;
    uint16_t id = (uint16_t)random_seq();
    *p++ = (uint8_t)(id >> 8);
    *p++ = (uint8_t)id;                       /* ID */
    *p++ = 0x01;
    *p++ = 0x00;                              /* standard query, recursion desired */
    *p++ = 0x00;
    *p++ = 0x01;                              /* QDCOUNT */
    p += sizeof(uint16_t);                                      /* ANCOUNT */
    p += sizeof(uint16_t);                                      /* NSCOUNT */
    *p++ = 0x00;
    *p++ = use_dnssec ? 0x01 : 0x00;           /* ARCOUNT */

    memcpy(p, dns_qname, dns_qname_len);
    p += dns_qname_len;
    *p++ = (uint8_t)(((uint16_t)query) >> 8);
    *p++ = (uint8_t)query;
    *p++ = 0x00;
    *p++ = DNS_QCLASS_IN;

    if(use_dnssec) {
        *p++ = 0x00;                          /* root name */
        *p++ = 0x00;
        *p++ = DNS_TYPE_OPT;                  /* OPT */
        *p++ = (uint8_t)(DNS_OPT_UDP_PAYLOAD >> 8);
        *p++ = (uint8_t)DNS_OPT_UDP_PAYLOAD;
        *p++ = 0x00;                          /* extended RCODE */
        *p++ = 0x00;                          /* EDNS version */
        *p++ = (uint8_t)(DNS_EDNS_DO >> 8);
        *p++ = (uint8_t)DNS_EDNS_DO;          /* DNSSEC OK */
        *p++ = 0x00;
        *p++ = 0x00;                          /* RDLEN */
    }

    free(data);
    data = NULL;

    *length_p = (size_t)(p - packet);
    data = packet;
}

/*
 * Initialize DNS UDP probe state.
 */
static int dns_init(const sockaddr_any* dest, unsigned int port_seq, size_t* packet_len_p)
{
    if(!port_seq)  
        port_seq = DEF_DNS_PORT;

    dest_addr = *dest;
    dest_addr.sin.sin_port = htons(port_seq);
    
    length_p = packet_len_p;
    fill_data(dns_query);

    if(use_additional_raw_icmp_socket) {
        raw_icmp_sk = socket(dest_addr.sa.sa_family, SOCK_RAW, (dest_addr.sa.sa_family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6);
        
        if(raw_icmp_sk < 0)
            error_or_perm("raw icmp socket");
        
        add_poll(raw_icmp_sk, POLLIN | POLLERR);
    }
    
    return 0;
}

/*
 * Parse and store the requested DNS query type.
 */
static int set_dns_query(CLIF_option* optn, char* arg)
{
    if(!arg || !*arg)
        ex_error("DNS query type is required");

    if(strcasecmp(arg, "a") == 0)
        dns_query = DNS_QUERY_A;
    else if(strcasecmp(arg, "aaaa") == 0)
        dns_query = DNS_QUERY_AAAA;
    else if(strcasecmp(arg, "ns") == 0)
        dns_query = DNS_QUERY_NS;
    else if(strcasecmp(arg, "txt") == 0)
        dns_query = DNS_QUERY_TXT;
    else if(strcasecmp(arg, "ds") == 0)
        dns_query = DNS_QUERY_DS;
    else if(strcasecmp(arg, "rrsig") == 0)
        dns_query = DNS_QUERY_RRSIG;
    else if(strcasecmp(arg, "nsec") == 0)
        dns_query = DNS_QUERY_NSEC;
    else if(strcasecmp(arg, "dnskey") == 0)
        dns_query = DNS_QUERY_DNSKEY;
    else if(strcasecmp(arg, "nsec3") == 0)
        dns_query = DNS_QUERY_NSEC3;
    else if(strcasecmp(arg, "nsec3param") == 0)
        dns_query = DNS_QUERY_NSEC3PARAM;
    else if(strcasecmp(arg, "cds") == 0)
        dns_query = DNS_QUERY_CDS;
    else if(strcasecmp(arg, "cdnskey") == 0)
        dns_query = DNS_QUERY_CDNSKEY;
    else
        ex_error("Unsupported query type: %s", arg);

    return 0;
}

static CLIF_option dns_options[] = {
    { 0, "domain", "domain", "The domain to include into the query", set_dns_domain, &dns_domain, 0, 0 },
    { 0, "type", "type", "The type of the query (a, aaaa, ns, txt, ds, dnskey, rrsig, nsec, nsec3, nsec3param, cds, cdnskey)", CLIF_call_func, &set_dns_query, 0, 0 },
    CLIF_END_OPTION
};

/*
 * Send one UDP DNS probe and register its socket for replies.
 */
static void dns_udp_send_probe(probe* pb, int ttl)
{
    int af = dest_addr.sa.sa_family;

    int sk = socket(af, SOCK_DGRAM, protocol);
    if(sk < 0)
        error("socket");

    tune_socket(sk);    /*  common stuff   */

    set_ttl(sk, ttl);

    if(connect(sk, &dest_addr.sa, (af == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) < 0)
        error("connect");

    #ifndef __APPLE__
    use_recverr(sk);
    #endif

    pb->send_time = get_time();

    if(do_send(sk, data, *length_p, NULL) < 0) {
        close(sk);
        pb->send_time = 0;
        return;
    }

    pb->sk = sk;

    socklen_t len = sizeof(pb->src);
    if(getsockname(sk, &pb->src.sa, &len) < 0)
        error("getsockname");
        
    add_poll(sk, POLLIN | POLLERR);

    pb->seq = dest_addr.sin.sin_port;

    memcpy(&pb->dest, &dest_addr, sizeof(dest_addr));
}

/*
 * Match and parse a UDP DNS reply for a probe.
 */
static probe* dns_check_reply(int sk, int err, sockaddr_any* from, char* buf, size_t len) 
{
    probe* pb = probe_by_sk(sk);
    if(!pb)
        return NULL;

    if(pb->seq != from->sin.sin_port)
        return NULL;

    if(!err) {
        char* ext = dns_parse_answers((const uint8_t*)buf, len);

        pb->final = 1;
        if(ext) {
            free(pb->ext);
            pb->ext = ext;
        }
    }

    return pb;
}

/*
 * Receive DNS UDP probe events.
 */
static void dns_recv_probe(int sk, int revents) 
{
    if((revents & (POLLIN | POLLERR)))
        recv_reply(sk, !!(revents & POLLERR), dns_check_reply);
}

/*
 * Return whether a socket is the auxiliary raw ICMP socket for UDP DNS mode.
 */
static int dns_is_raw_icmp_sk(int sk)
{
    if(sk == raw_icmp_sk)
        return 1;

    return 0;
}

/*
 * Match a raw ICMP packet to the UDP DNS probe that triggered it.
 */
static probe* dns_handle_raw_icmp_packet(char* bufp, uint16_t* overhead, struct msghdr* response_get, struct msghdr* ret)
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

/*
 * Release DNS module buffers and sockets.
 */
static void dns_close()
{
    free(data);
    data = NULL;

    if(raw_icmp_sk >= 0)
        close(raw_icmp_sk);
}

/*  All three modules share the same methods except the init...  */

static tr_module dns_ops = {
    .name = "dns",
    .init = dns_init,
    .send_probe = dns_udp_send_probe,
    .recv_probe = dns_recv_probe,
    .header_len = sizeof(struct udphdr),
    .handle_raw_icmp_packet = dns_handle_raw_icmp_packet,
    .is_raw_icmp_sk = dns_is_raw_icmp_sk,
    .options = dns_options,
    .close = dns_close
};

TR_MODULE(dns_ops);
