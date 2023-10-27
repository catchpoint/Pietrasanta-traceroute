/*
    Copyright (c)  2023             Catchpoint Systems, Inc.    
    Copyright (c)  2023             Alessandro Improta, Luca Sani
                    <aimprota@catchpoint.com>    
                    <lsani@catchpoint.com>    
    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <stdlib.h>
#include <string.h>
#include <netinet/udp.h>
#include <unistd.h>
#include <sys/socket.h>
#include <poll.h>
#include <stdio.h>
#include "traceroute.h"

#define SUPPORTED_QUIC_VERSION 0x01
#define INITIAL_PACKET_LEN 1182
#define INITIAL_PACKET_PLAIN_PAYLOAD_LEN 1162
#define MAX_TOKEN_LEN 255
#define INITIAL_PACKET_HEADER_LEN (25 + MAX_TOKEN_LEN)
#define INITIAL_PACKET_BUFFER 2000 // It should be more than enough for an Initial packet received

static sockaddr_any dest_addr = {{ 0, }, };
static unsigned int curr_port = 0;
static unsigned int protocol = IPPROTO_UDP;
static int raw_icmp_sk = -1;
extern int use_additional_raw_icmp_socket; 
extern int ecn_input_value;

static uint8_t initial_packet_header[INITIAL_PACKET_HEADER_LEN];
// plain_payload and encrypted packets can be huge (65k) due to MTU discovery, thus we can't allocate on stack.
// Also, we need to keep separated the payload from the encrypted packet because encryption will be called so having source and dest in the same space may produce unwanted behavior
static uint8_t* encrypted_packet = NULL;
static uint8_t* initial_payload = NULL;
static size_t init_packets_len = 0;
static size_t* length_p = NULL;
static uint32_t packet_number = 0;

// This is a fixed value for QUIC version 1, see https://www.rfc-editor.org/rfc/rfc9001#section-5.2-2
static uint8_t initial_salt[] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

// The following are the keys used by quic to peform encryption/header protection of the Initial packet, see https://www.rfc-editor.org/rfc/rfc9001#section-5.1
static uint8_t initial_secret[32];
// client keys
static uint8_t client_initial_secret[32];
static uint8_t client_key[16];
static uint8_t client_iv[12];
static uint8_t client_hp[16];
// server keys
static uint8_t server_initial_secret[32];
static uint8_t server_key[16];
static uint8_t server_iv[12];
static uint8_t server_hp[16];

enum { // These are the only QUIC packets we care of
    QUIC_INITIAL_PACKET = 0x00,
    QUIC_RETRY_PACKET = 0x03
};

// CRYPTO frame that we use when sending our Initial QUIC packet
/*
    Frame Type: CRYPTO (0x0000000000000006)
    Offset: 0
    Length: 254
    Crypto Data
    TLSv1.3 Record Layer: Handshake Protocol: Client Hello
        Handshake Protocol: Client Hello
            Handshake Type: Client Hello (1)
            Length: 250
            Version: TLS 1.2 (0x0303)
            Random: eb1b7857000fc37e6cdca3dae6cdafb9a7f569d9ad0c3c8a26cfdb180d05ee9c
            Session ID Length: 0
            Cipher Suites Length: 6
            Cipher Suites (3 suites)
            Compression Methods Length: 1
            Compression Methods (1 method)
                Compression Method: null (0)
            Extensions Length: 203
            Extension: quic_transport_parameters (len=49)
            Extension: ec_point_formats (len=4)
            Extension: supported_groups (len=22)
            Extension: session_ticket (len=0)
            Extension: application_layer_protocol_negotiation (len=5)
            Extension: encrypt_then_mac (len=0)
            Extension: extended_master_secret (len=0)
            Extension: signature_algorithms (len=36)
            Extension: supported_versions (len=3)
            Extension: psk_key_exchange_modes (len=2)
            Extension: key_share (len=38)
            [JA3 Fullstring: 771,4866-4867-4865,57-11-10-35-16-22-23-13-43-45-51,29-23-30-25-24-256-257-258-259-260,0-1-2]
            [JA3: 8b96fe2742f06edd57eec86e77806b0a]
*/
static uint8_t crypto[] = { // from byte-index 10 there is the "random" for 32 bytes
0x06, 0x00, 0x40, 0xfe, 0x01, 0x00, 0x00, 0xfa, 0x03, 0x03, 0xeb, 0x1b, 0x78, 0x57, 0x00, 0x0f,
0xc3, 0x7e, 0x6c, 0xdc, 0xa3, 0xda, 0xe6, 0xcd, 0xaf, 0xb9, 0xa7, 0xf5, 0x69, 0xd9, 0xad, 0x0c,
0x3c, 0x8a, 0x26, 0xcf, 0xdb, 0x18, 0x0d, 0x05, 0xee, 0x9c, 0x00, 0x00, 0x06, 0x13, 0x02, 0x13,
0x03, 0x13, 0x01, 0x01, 0x00, 0x00, 0xcb, 0x00, 0x39, 0x00, 0x31, 0x0c, 0x00, 0x0f, 0x00, 0x01,
0x04, 0x80, 0x00, 0x75, 0x30, 0x03, 0x02, 0x44, 0xb0, 0x0e, 0x01, 0x02, 0x04, 0x04, 0x80, 0x20,
0x00, 0x00, 0x05, 0x04, 0x80, 0x20, 0x00, 0x00, 0x06, 0x04, 0x80, 0x20, 0x00, 0x00, 0x07, 0x04,
0x80, 0x20, 0x00, 0x00, 0x08, 0x02, 0x40, 0x64, 0x09, 0x02, 0x40, 0x64, 0x00, 0x0b, 0x00, 0x04,
0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00, 0x16, 0x00, 0x14, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e,
0x00, 0x19, 0x00, 0x18, 0x01, 0x00, 0x01, 0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x23,
0x00, 0x00, 0x00, 0x10, 0x00, 0x05, 0x00, 0x03, 0x02, 0x68, 0x33, 0x00, 0x16, 0x00, 0x00, 0x00,
0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x24, 0x00, 0x22, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x08,
0x07, 0x08, 0x08, 0x08, 0x1a, 0x08, 0x1b, 0x08, 0x1c, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08,
0x04, 0x08, 0x05, 0x08, 0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x00, 0x2b, 0x00, 0x03, 0x02,
0x03, 0x04, 0x00, 0x2d, 0x00, 0x02, 0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d,
0x00, 0x20, 0x14, 0x39, 0xbf, 0x7d, 0x5f, 0xc8, 0xde, 0xce, 0x49, 0xdb, 0xf9, 0xc0, 0xfa, 0xc8,
0x39, 0x7b, 0xba, 0x58, 0x2c, 0xef, 0xeb, 0x10, 0x67, 0x00, 0xac, 0x02, 0x7c, 0x9e, 0xef, 0xa9,
0xf6, 0x66
};

// CONNECTION_CLOSE frame https://www.rfc-editor.org/rfc/rfc9000#name-connection_close-frames
// This is a connection close containing APPLICATION_ERROR (https://www.rfc-editor.org/rfc/rfc9000#section-20.1-2.26.1)
static uint8_t connection_close[] = {0x1c, 0x0c, 0x00, 0x00};

enum { // These are the only QUIC frames that can be found into an Initial QUIC packet according to https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4-6
    PADDING = 0x00,
    PING = 0x01,
    ACK = 0x02,
    ACK_ECN = 0x03,
    CRYPTO = 0x06,
    CONNECTION_CLOSE = 0x1c // https://www.rfc-editor.org/rfc/rfc9000.html#section-12.4-11.10.1 
};

/* https://www.rfc-editor.org/rfc/rfc9000.html#name-initial-packet
Initial Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2) = 0,
  Reserved Bits (2),
  Packet Number Length (2),
  Version (32),
  Destination Connection ID Length (8),
  Destination Connection ID (0..160),
  Source Connection ID Length (8),
  Source Connection ID (0..160),
  Token Length (i),
  Token (..),
  Length (i),
  Packet Number (8..32),
-------------------------------------------Header ends here
  Packet Payload (8..),
}
*/

enum {
    DCID_LEN_OFFSET = 5,
    DCID_OFFSET = 6
};

void init_quic_header()
{
    memset(initial_packet_header, 0, sizeof(initial_packet_header));
    
    initial_packet_header[0] |= 0x80; // Long header
    initial_packet_header[0] |= 0x40; // Fixed bit is always 1 (https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-3.4.1)
    // 2 bits packet type is already already 0 (which is exactly the Initial packet type)
    // 2 bits Reserved are already implicitly 0 and need to be zero (https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-8.2.1)
    initial_packet_header[0] |= 0x03; // We know that we are using Packet numbers on four bytes so we must put 3 here (https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2-8.4.1)
    initial_packet_header[4] = SUPPORTED_QUIC_VERSION; // QUIC version is 1 (note that bytes[1, 2, 3] are already zero)
    // Leave all the rest to zero. Will be filled when needed
}

size_t fill_quic_header(uint8_t* dcid, uint8_t dcid_len, uint32_t pn, const uint8_t* token, size_t token_len, size_t* encrypted_payload_len)
{
    // Here assume Token Len encoded on one byte and equal to zero
    size_t header_len = 16; // First byte + Version (4 bytes) + DCID len (1 byte) + SCID len (1 byte) + Token Len (1 byte) + Length (4 bytes) + Packet number (4 bytes)
    header_len += dcid_len;
    
    if(token_len > MAX_TOKEN_LEN)
        ex_error("Token length %u bytes not supported\n", token_len);
    
    // Write the DCID
    initial_packet_header[DCID_LEN_OFFSET] = dcid_len;
    memcpy(&initial_packet_header[DCID_OFFSET], dcid, dcid_len);
    
    // Now need to write the token (if present)
    uint8_t token_len_offset = 7 + dcid_len; // First byte + Version (4 bytes) + DCID len (1 bytes) + SCID len (1 bytes) =  7 bytes
    uint8_t* tl_ptr = &initial_packet_header[token_len_offset];
    uint8_t* field_len_ptr = tl_ptr + 1; // pointer to the Length field. If the token is present, we will need to move it
    
    if(token_len > 0) {
        if(token_len <= 63) { // If the Token Len fits on 1 byte according to VLE, use 1 byte (https://www.rfc-editor.org/rfc/rfc9000.html#name-summary-of-integer-encoding)
            *tl_ptr = token_len;
            memcpy(&initial_packet_header[token_len_offset + 1], token, token_len);
            header_len += token_len;
            field_len_ptr += token_len;
        } else { // Otherwise use two bytes
            *((uint16_t*)tl_ptr) = htons(0x4000 | token_len); // use VLE
            memcpy(&initial_packet_header[token_len_offset + 2], token, token_len);
            // The "extra 1" is the additional byte needed to encode the Token Len
            header_len += (1 + token_len);
            field_len_ptr += (1 + token_len);
        }
    }
    
    // We need to fill the four-bytes length with a proper value
    // The global length_p is the length of the protected+encrypted QUIC packet (thus header + encrypted payload)
    // The Length field must report the length of the encrypted packet only plus the four bytes packet number (which is included into header_len)
    *encrypted_payload_len = *length_p - header_len + 4;
    *((uint32_t*)field_len_ptr) = htonl(0x80000000 | *encrypted_payload_len); // Use VLE
    
    // Write the packet number
    uint8_t* pn_ptr = (uint8_t*)field_len_ptr + 4;
    *((uint32_t*)pn_ptr) = htonl(pn);
    
    return header_len;
}

// Applies AES-ECB on the given sample using the given hp key
// The sample should be the first 16 bytes of the encrypted packet
// See https://www.rfc-editor.org/rfc/rfc9001#section-a.2-6
// https://www.rfc-editor.org/rfc/rfc9001#section-5.4.3
static void get_protection_header_mask(uint8_t* sample, size_t sample_len, unsigned char* hp, unsigned char *mask)
{
    EVP_CIPHER_CTX *ctx;
    if(!(ctx = EVP_CIPHER_CTX_new()))
        error("EVP_CIPHER_CTX_new");
    
    if(EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, hp, NULL) != 1)
        error("EVP_EncryptInit_ex");
   
    int len = 0;

    char ciphertext[128];
    if(EVP_EncryptUpdate(ctx, (unsigned char *)ciphertext, &len, (const unsigned char *)sample, sample_len) != 1)
        error("EVP_EncryptUpdate");
    
    int ciphertext_len = len;

    if(EVP_EncryptFinal_ex(ctx, (unsigned char *)(ciphertext + len), &len) != 1)
        error("EVP_EncryptFinal_ex");

    ciphertext_len += len;

    int i;
    for(i = 0; i < 5; ++i)
        mask[i] = ciphertext[i];
    
    EVP_CIPHER_CTX_free(ctx);
}

// This is how the header protection of QUIC packets is performed
// The mask is generated starting from a sample (see get_protection_header_mask)
// Note that packet numbers is long and short headers are encoded between 1 and 4 bytes (https://www.rfc-editor.org/rfc/rfc9000#section-12.3-2) thus we are sure that we are not going over the bound of mask 
// See also https://www.rfc-editor.org/rfc/rfc9001#section-a.2-6
static void protect_header(uint8_t* header, const uint8_t* mask, uint8_t* pn_ptr, size_t pn_length)
{
    header[0] ^= mask[0] & 0x0f;
    for(int i = 1, hi = 0; i <= pn_length; i++, hi++)
        pn_ptr[hi] ^= mask[i];
}

// Note that packet numbers is long and short headers are encoded between 1 and 4 bytes (https://www.rfc-editor.org/rfc/rfc9000#section-12.3-2) thus we are sure that we are not going over the bound of mask
// https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.1-3
static size_t unprotect_header(uint8_t* header, const uint8_t* mask, uint8_t* pn_ptr)
{
    header[0] ^= mask[0] & 0x0f;
    int i = 0;
    int hi = 0;
    
    size_t pn_length = (header[0] & 0x03) + 1; // https://www.rfc-editor.org/rfc/rfc9000#section-17.2-8.4.1
    
    for(i = 1, hi = 0; i <= pn_length; i++, hi++)
        pn_ptr[hi] ^= mask[i];
        
    return pn_length;
}

// Implements HKDF-Extract (see https://www.rfc-editor.org/rfc/rfc5869#section-2.2)
static int hkdf_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t *out, size_t out_len)
{  
    int mode = EVP_PKEY_HKDEF_MODE_EXTRACT_ONLY;
    
    OSSL_PARAM params[7];
    OSSL_PARAM* p = params;
    
    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, "SHA2-256", 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, (unsigned char *)salt, salt_len);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (unsigned char *)ikm, ikm_len);
    *p++ = OSSL_PARAM_construct_end();

    OSSL_LIB_CTX* libctx = OSSL_LIB_CTX_new();
    EVP_KDF *kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_HKDF, NULL);
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    
    int ret = EVP_KDF_derive(kctx, out, out_len, params);

    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    OSSL_LIB_CTX_free(libctx);

    return ret;
}

// Implements HKDF-Expand-Label (see https://www.rfc-editor.org/rfc/rfc8446.html#section-7.1)
int hkdf_expand_label(const uint8_t* secret, const char* label, size_t labellen, uint8_t *out, size_t outlen)
{
    OSSL_LIB_CTX* libctx = OSSL_LIB_CTX_new();

    const char* data = NULL;
    size_t datalen = 0;
    
    EVP_MD* sha256 = EVP_MD_fetch(libctx, "SHA256", NULL);
    EVP_KDF* kdf = EVP_KDF_fetch(libctx, OSSL_KDF_NAME_TLS1_3_KDF, NULL);
    
    OSSL_PARAM params[7]; 
    OSSL_PARAM* p = params;
    
    int mode = EVP_PKEY_HKDEF_MODE_EXPAND_ONLY;
    const char *mdname = EVP_MD_get0_name(sha256);
    
    EVP_KDF_CTX* kctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    if(kctx == NULL)
        return 0;
    
    int ret = EVP_MD_get_size(sha256);
    size_t hashlen = (size_t)ret;
    
    // This is ASCII for "tls13 " (note that the the space at the end is needed)
    static const unsigned char label_prefix[] = "\x74\x6C\x73\x31\x33\x20";

    *p++ = OSSL_PARAM_construct_int(OSSL_KDF_PARAM_MODE, &mode);
    *p++ = OSSL_PARAM_construct_utf8_string(OSSL_KDF_PARAM_DIGEST, (char *)mdname, 0);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_KEY, (unsigned char *)secret, hashlen);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PREFIX, (unsigned char *)label_prefix, sizeof(label_prefix) - 1);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_LABEL, (unsigned char *)label, labellen);
    
    if(data != NULL)
        *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_DATA, (unsigned char *)data, datalen);
    *p++ = OSSL_PARAM_construct_end();

    ret = EVP_KDF_derive(kctx, out, outlen, params) <= 0;
    
    EVP_KDF_CTX_free(kctx);
    OSSL_LIB_CTX_free(libctx);
    EVP_MD_free(sha256);
    
    if(ret != 0)
        ex_error("hkdf_expand_label");
    
    return ret;
}

// Generate the nonce to be used in encryption/decryption of the packet payload
// "The 62 bits of the reconstructed QUIC packet number in network byte order are left-padded with zeros to the size of the IV. The exclusive OR of the padded packet number and the IV forms the AEAD nonce" (https://www.rfc-editor.org/rfc/rfc9001#section-5.3-5)
// With an input of iv[] = {0xdc, 0x82, 0x45, 0xb0, 0xc9, 0xd8, 0x66, 0x46, 0xaa, 0x98, 0x03, 0xae}; and pn = 1 the expected output is
//                 nonce = {0xdc, 0x82, 0x45, 0xb0, 0xc9, 0xd8, 0x66, 0x46, 0xaa, 0x98, 0x03, 0xaf}
// Inspired from code in openssl qtx_encrypt_into_txe@quic_record_tx.c
// pn is the packet number in *host* endiannes
// Note that the packet number is taken as an eight-byte integer: if it is actually smaller, "automatic" padding is done
static void generate_nonce(const uint8_t* iv, uint64_t pn, uint8_t* nonce, uint8_t nonce_len)
{
    memcpy(nonce, iv, nonce_len);
    for(int i = 0; i < sizeof(pn); ++i)
        nonce[nonce_len - i - 1] ^= (uint8_t)(pn >> (i * 8));
}

// Applies AEAD_AES_GCM_128 encryption algorithm (the one used to encrypt the payload of an Initial packet)
// The tag need to be appended to the ciphertext: See https://www.rfc-editor.org/rfc/rfc5116#section-5.1
// "The AEAD_AES_128_GCM ciphertext is formed by appending the authentication tag provided as an output to the GCM encryption operation to the ciphertext that is output by that operation."
// From same RFC: An AEAD_AES_128_GCM ciphertext is exactly 16 octets longer than its corresponding plaintext.
// The following code is inspired from https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
int aead_aes_gcm_128_encrypt(const uint8_t* plaintext, int plaintext_len, const uint8_t* aad, int aad_len, const uint8_t* key, const uint8_t* iv, int iv_len, uint8_t* ciphertext)
{
    EVP_CIPHER_CTX *ctx = NULL;

    int len = 0;
    int ciphertext_len = 0;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        error("aead_aes_gcm_128_encrypt: EVP_CIPHER_CTX_new");

    if(EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL) != 1)
        error("aead_aes_gcm_128_encrypt: EVP_EncryptInit_ex");

    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL) != 1)
         error("aead_aes_gcm_128_encrypt: EVP_CIPHER_CTX_ctrl (EVP_CTRL_GCM_SET_IVLEN)");

    if(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
         error("aead_aes_gcm_128_encrypt: EVP_EncryptInit_ex");

    // Provide the additional data
    if(EVP_EncryptUpdate(ctx, NULL, &ciphertext_len, aad, aad_len) != 1)
        error("aead_aes_gcm_128_encrypt: EVP_EncryptUpdate");

    if(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) != 1)
        error("aead_aes_gcm_128_encrypt: EVP_EncryptUpdate");
    
    ciphertext_len = len;

    if(EVP_EncryptFinal_ex(ctx, ciphertext + len, &ciphertext_len) != 1)
        error("aead_aes_gcm_128_encrypt: EVP_EncryptFinal_ex");

    ciphertext_len += len;
    
    uint8_t tag[16]; // The length of the tag is 16 bytes (https://www.rfc-editor.org/rfc/rfc5116.html#section-5.3)
    
    // Get the tag
    if(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) != 1)
       error("aead_aes_gcm_128_encrypt: EVP_CIPHER_CTX_ctrl (EVP_CTRL_AEAD_GET_TAG)");

    memcpy(ciphertext + plaintext_len, tag, 16); // Append the tag to the ciphertext

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

// Applies AEAD_AES_GCM_128 decryption algorithm (the one used to decrypt the payload of an Initial packet)
// The following code is inspired from https://wiki.openssl.org/index.php/EVP_Authenticated_Encryption_and_Decryption
int aead_aes_gcm_128_decrypt(const uint8_t* ciphertext, int ciphertext_len, const uint8_t* aad, int aad_len, uint8_t* tag, const uint8_t* key, const uint8_t* iv, int iv_len, uint8_t* plaintext)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int plaintext_len = 0;
    int ret = 0;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        error("aead_aes_gcm_128_decrypt: EVP_CIPHER_CTX_new");

    if(!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL))
        error("aead_aes_gcm_128_decrypt: EVP_aes_256_gcm");

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL))
        error("aead_aes_gcm_128_decrypt: EVP_CIPHER_CTX_ctrl");

    if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        error("aead_aes_gcm_128_decrypt: EVP_DecryptInit_ex");

    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        error("aead_aes_gcm_128_decrypt: EVP_DecryptUpdate");

    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
       error("aead_aes_gcm_128_decrypt: EVP_DecryptUpdate");
    plaintext_len = len;

    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
        error("aead_aes_gcm_128_decrypt: EVP_CIPHER_CTX_ctrl");

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if(ret > 0) {
        plaintext_len += len;
        return plaintext_len;
    }
    
    return -1;
}

static void get_dcid(uint8_t* dcid, uint8_t dcid_len)
{
    OSSL_LIB_CTX* libctx = OSSL_LIB_CTX_new();
    
    if(RAND_bytes_ex(libctx, dcid, dcid_len, dcid_len * 8) != 1) // Inspired from openssl gen_rand_conn_id@quic_channel.c
        error("RAND_bytes_ex");
    
    OSSL_LIB_CTX_free(libctx);
}

// These secrets are generated as specified in https://www.rfc-editor.org/rfc/rfc9001.html#section-a.1-5
static void generate_secrets(uint8_t* cid, uint8_t cid_len)
{
    hkdf_extract(initial_salt, sizeof(initial_salt), cid, cid_len, initial_secret, sizeof(initial_secret));
    hkdf_expand_label(initial_secret, "client in", strlen("client in"), client_initial_secret, sizeof(client_initial_secret));
    hkdf_expand_label(client_initial_secret, "quic key", strlen("quic key"), client_key, sizeof(client_key));
    hkdf_expand_label(client_initial_secret, "quic iv", strlen("quic iv"), client_iv, sizeof(client_iv));
    hkdf_expand_label(client_initial_secret, "quic hp", strlen("quic hp"), client_hp, sizeof(client_hp));
    
    hkdf_expand_label(initial_secret, "server in", strlen("server in"), server_initial_secret, sizeof(server_initial_secret));
    hkdf_expand_label(server_initial_secret, "quic key", strlen("quic key"), server_key, sizeof(server_key));
    hkdf_expand_label(server_initial_secret, "quic iv", strlen("quic iv"), server_iv, sizeof(server_iv));
    hkdf_expand_label(server_initial_secret, "quic hp", strlen("quic hp"), server_hp, sizeof(server_hp));
}

// A note about the lengths involved.
// The final protected and encrypted "quic Initial packet" need to be at least 1200 bytes (https://www.rfc-editor.org/rfc/rfc9000#section-8.1-5)
// (Note that an Initial packet has the long header)
// The long header packet is 24 bytes. This leaves 1176 bytes for the encrypted payload.
// Since the encrypted payload is 16 bytes longer than the plain payload, this leaves 1160 bytes for the plain payload.
// Those 1160 bytes will host the given quic frame (e.g. CRYPTO), which is much less than 1160 bytes, followed by a PADDING frame (all zeros) to get to 1160 bytes
// The length into the header needs to take in consideration *also* the four bytes packet number, thus the encoded length is 1176+4 = 1180 bytes.
// Since we need to accomodate the p;ossibility to do MTU, we must do these calculations on the basis of the provided length_p.
// Keep in mind that the length_p will be the length of the whole protected+encrypted QUIC Initial packet, but the encoded length need to take in consideration only the encrypted_packet len (auth tag included) plus the four bytes packet number
void generate_quic_initial_packet(uint8_t* dcid, uint8_t dcid_len, uint8_t* frame, size_t frame_len, uint8_t* retry_token, size_t retry_token_len, int gen_secrets)
{
    size_t encrypted_payload_len = 0;
    init_quic_header();
    size_t header_len = fill_quic_header(dcid, dcid_len, packet_number, retry_token, retry_token_len, &encrypted_payload_len);
    size_t plain_payload_len = *length_p - header_len - 16;
    
    memset(initial_payload, 0, init_packets_len); // "Implicit" PADDING
    memcpy(initial_payload, frame, frame_len);
    memset(encrypted_packet, 0, init_packets_len);
    
    // Now protect the packet... and then it is ready to be sent
    
    // 1) Generate the needed secrets
    if(gen_secrets)
        generate_secrets(dcid, dcid_len);
    
    // 2) Encrypt the payload with AEAD_AES_128_GCM (https://www.rfc-editor.org/rfc/rfc9001#section-5-3.3)
    // 2.1) We need to provide the associated data
    // The associated data is the contents of the QUIC header, starting from the first byte of either the short or long header, up to and including the unprotected packet number (https://www.rfc-editor.org/rfc/rfc9001.html#section-5.3-6)
    uint8_t* associated_data = (uint8_t*)initial_packet_header;
    size_t associated_data_len = header_len;
    
    // 2.2) Instead of using the generated IV, we need to use a nonce generated from a combination of the IV and the packet_number
    // https://www.rfc-editor.org/rfc/rfc9001.html#section-5.3-5
    uint8_t nonce[sizeof(client_iv)];
    uint8_t nonce_len = sizeof(nonce);
    generate_nonce(client_iv, packet_number, nonce, nonce_len);
    
    // 2.3) Encrpyt the packet payload
    // Note that we now that the encrypted payload is 16 bytes longer than the plain payload (https://www.rfc-editor.org/rfc/rfc5116.html#section-5.1).
    // We put the encrypted payload directly after the quic header
    aead_aes_gcm_128_encrypt(initial_payload, plain_payload_len, associated_data, associated_data_len, client_key, nonce, nonce_len, encrypted_packet+header_len);
    
    // 3) Protect the quic packet header
    // The protection of the header is done using a "mask" obtained from a sample of the encrypted payload
    // Since where we are encrypting only Initial packets (i.e. encrypting with AEAD_AES_128_GCM), the sample used are the first 16 bytes of the encrypted payload (https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.3)
    // See also https://www.rfc-editor.org/rfc/rfc9001.html#section-a.2-5
    uint8_t mask[5]; // The mask is composed by five-bytes (https://www.rfc-editor.org/rfc/rfc9001#section-5.4.1-2)
    uint8_t* sample = encrypted_packet + header_len;
    size_t sample_len = 16;  
    get_protection_header_mask(sample, sample_len, client_hp, mask);
    
    memcpy(encrypted_packet, initial_packet_header, header_len);
    protect_header(encrypted_packet, mask, encrypted_packet + header_len - sizeof(uint32_t), sizeof(uint32_t));
    
    packet_number++;
}

static int quic_init(const sockaddr_any* dest, unsigned int port, size_t* packet_len_p) 
{
    if(port) 
        curr_port = port;
    else
        curr_port = DEF_QUIC_PORT;
    
    dest_addr = *dest;
    dest_addr.sin.sin_port = htons(curr_port);

    if(use_additional_raw_icmp_socket) {
        raw_icmp_sk = socket(dest_addr.sa.sa_family, SOCK_RAW, (dest_addr.sa.sa_family == AF_INET) ? IPPROTO_ICMP : IPPROTO_ICMPV6);
        
        if(raw_icmp_sk < 0)
            error_or_perm("raw icmp socket");
        
        add_poll(raw_icmp_sk, POLLIN | POLLERR);
    }
    
    length_p = packet_len_p;
    
    initial_payload = calloc(1, *length_p);
    if(!initial_payload)
        error("calloc");
    encrypted_packet = calloc(1, *length_p); 
    if(!encrypted_packet)
        error("calloc");

    init_packets_len = *length_p;
    
    return 0;
}

static void quic_send_probe(probe* pb, int ttl) 
{
    int sk;
    int af = dest_addr.sa.sa_family;

    sk = socket(af, SOCK_DGRAM, protocol);
    if(sk < 0)
        error("socket");

    tune_socket(sk);    /*  common stuff   */

    set_ttl(sk, ttl);

    if(connect(sk, &dest_addr.sa, sizeof(dest_addr)) < 0)
        error("connect");

    use_recverr(sk);

    uint8_t dcid[8]; // We arbitrarily use an 8 byte dcid
    memset(dcid, 0, sizeof(dcid));
    get_dcid(dcid, sizeof(dcid));
    generate_quic_initial_packet(dcid, sizeof(dcid), crypto, sizeof(crypto), NULL, 0, 1);
    
    // save the dcid so we can re-generate the secrets if and when we receive the Initial packet from the server
    memcpy(pb->dcid, dcid, sizeof(dcid));
    pb->dcid_len = sizeof(dcid);
    pb->send_time = get_time();
    if(do_send(sk, (uint8_t*)encrypted_packet, *length_p, NULL) < 0) {
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

static uint8_t get_vlint_size(uint8_t buf)
{
    return 1 << (buf >> 6);
}
        
static uint8_t get_vlint1(uint8_t* buf)
{
    return buf[0];
}

static uint16_t get_vlint2(uint8_t* buf)
{
    uint16_t ret = *((uint16_t*)buf);
    *((uint8_t*)&ret) &= 0x3f;
    return ntohs(ret);
}

static uint32_t get_vlint4(uint8_t* buf)
{
    uint32_t ret = *((uint32_t*)buf);
    *((uint8_t*)&ret) &= 0x3f;
    return ntohl(ret);
}

static uint64_t get_vlint8(uint8_t* buf)
{
    uint64_t ret = *((uint64_t*)buf);
    *((uint8_t*)&ret) &= 0x3f;
    return be64toh(ret);
}

size_t get_vlint(uint8_t* buf, uint8_t* len_size)
{
    uint8_t tmp = 0;
    if(len_size == NULL)
        len_size = &tmp;
    
    *len_size = get_vlint_size(buf[0]); 
    switch(*len_size)
    {
        case 1:
        {
            return get_vlint1(buf);
        }
        case 2:
        {
            return get_vlint2(buf);
        }
        case 4:
        {
            return get_vlint4(buf);
        }
        case 8:
        {
            return get_vlint8(buf);
        }
        default:
        {
            ex_error("Got an impossible vlint size\n");
        }
    }
    
    return 0;
}


static probe* quic_check_reply(int sk, int err, sockaddr_any* from, char* buf, size_t len) 
{
    probe* pb = probe_by_sk(sk);
    if(!pb)
        return NULL;

    if(pb->seq != from->sin.sin_port)
        return NULL;

    if(!err) { 
        pb->final = 1;
        
        uint8_t server_scid[MAX_QUIC_ID_LEN];
        memset(server_scid, 0, MAX_QUIC_ID_LEN);
        uint8_t server_scid_len = 0;
            
        uint8_t packet_type = (buf[0] & 0x30) >> 4;
        // If a Retry packet was received, we need to take the token and send another Initial packet with that token included
        // Retry packet format: https://www.rfc-editor.org/rfc/rfc9000.html#name-retry-packet
        if(packet_type == QUIC_RETRY_PACKET) {
            // the "len" argument is the length of the QUIC retry packet
            // thus we can infer the Token length (which is not specified by other means)
            // keep in mind that Retry packets do not have header protection (nor any payload to encrypt) https://www.rfc-editor.org/rfc/rfc9001#section-5.4-4
            uint8_t* ptr = (uint8_t*)buf + 5; // skip first byte and QUIC version
            uint8_t dcid_len = *ptr;
            ptr += 1; // skip DCID len
            ptr += dcid_len; // skip DCID
            server_scid_len = *ptr;
            ptr += 1; // skip SCID len
            memcpy(server_scid, ptr, server_scid_len);
            ptr += server_scid_len; // skip SCID
            
            // Now we have the token followed by 16 bytes of Integrity tag
            // Thus the length of the token is what remains to reach the end of the QUIC packet minus 16 bytes
            uint8_t* end = (uint8_t*)buf + len;
            size_t token_len = end - ptr - 16; 
            uint8_t* token = ptr;
            ptr += token_len;
            // Now `ptr` points to the Integrity Tag. This tag is used to 1) verify the integrity of the packet 2) Verify that the entity that sends the packet is the same that saw our Initial packet. Since the Integrity is also provided by UDP (via the checksum) and since the Initial packet can be decrypted by anyone, here we skip this check that seems not useful for the purpose of tracerouting.
            
            // When we will send another Initial packet with the CONNECTION_CLOSE frame we will need to include the Retry token: https://www.rfc-editor.org/rfc/rfc9000#section-8.1.2-1
            pb->retry_token = calloc(1, token_len);
            if(!pb->retry_token)
                error("calloc");
            memcpy(pb->retry_token, token, token_len);
            pb->retry_token_len = token_len;
            
            // Here we also need to change the DCID on the basis of what we received from the server
            // In particular, we need to use the SCID sent by the server into the Retry packet: https://www.rfc-editor.org/rfc/rfc9000#section-7.2-7
            // See also https://www.rfc-editor.org/rfc/rfc9001.html#section-5.2-6
            generate_quic_initial_packet(server_scid, server_scid_len, crypto, sizeof(crypto), token, token_len, 1);
            pb->send_time = get_time(); // Consider the time since now (as we are going to do the handshake with a new Initial packet)
            if(do_send(sk, (uint8_t*)encrypted_packet, *length_p, NULL) < 0) {
                free(pb->retry_token);
                error("do_send");
            }
            
            // Update the dcid so that when we will send the final Initial packet (the one with the connection close) we can use that as input for the (new) secrets
            // https://www.rfc-editor.org/rfc/rfc9000#section-7.2-4
            memcpy(pb->dcid, server_scid, server_scid_len);
            pb->dcid_len = server_scid_len;
            
            return NULL; // Return NULL and defer to next reception on the same sk (ideally we should receive an Initial packet)
        }
        
        // If we reached the destination, send also a CONNECTION_CLOSE frame within an Initial QUIC packet
        // However, we need to extract the SCID from the Initial packet sent by the server, because we need to use as DCID the SCID sent by the server.
        // See https://www.rfc-editor.org/rfc/rfc9000#section-7.2-7
        // Note that sending a CONNECTION_CLOSE into an Initial packet to abandon the handshake is legitimate as per https://www.rfc-editor.org/rfc/rfc9000#section-19.19-7
        // See also:
        //    - https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3-3
        //    - https://www.rfc-editor.org/rfc/rfc9000#section-10.2.3-5
        //    - https://www.rfc-editor.org/rfc/rfc9000#section-17.2.2-8
        //    - https://www.rfc-editor.org/rfc/rfc9000#section-12.4-11.10.1
        //    - https://www.rfc-editor.org/rfc/rfc9000#name-example-1-rtt-handshake (here a "third" Initial packet is sent by the Client)
        // Note: if we received a Retry packet, we need to include it also the Initial packet we are going to send carrying the CONNECTION_CLOSE: https://www.rfc-editor.org/rfc/rfc9000#section-8.1.2-1
        
        uint32_t quic_version = ntohl(*((uint32_t*)&buf[1])); // Note that is valid also for Version negotiation packets (which will contain Version = 0, see https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.1-3)
        
        char proto_details[100];
        
        // Note about Version negotiation packet: RFC says that a client MUST discard a Version negotiation packet if it contains the the QUIC version selected by the client.
        // This means that if we receive a Version negotiation packet either the Server does not support our version (1) or anyway that we need to discard it.
        // So we treat the reception of a Version negotiation packet as an indication that we cannot proceed with the connection attempt
        // Note also that the packet type of a Version negotation is zero
        // Please also note that the packet type does not make sense for a Version negotiation, because the two bits of the type are included into the 7 Unused bits, which are set to an arbitrary value by the server (see https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.1-5). Thus is might even happen that the type of a Version negotation is 0x00 (i.e. Initial), for this reason we also check for the version being returned. Indeed, a Version negotiation packet is recognized by checking whether the carried version is zero (https://www.rfc-editor.org/rfc/rfc9000.html#section-17.2.1-1)
        // See also https://www.rfc-editor.org/rfc/rfc9000.html#section-6.2-2
        
        if(packet_type != QUIC_INITIAL_PACKET || quic_version != SUPPORTED_QUIC_VERSION) {
            if(pb->retry_token != NULL) {
                free(pb->retry_token);
                pb->retry_token = NULL;
                pb->retry_token_len = 0;
            }
            
            if(quic_version == 0x00)
                sprintf(proto_details, "Version Negotiation");
            else
                sprintf(proto_details, "Unhandled packet type %d", packet_type);
            
            pb->proto_details = strdup(proto_details);
            
            return pb;
        }
        
        if(pb->retry_token != NULL)
            sprintf(proto_details, "Retry,Initial");
        else
            sprintf(proto_details, "Initial");
        
        pb->proto_details = strdup(proto_details);
        
        // "buf" is the UDP payload and thus points to the first QUIC Packet, which at this point we know it is an Initial packet
        uint8_t* ptr = (uint8_t*)&buf[DCID_LEN_OFFSET];
        ptr += (1 + *ptr); // Skip DCID len and DCID
        server_scid_len = *ptr;
        ptr++;
        memcpy(server_scid, ptr, server_scid_len);
        
        // Despite we need to use the server SCID as DCID for the connection close (https://www.rfc-editor.org/rfc/rfc9000#section-7.2-7), we need to keep the same secrets used so far (unless a Retry packet has been received): https://www.rfc-editor.org/rfc/rfc9000#section-7.2-4
        generate_secrets(pb->dcid, pb->dcid_len);
        generate_quic_initial_packet(server_scid, server_scid_len, connection_close, sizeof(connection_close), pb->retry_token, pb->retry_token_len, 0);
        if(do_send(sk, (uint8_t*)encrypted_packet, *length_p, NULL) < 0) {
            free(pb->retry_token);
            error("do_send");
        }
            
        if(pb->retry_token != NULL) {
            free(pb->retry_token);
            pb->retry_token = NULL;
            pb->retry_token_len = 0;
        }
        
        // If we don't have to care about ECN support we can stop here.
        // Otherwise we need to inspect the packet looking for an ACK_ECN frame (type 0x03)
        if(!ecn_input_value)
            return pb;
          
        // Try to decrypt the packet to find an ACK_ECN to determine if the destination supports ECN
        //
        // Note that an Inital packet containing a CRYPTO frame (like the one we sent initially) is an ACK-eliciting packet, thus it is legitimate
        // that we look for an ACK frame into the Initial packet we receive from the server. In partcular see:
        // - https://www.rfc-editor.org/rfc/rfc9000#section-1.2-3.12.1
        // - https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1-2
        
        uint8_t plaintext[INITIAL_PACKET_BUFFER];
        memset(plaintext, 0, sizeof(plaintext));
        memcpy(plaintext, buf, len); // copy all the protected+encrypted QUIC packet there
        
        // Now we need to do two macro-steps:
        // 1) Remove header protection
        // 2) Decrypt the packet payload
        
        // In order to do 1), we first need to determine the length of the header. 
        // This because we need to take the 16 bytes immediately after the header and use them as sample to perform header protection removal (https://www.rfc-editor.org/rfc/rfc9001.html#section-5.4.1-3)
        // Note that despite we used a "22 byte" long header, the server might have used different lengths (e.g. a longer cid, a longer pn etc.), thus we cannot assume the header is 22-byte long.
        // While doing this computation we also record the header Length field (https://www.rfc-editor.org/rfc/rfc9001#section-a.2-3)
        // Note that the length of the header and the Length field into the header are two different things
        // Here we add sizes according to "Long header" definition (https://www.rfc-editor.org/rfc/rfc9000#section-17.2) because an Initial packet has a long header (https://www.rfc-editor.org/rfc/rfc9000#name-initial-packet)
        size_t server_header_size = sizeof(uint8_t); // flags
        server_header_size += sizeof(uint32_t); // version
        server_header_size += sizeof(uint8_t); // dcid len
        server_header_size += buf[server_header_size - sizeof(uint8_t)]; // dcid
        server_header_size += sizeof(uint8_t); // scid len
        server_header_size += buf[server_header_size - sizeof(uint8_t)]; // scid
        server_header_size += sizeof(uint8_t); // token len
        server_header_size += buf[server_header_size - sizeof(uint8_t)]; // token
        // Here the amount of server_header_size is such that we are pointing to the Length field, so before proceeding we decode the Length 
        // Again, here we are talking about the Length field within the packet header and not the length of the header we are trying to determine: https://www.rfc-editor.org/rfc/rfc9001#section-a.2-3
        // Determine on how much bytes the length is encoded
        uint8_t len_size = 0;
        size_t packet_len = get_vlint((uint8_t*)buf + server_header_size, &len_size); // Remember that this Length includes also the packet number and the authentication tag
        
        // Now continue to compute the length of the pakcet header
        server_header_size += len_size; // length
        
        // Here another interruption: save the pointer to the encoded packet number, because it will be useful later
        uint8_t* server_pn_ptr = plaintext + server_header_size;
        
        // Proceed with computation of the length of the header
        // Here we need to add the amount occupied by the packet number. Since the packet number is a variable-length integer and it is protected, we don't know its actual length.
        // However, when doing header protection the packet number is always considered to be encoded on four bytes (https://www.rfc-editor.org/rfc/rfc9001#section-5.4.2-2)
        // This means that the sample will be taken starting four-bytes from here, either if it is the actual "first" encrypted byte or not
        // Note that this also means that when doing header protection we must take the sample in the same way. Since we used a four-byte packet number, we are ok.
        server_header_size += sizeof(uint32_t); // packet number 
        
        // Now we can finally take the sample and thus get the mask to remove the header protection
        uint8_t* sample = (uint8_t*)buf + server_header_size;
        size_t sample_len = 16; // Initial packets are protected with AEAD_AES_128_GCM thus the sample is 16 bytes (https://www.rfc-editor.org/rfc/rfc9001#section-5.4.3-2)  
        uint8_t mask[5]; // The mask is composed by 5 bytes: https://www.rfc-editor.org/rfc/rfc9001#section-5.4.1-2
        get_protection_header_mask(sample, sample_len, server_hp, mask);
        
        // Remove header protection. We also get the length of the packet number as byproduct
        size_t server_pn_len = unprotect_header(plaintext, mask, server_pn_ptr);
        
        // So now we know the exact length o the QUIC header received from the server and we can also extract the server pn:
        server_header_size -= sizeof(uint32_t); // Remove the four-bytes "allowance" ...
        server_header_size += server_pn_len; // ... and include the actual space occupied by the packet number
        
        // Now time to gather all we need to decrypt the payalod (2nd macrostep):
        // - Packet number: we need to combine it with the server_iv to get the nonce 
        // - Additional data: the unprotected quic header
        // - The length of the encrypted payload (i.e. what we need to decrypt)
        // - The authentication tag, which is the last 16 bytes of the encrypted payload
        
        // Get the packet number.
        // Note that the packet number is *not* encoded as a variable-length integer so we cannot use the get_vlint* functions
        // Note also that the packet number max size is four-bytes https://www.rfc-editor.org/rfc/rfc9000#section-17.2-8.8.1 
        uint32_t server_pn = 0;
        if(server_pn_len == 1)
            server_pn = *server_pn_ptr;
        else if(server_pn_len == 2)
            server_pn = ntohs(*((uint16_t*)server_pn_ptr));
        else if(server_pn_len == 3) // need to change endianness on three bytes(!)
            server_pn = (((uint32_t) server_pn_ptr[0]) << 16) | (((uint32_t) server_pn_ptr[1]) << 8) | ((uint32_t) server_pn_ptr[2]);
        else if(server_pn_len == 4)
            server_pn = ntohl(*((uint32_t*)server_pn_ptr));
        else
            ex_error("Got an impossible server pn len: %d\n", server_pn_len);
                
        // Record also the associated data as we need that to perform the decryption
        // Remember that the associated data is the content of the QUIC header, starting from the first byte of either the short or long header, up to and including the unprotected packet number (https://www.rfc-editor.org/rfc/rfc9001.html#section-5.3-6)
        // So here we already have everything we need, we just need to record the pointer and the length
        uint8_t* aad = plaintext;
        size_t aad_len = server_header_size;
        
        // Remember that the Length field includes also the packet number
        size_t encrypted_payload_len = packet_len - server_pn_len;
        
        // The authentication tag is composed by the last 16 bytes of the encrypted payload
        uint8_t* tag = (uint8_t*)buf + server_header_size + encrypted_payload_len - 16;
        
        // Generate the nonce combining the "server iv" with the packet number
        uint8_t nonce[sizeof(server_iv)];
        uint8_t nonce_len = sizeof(nonce);
        generate_nonce(server_iv, server_pn, nonce, nonce_len);
        
        // Now can finally decrypt the packet
        // Note that we declare that we need to decrypt "encrypted_payload_len - 16" bytes, because the last 16 bytes of the encrypted packet are the "authentication ta"g that was added during encryption (like we did) for authentication check purposes
        // The return value "dec_len" indicates how many bytes the "clear" payload is long
        int dec_len = aead_aes_gcm_128_decrypt((uint8_t*)buf + server_header_size, encrypted_payload_len - 16, aad, aad_len, tag, server_key, nonce, nonce_len, plaintext + server_header_size);
        
        if(dec_len == -1)
            ex_error("Error while decrypting packet from server\n");
        
        // Now scan frame by frame looking for an ACK_ECN frame
        uint8_t* decrypted_payload = plaintext + server_header_size;
        uint8_t* end = decrypted_payload + dec_len;
        uint8_t frame_type = 0;
        char ecn_add_info[1024];
        
        do {
            frame_type = *decrypted_payload;
            decrypted_payload++;
            
            switch(frame_type)
            {
                case PADDING: // https://www.rfc-editor.org/rfc/rfc9000#name-padding-frames
                {
                    decrypted_payload++;
                    
                    break;
                }
                case ACK: // https://www.rfc-editor.org/rfc/rfc9000#name-ack-frames
                case ACK_ECN:
                {   
                    uint8_t field_len = 0;
                    get_vlint(decrypted_payload, &field_len); // largest ack
                    decrypted_payload += field_len;
                    get_vlint(decrypted_payload, &field_len); // ack delay
                    decrypted_payload += field_len;
                    size_t ack_range_count = get_vlint(decrypted_payload, &field_len); // ack range count
                    decrypted_payload += field_len;
                    get_vlint(decrypted_payload, &field_len); // first ack range
                    decrypted_payload += field_len;
                    
                    for(size_t i = 0; i < ack_range_count; ++i) {
                        get_vlint(decrypted_payload, &field_len); // gap
                        decrypted_payload += field_len;
                        get_vlint(decrypted_payload, &field_len); // ack range length
                        decrypted_payload += field_len;
                    }
                    
                    if(frame_type == ACK_ECN) { // https://www.rfc-editor.org/rfc/rfc9000#name-ecn-counts
                        size_t ect0_count = get_vlint(decrypted_payload, &field_len); // ect0_count
                        decrypted_payload += field_len;
                        size_t ect1_count = get_vlint(decrypted_payload, &field_len); // ect1_count
                        decrypted_payload += field_len;
                        size_t ecn_ce_count = get_vlint(decrypted_payload, &field_len); // ecn_ce_count
                        decrypted_payload += field_len;
                        
                        sprintf(ecn_add_info, "ECT0:%zu,ECT1:%zu,ECN-CE:%zu", ect0_count, ect1_count, ecn_ce_count);
                        pb->ecn_info = strdup(ecn_add_info);
                    }
                    
                    break;
                }
                case CRYPTO: // https://www.rfc-editor.org/rfc/rfc9000#name-crypto-frames
                {
                    uint8_t field_len = 0;
                    get_vlint(decrypted_payload, &field_len); // offset
                    decrypted_payload += field_len;
                    size_t crypto_data_len = get_vlint(decrypted_payload, &field_len); // length
                    decrypted_payload += field_len;
                    decrypted_payload += crypto_data_len;
                    
                    break;
                }
                case CONNECTION_CLOSE: // https://www.rfc-editor.org/rfc/rfc9000#name-connection_close-frames
                {
                    uint8_t field_len = 0;
                    get_vlint(decrypted_payload, &field_len); // error code
                    decrypted_payload += field_len;
                    get_vlint(decrypted_payload, &field_len); // frame type
                    decrypted_payload += field_len;
                    size_t rp_len = get_vlint(decrypted_payload, &field_len); // reason phrase len
                    decrypted_payload += field_len;
                    decrypted_payload += rp_len;
                    
                    break;
                }
                default:
                {
                    ex_error("Got an unexpected frame of type %d into an Initial packet\n", frame_type);
                    break;
                }
            }
        } while(frame_type != ACK_ECN && frame_type != ACK && decrypted_payload < end);
    } // if(!err)
    
    return pb;
}

static void quic_recv_probe(int sk, int revents) 
{
    if(revents & (POLLIN | POLLERR))
        recv_reply(sk, !!(revents & POLLERR), quic_check_reply);
}

static int quic_is_raw_icmp_sk(int sk)
{
    if(sk == raw_icmp_sk)
        return 1;

    return 0;
}

static void quic_handle_raw_icmp_packet(char* bufp)
{
    sockaddr_any offending_probe_dest;
    sockaddr_any offending_probe_src;
    struct udphdr* offending_probe = NULL;
    int proto = 0;
    int returned_tos = 0;
    extract_ip_info(dest_addr.sa.sa_family, bufp, &proto, &offending_probe_src, &offending_probe_dest, (void **)&offending_probe, &returned_tos); 
    
    if(proto != IPPROTO_UDP)
        return;
        
    offending_probe = (struct udphdr*)offending_probe;
    offending_probe_dest.sin.sin_port = offending_probe->dest;
    offending_probe_src.sin.sin_port = offending_probe->source;
    
    probe* pb = probe_by_src_and_dest(&offending_probe_src, &offending_probe_dest);
    
    if(pb) {
        pb->returned_tos = returned_tos;        
        probe_done(pb, &pb->icmp_done);
    }
}

void quic_close()
{
    free(initial_payload);
    free(encrypted_packet);
}

static tr_module quic_ops = {
    .name = "quic",
    .init = quic_init,
    .send_probe = quic_send_probe,
    .recv_probe = quic_recv_probe,
    .header_len = sizeof(struct udphdr),
    .is_raw_icmp_sk = quic_is_raw_icmp_sk,
    .handle_raw_icmp_packet = quic_handle_raw_icmp_packet,
    .close = quic_close
};

TR_MODULE(quic_ops);

