#ifndef _APPLE_UDP_H
#define _APPLE_UDP_H
struct udphdr
{
  u_int16_t source;
  u_int16_t dest;
  u_int16_t len;
  u_int16_t check;
};
#endif