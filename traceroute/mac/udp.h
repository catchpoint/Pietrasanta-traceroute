/*
    Copyright(c)  2023   Alessandro Improta, Luca Sani, Catchpoint Systems, Inc.

    This is a workaround to use Linux types in Mac OS. The types are removing the endianness checks/info from the name of the type keeping the size of bytes the same

    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

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
