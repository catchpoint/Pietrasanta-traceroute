/*
    Copyright(c)  2023   Alessandro Improta, Luca Sani, Catchpoint Systems, Inc.
    
    This is a workaround to use Linux types in Mac OS. The types are removing the endianness checks/info from the name of the type keeping the size of bytes the same

    License:  GPL v2 or any later

    See COPYING for the status of this software.
*/

#include <stdint.h>

#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif
#ifdef __CHECK_ENDIAN__
#define __bitwise __bitwise__
#else
#define __bitwise
#endif

#define SOL_IP 0
#define SOL_IPV6 41
#define IPV6_MTU 24 // TODO Need to check if this works on Mac

typedef uint64_t __u64;
typedef uint32_t __u32;
typedef uint16_t __u16;
typedef uint8_t __u8;

typedef uint16_t __bitwise __le16;
typedef uint16_t __bitwise __be16;
typedef uint32_t __bitwise __le32;
typedef uint32_t __bitwise __be32;
typedef uint64_t __bitwise __le64;
typedef uint64_t __bitwise __be64;

typedef uint16_t __bitwise __sum16;
typedef uint32_t __bitwise __wsum;
