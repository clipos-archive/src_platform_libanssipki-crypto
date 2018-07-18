// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
/**************************************************************
   titre        : sha1.c

   Algorithme de hachage SHA-1, générant des hachés de 160 bits
**************************************************************/


/* Implementation of NIST's Secure Hash Algorithm (FIPS 180)
 * Lightly bummed for execution efficiency.
 *
 * Jim Gillogly 3 May 1993
 *
 * Synopsis of the function calls:
 *
 *   void sha1(const uchar* mem, const uint length, uint* buffer)
 *      Input is a memory block "length" bytes long.
 *
 * Caveat:
 *      Not tested for case that requires the high word of the length,
 *      which would be files larger than 1/2 gig or so.
 *
 * Limitation:
 *      sha1 (the memory block function) will deal with blocks no longer
 *      than 4 gigabytes; for longer samples, the stream version will
 *      probably be most convenient (e.g. perl moby_data.pl | sha).
 *
 * Bugs:
 *      The standard is defined for bit strings; I assume bytes.
 *
 * Copyright 1993, Dr. James J. Gillogly
 * This code may be freely used in any application.
 */

#define __STDC_LIMIT_MACROS
#include "anssipki-crypto.h"
#include "anssipki-common.h"
#include <string.h>
#include <errno.h>
#include <stdint.h>

#if !defined(BYTE_ORDER) || (BYTE_ORDER != LITTLE_ENDIAN && BYTE_ORDER != BIG_ENDIAN)
#error Define BYTE_ORDER to be equal to either LITTLE_ENDIAN or BIG_ENDIAN
#endif



#if BYTE_ORDER == LITTLE_ENDIAN      /* Imported from Peter Gutmann's implementation */

/* When run on a little-endian CPU we need to perform byte reversal on an
   array of longwords.  It is possible to make the code endianness-
   independant by fiddling around with data at the byte level, but this
   makes for very slow code, so we rely on the user to sort out endianness
   at compile time */

static void byteReverse(unsigned int * buffer, const size_t byteCount)
{
  const size_t uintCount = byteCount / sizeof(unsigned int);
  unsigned int value;
  size_t count;


  for (count = 0; count < uintCount; count++)
  {
    value = ( buffer[ count ] << 16 ) | ( buffer[ count ] >> 16 );
    buffer[ count ] = ( ( value & 0xFF00FF00U ) >> 8 ) | ( ( value & 0x00FF00FFU ) << 8 );
  }
}
#endif /* BYTE_ORDER == LITTLE_ENDIAN */





union longbyte
{
  u32 W[80];        /* Process 16 32-bit words at a time */
  char B[320];       /* But read them as bytes for counting */
};





#define f0(x,y,z) (z ^ (x & (y ^ z)))           /* Magic functions */
#define f1(x,y,z) (x ^ y ^ z)
#define f2(x,y,z) ((x & y) | (z & (x | y)))
#define f3(x,y,z) (x ^ y ^ z)

#define K0 0x5a827999                           /* Magic constants */
#define K1 0x6ed9eba1
#define K2 0x8f1bbcdc
#define K3 0xca62c1d6

#define S(n, X) ((X << n) | (X >> (32 - n)))    /* Barrel roll */

#define r0(f, K) \
    temp = S(5, A) + f(B, C, D) + E + *p0++ + K; \
    E = D;  \
    D = C;  \
    C = S(30, B); \
    B = A;  \
    A = temp

#define r1(f, K) \
    temp = *p1++ ^ *p2++ ^ *p3++ ^ *p4++; \
    temp = S(5, A) + f(B, C, D) + E + (*p0++ = S(1,temp)) + K; \
    E = D;  \
    D = C;  \
    C = S(30, B); \
    B = A;  \
    A = temp



/* Hash a memory block */
static void _sha1(const char* const mem, size_t _length, unsigned int* buf)
{
  u32 i, nread, nbits;
  union longbyte d;
  u32 hi_length, lo_length;
  bool padded;
  const char* s = mem;

  if (_length > UINT_LEAST32_MAX)
    throw UnexpectedError ("message too big for this implementation of sha1");
  u32 length = (u32) _length;

  register u32 *p0, *p1, *p2, *p3, *p4;
  u32 A, B, C, D, E, temp;

  u32 h0, h1, h2, h3, h4;

  h0 = 0x67452301;                            /* Accumulators */
  h1 = 0xefcdab89;
  h2 = 0x98badcfe;
  h3 = 0x10325476;
  h4 = 0xc3d2e1f0;

  padded = false;
  for (hi_length = lo_length = 0; ;)          /* Process 16 longs at a time */
  {
    if (length < 64)
      nread = length;
    else
      nread = 64;
    length -= nread;
    memcpy(d.B, s, nread);
    s += nread;

    if (nread < 64)                       /* Partial block? */
    {
      nbits = nread << 3;                 /* Length: bits */
      if ((lo_length += nbits) < nbits)
        hi_length++;                      /* 64-bit integer */

      if (nread < 64 && ! padded)         /* Append a single bit */
      {
        d.B[nread++] = '\x80';       /* Using up next byte */
        padded = true;                    /* Single bit once */
      }
      for (i = nread; i < 64; i++)        /* Pad with nulls */
        d.B[i] = 0;
      if (nread <= 56)                    /* Room for length in this block */
      {
        d.W[14] = hi_length;
        d.W[15] = lo_length;
#if BYTE_ORDER == LITTLE_ENDIAN

        byteReverse(d.W, 56 );
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

      }
#if BYTE_ORDER == LITTLE_ENDIAN
      else
        byteReverse(d.W, 64 );
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

    }
    else                                     /* Full block ++ get efficient */
    {
      if ((lo_length += 512) < 512)
        hi_length++;                       /* 64-bit integer */
#if BYTE_ORDER == LITTLE_ENDIAN

      byteReverse(d.W, 64 );
#endif /* BYTE_ORDER == LITTLE_ENDIAN */

    }

    p0 = d.W;
    A = h0;
    B = h1;
    C = h2;
    D = h3;
    E = h4;

    r0(f0,K0);
    r0(f0,K0);
    r0(f0,K0);
    r0(f0,K0);
    r0(f0,K0);
    r0(f0,K0);
    r0(f0,K0);
    r0(f0,K0);
    r0(f0,K0);
    r0(f0,K0);
    r0(f0,K0);
    r0(f0,K0);
    r0(f0,K0);
    r0(f0,K0);
    r0(f0,K0);
    r0(f0,K0);

    p1 = &d.W[13];
    p2 = &d.W[8];
    p3 = &d.W[2];
    p4 = &d.W[0];

    r1(f0,K0);
    r1(f0,K0);
    r1(f0,K0);
    r1(f0,K0);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f1,K1);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f2,K2);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);
    r1(f3,K3);

    h0 += A;
    h1 += B;
    h2 += C;
    h3 += D;
    h4 += E;

    if (nread <= 56)
      break; /* If it's greater, length in next block */
  }
  buf[0] = h0;
  buf[1] = h1;
  buf[2] = h2;
  buf[3] = h3;
  buf[4] = h4;
}

/* Fonction SHA1 retournant le résultat dans un champ d'octet plutot que d'entiers (pour gérer
l'endianness) */

int sha1 (const char* string, const size_t string_len, char* result)
{
  u32 tmp;
  u32 i;

  if (string == NULL || result == NULL) {
    errno = EINVAL;
    return -1;
  }

  _sha1(string, string_len, (unsigned int*) result);

#if BYTE_ORDER == LITTLE_ENDIAN
  for (i=0; i<(SHA1_DIGEST_LENGTH / 4); i++)
  {
    tmp = ((u32*) result) [i];
    result[3+4*i] = (char) (tmp & 0xff);
    result[2+4*i] = (char) ((tmp>>8) & 0xff);
    result[1+4*i] = (char) ((tmp>>16) & 0xff);
    result[0+4*i] = (char) ((tmp>>24) & 0xff);
  }
#endif

  return 0;
}

