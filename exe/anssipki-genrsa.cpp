// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
#include <stdio.h>
#include <strings.h>
#include <stdlib.h>
#include <string>
#include <unistd.h>
#include "anssipki-crypto.h"

#define BEGIN "-----BEGIN RSA PRIVATE KEY-----\n"
#define END   "-----END RSA PRIVATE KEY-----\n"
#define B64 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

static inline char*	PEMEncode(const unsigned char* key,
				  const unsigned int size)
{
  char* ret = (char*)malloc(sizeof(char) * size * 2);
  unsigned int i;
  unsigned int j = 0;

  if (ret == NULL)
    return ret;
  bzero(ret, ((size < 64) ? 128 : (size * 2)));
  for (i = 0; i < size; i += 3)
    {
      ret[j] = B64[key[i] >> 2];
      j++;
      ret[j] = B64[((key[i] & 0x3) << 4) | (((size - i)  < 2) ? 0 : (key[i + 1] >> 4))];
      j++;
      ret[j] = ((size - i) < 2) ? '=' : B64[((key[i + 1] & 0xf) << 2) | (((size - i) < 3) ? 0 : (key[i + 2] >> 6))];
      j++;
      ret[j] = ((size - i) < 3) ? '=' : B64[key[i + 2] & 0x3f];
      j++;
      if (((size - i) <= 3) || (((i + 3) % 48) == 0))
	{
	  ret[j] = '\n';
	  j++;
	}
    }
  return ret;
}

int	main(int argc, char** argv)
{
  unsigned int	nbits;
  DevUrandomPRNG rng;
  char* pem;

  if ((argc != 2) || ((nbits = atoi(argv[1])) < 1024))
    {
      fprintf(stderr, " Usage : %s keysize (>= 1024)\n", (argc > 0) ? argv[0] : NULL);
      return (EXIT_FAILURE);
    }
  RSAKey rsa(rng, nbits, true);
  if ((pem = PEMEncode((const unsigned char*)rsa.ASN1PrivateKeyInfo().toChar(),
		       (const unsigned int)rsa.ASN1PrivateKeyInfo().size())) == NULL)
    {
      perror("malloc");
      return (EXIT_FAILURE);
    }
  printf("%s%s%s", BEGIN, pem, END);
  return (EXIT_SUCCESS);
}
