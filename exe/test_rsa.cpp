// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2018 ANSSI. All Rights Reserved.
#define ANSSIPKI_TEST_RSA
#include <anssipki-crypto.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define TEST_LEN 1024

void testKey (size_t nBits, bool useF4) {
  printf ("TEST avec nBits=%d et useF4=%s\n", nBits, useF4 ? "true" : "false");

  BarakHaleviPRNG s;

  const RSAKey k (s, nBits, useF4);

  printf ("Cle generee:\n  n=%s\n  e=%s\n  d=%s\n",
	  mpz_get_str (NULL, 16, k.n()),
	  mpz_get_str (NULL, 16, k.e()),
	  mpz_get_str (NULL, 16, k.d()));

  
  gmp_randstate_t GMP_state;
  mpz_t m, c, x;
  gmp_randinit_lc_2exp_size (GMP_state, 128);
  mpz_init (m);
  mpz_init (c);
  mpz_init (x);

  printf ("Tests\n");
  for (int i=0; i<10; i++) {
    mpz_urandomm (m, GMP_state, k.n());
    mpz_powm (c, m, k.e(), k.n());
    mpz_powm (x, c, k.d(), k.n());

    printf ("  m=%s\n  c=%s\n  x=%s\n",
	    mpz_get_str (NULL, 16, m),
	    mpz_get_str (NULL, 16, c),
	    mpz_get_str (NULL, 16, x));
    
    if (mpz_cmp (m, x) != 0)
      printf ("  NOK\n");
    else
      printf ("  OK\n");
  }

  printf ("\n");
}


int main (int argc __attribute__((unused)), char* argv[] __attribute__((unused))) {
  try {
    BarakHaleviPRNG s;
    
    initPrimes (s);
    
    testKey (TEST_LEN / 2, true);
    testKey (TEST_LEN / 2, false);

    testKey (TEST_LEN, true);
    testKey (TEST_LEN, false);

    testKey (TEST_LEN * 2, true);
    testKey (TEST_LEN * 2, false);

    return 0;
  } catch (std::exception& e) {
    printf ("Exception caught: %s\n", e.what());
    return 1;
  }   
}
