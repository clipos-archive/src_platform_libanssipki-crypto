// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
#include <stdio.h>

#include <readline/readline.h>
#include <readline/history.h>

#include "anssipki-crypto.h"
#include <anssipki-common.h>

#include <stdlib.h>
#include <string.h>


int main (int argc __attribute__((unused)), char* argv[] __attribute__((unused))) {
  char* entier;
  mpz_t n, m, tmp;

  DevUrandomPRNG prng;

  initPrimes (prng);

  mpz_init (n);
  mpz_init (m);
  mpz_init (tmp);

  try {
    while (true) {
      entier = readline (NULL);
      mpz_set_str (n, entier, 16);
      mpz_fdiv_q_ui (m, n, 2);

      printf ("IsPrime (p) -> %d\n", isPrime (n));

      printf ("IsPrime ((p-1)/2) -> %d\n", isPrime (m));

      mpz_sub_ui(tmp, m, 1);
      printf ("IsSmooth ((p-1/2 - 1) -> %d\n", isSmooth (tmp));

      mpz_add_ui(tmp, m, 1);
      printf ("IsSmooth ((p-1)/2 + 1) -> %d\n", isSmooth (tmp));

      mpz_add_ui(tmp, n, 1);
      printf ("IsSmooth (p + 1) -> %d\n", isSmooth (tmp));

      free (entier);
    }
  } catch (std::exception& e) {
    printf ("Exception rattrappée: %s\n", e.what());
  }
}
