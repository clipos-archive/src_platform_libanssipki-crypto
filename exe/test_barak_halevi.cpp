// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2018 ANSSI. All Rights Reserved.
#include <anssipki-crypto.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#define TEST_LEN 256

char test[] = "Tititoto";
char alea[TEST_LEN];
mpz_t entier;

void display (const char* str, const char* a, size_t len) {
  uint i;

  printf ("%s:\n", str);
  for (i=0; i<len; i++)
  {
    printf("%02x ", a[i] & 0xff);

    if (i%32 == 31)
      printf("\n");
  }
  printf("\n");
}


int main (int argc __attribute__((unused)), char* argv[] __attribute__((unused))) {
  try {
    BarakHaleviPRNG s;
    
    display("State", s.state(), BARAK_HALEVI_STATE_BYTE_SIZE);
    
    s.refresh (test, (uint) strlen ((char*) test));
    display("State", s.state(), BARAK_HALEVI_STATE_BYTE_SIZE);

    for (int i=0; i<12; i++) {
      s.getRandomBytes (alea, TEST_LEN);
      display("Random extracted", alea, TEST_LEN);
      display("State", s.state(), BARAK_HALEVI_STATE_BYTE_SIZE);
    }
 
    s.getRandomInt (entier, TEST_LEN, true);
    printf ("Integer extracted:\n%s\n", mpz_get_str (NULL, 16, entier));
    display("State", s.state(), BARAK_HALEVI_STATE_BYTE_SIZE);

    return 0;
  } catch (std::exception& e) {
    printf ("Exception caught: %s\n", e.what());
    return 1;
  }
}
