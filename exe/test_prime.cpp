// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2018 ANSSI. All Rights Reserved.
#include <anssipki-crypto.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>


#define TEST_LEN 512

mpz_t entier;

// Some random 256-bit primes
const char *list_primes[] = {
"39ee567c95492f4ef5f7bbee169cfedf039296ebe3e214ba3a20fd03f48c5939",
"7aea784038e247e4bf3c4a4fa7ab1d01b5c7adfcb5fb775cdcc46c1f612a29fb",
"9613e5b7d76b51dec9cad8f5cc04a070e00a8fe49c8f656b88e7146f6cedeb1f",
"badf4adf6ac8db5b9954be7178ffbdae2a170a7b8252b24652661cba9e291cb5",
"d040200615402e2baef6477eb5623d818a20084ecd0d9538c85ced1d115ede2f",
"824fbc17aa446d56f8e38e5426ac39de7ac40579b61d3778a0cd236b5a7e0443",
"eb01619a443b96d32a75ab2792d96467afb28e2dc7a6cfbbb72a6302a2a60a41",
"6e4d89a409b66395e95c341e87ddef5751a8327cf417388482a1eeb70499221d",
"8761d06a4241cff0ea3361e26d0386d8443263d546c87fdc0050bc4c19071c5b",
"79c63549edc05473078f4722567182dced2c68ad8d34e723c1e5aeadda0759e7",
"d6a2d15218c322de6b962d33952b7fe28e3dc6259990721a7bc31b1a963c684f",
"ea36380458ff1f06056f7f57d372868dd07eac402707a638734f3b6e3815105f",
"2db09d6de32c6e1966b50f1418f86ce837e9aa8d9b09fa1dae91811f3c1dcd87",
"d395ce74b0472b8d72cef51c78198e37dee0d6398658cfd1e39c12b47f8ad02d",
"35d4805bed4a69c62d9bf0c3dc3bc9c306cf8d7f2842bb2e2f709c40f08d6f25",
"8c3d24fbb9d2abfeef68a30e64abb2f58e951c04ba22a7de0811a2b125e47093",
"d221821c580622bb80b089a45f6820523b6656635e3f3161732260aa4e44ae23",
"974dc6f449eba34dd0f805a842e7f87a94211acc1402b2ab497ffadf498e6c3b",
"d299082d59c0f43009a4408204e42774338ff65a3d73464422da5b6223f73bdf",
"bfacd9d08f2f266236a000a5835542afddb52c2c4bd8f95f496d156387dc6233",
"9cd42dd5d90adf70a54285c20efb2157d554edac93268a75e5a7ba1b04631a97",
"db3fa4da6094db44ee4a0fabfa4f8ec998e135f4dbb94a67b2c529a468fa1309",
"9b30adf053cd292faa509ea4a765ec8257b45c167ccc5d0fdf9e602ccf34094f",
"62546e3966807b0ec615b15c71eca7cce18f969e31f02b0f92a5169aec0899a7",
"23bcd00f4e6e4a97b9d71a50f872620686aff5fab1a452ed8cd7fc1852485e67",
"c82be76f5832a0066949a61d2202c71b55278d5ca91c991f6cbc2829827b75f5",
"9cede8220551a1c49c0149b1507a71310412d70989c8ac392b9ad8aba3022f1b",
"85f0ea7b94d89cdb2722d68e420d6014003c749c19505593a00f534704fc7755",
NULL };


void test_Prime () {
  BarakHaleviPRNG s;

  while (true) {
    s.getRandomInt (entier, TEST_LEN, true);
    bool prime = isPrime (entier);
    printf ("Integer extracted:\n%s\n", mpz_get_str (NULL, 16, entier));
    mpz_shred (entier);
    if (prime) {
      printf ("  -> Prime number found !\n");
      break;
    }
  }
}


void test_Smoothness () {
  BarakHaleviPRNG s;

  while (true) {
    s.getRandomInt (entier, TEST_LEN, true);
    printf ("Integer extracted:\n%s\n", mpz_get_str (NULL, 16, entier));
    if (isSmooth (entier)) {
      printf ("  -> Smooth\n");
    } else {
      printf ("  -> Not smooth !\n");
      break;
    }
    mpz_shred (entier);
  }
}


void test_RSAFactor (size_t len) {
  BarakHaleviPRNG s;

  findRSAFactor (entier, len, s, true);
  printf ("RSA factor found:\n%s\n", mpz_get_str (NULL, 16, entier));
  mpz_shred (entier);

  findRSAFactor (entier, len, s, true);
  printf ("RSA factor found:\n%s\n", mpz_get_str (NULL, 16, entier));  
  mpz_shred (entier);
}


int main (int argc __attribute__((unused)), char* argv[] __attribute__((unused))) {

  // Checking that isPrime_Lucas returns 0 when it should
  for (const char **p = list_primes;  *p != NULL; p++) {
    mpz_t n;
    mpz_init_set_str (n, *p, 16);

    if (!isPrime_Lucas (n)) {
      fprintf (stderr, "Prime must be a Lucas pseudoprime:\n%s\n", *p);
      exit (EXIT_FAILURE);
    }
//     if (!isPrime_MillerRabin (n)) {
//       fprintf (stderr, "Prime must be a Miller-Rabin pseudoprime:\n%s\n", *p);
//       exit (EXIT_FAILURE);
//     }
  }
  try {
    BarakHaleviPRNG s;
    
    initPrimes (s);
    
    test_Prime ();
    test_Smoothness ();
    test_RSAFactor (128);
    test_RSAFactor (256);
    test_RSAFactor (TEST_LEN);
 
    return 0;
  } catch (std::exception& e) {
    printf ("Exception caught: %s\n", e.what());
    return 1;
  }   
}
