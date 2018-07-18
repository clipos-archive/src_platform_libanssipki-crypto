// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2018 ANSSI. All Rights Reserved.
#include <anssipki-crypto.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctime>

mpz_t entier;
BarakHaleviPRNG s;


void test_Random (int n, size_t len) {
  printf ("Generating %d random of %u bits...\n", n, len);
  
  for (int i=0; i<n; i++) {
    s.getRandomInt (entier, len, false);
    fprintf (stderr, ".");
  }

  printf ("\n");
}


void test_Prime (int n, size_t len) {
  printf ("Generating %d primes of %u bits...\n", n, len);
  
  for (int i=0; i<n; ) {
    s.getRandomInt (entier, len, false);
    if (isPrime (entier)) {
      i++;
      fprintf (stderr, ".");
    }
  }

  printf ("\n");
}


void test_PrimeFT (int n, size_t len) {
  BarakHaleviPRNG s;

  printf ("Generating %d primes of %u bits using FT method...\n", n, len);
  
  for (int i=0; i<n; i++) {
    genPrimeFT (entier, len, s, false);
    fprintf (stderr, ".");
  }

  printf ("\n");
}

void test_Smooth (int n, size_t len) {
  printf ("Generating %d smooth integers of %u bits...\n", n, len);
  
  for (int i=0; i<n; ) {
    s.getRandomInt (entier, len, false);

    if (isSmooth (entier)) {
      i++;
      fprintf (stderr, ".");
    }
  }

  printf ("\n");
}


void test_NonSmooth (int n, size_t len) {
  printf ("Generating %d non smooth integers of %u bits...\n", n, len);
  
  for (int i=0; i<n; ) {
    s.getRandomInt (entier, len, false);

    if (!isSmooth (entier)) {
      i++;
      fprintf (stderr, ".");
    }
  }

  printf ("\n");
}


void test_RSAFactor (int n, size_t len) {
  printf ("Generating %d RSA factors of %u bits...\n", n, len);
   
  for (int i=0; i<n; i++) {
    findRSAFactor (entier, len, s, false);
    fprintf(stderr, ".");
    //printf ("RSA factor found:\n%s\n", mpz_get_str (NULL, 16, entier));  
  }

  printf ("\n");
}


void test_RSAFactorFT (int n, size_t len) {
  printf ("Generating %d RSA factors of %u bits using FT method...\n", n, len);
   
  for (int i=0; i<n; i++) {
    findRSAFactorFT (entier, len, s, false);
    fprintf(stderr, ".");
    //printf ("RSA factor found:\n%s\n", mpz_get_str (NULL, 16, entier));  
  }

  printf ("\n");
}


int main (int argc, char* argv[]) {
  try {
    //init Barak-Halevi PRNG with time
    int i;
    time_t bht;
    char bhc[32];

    bht = time(NULL);
    for (i = 0; i < (int) sizeof(time_t); i++) {
        bhc[i] = (char) (bht & 0xFF);
        bht >>= 8;
    }
    s.refresh(bhc, sizeof(time_t));

    //init Primes
    initPrimes (s);
    mpz_init (entier);
   
    //read arguments 
    int tests = 31;
    int n = 1;
    size_t len = 512;
    clock_t t;
    
    if (argc == 4) {
      tests = atoi (argv[1]);
      n = atoi (argv[2]);
      len = atoi (argv[3]);
    }
    
    //perform tests
    printf ("%d %d %u\n", tests, n, len);
    
    if (tests & 1) {
      t = clock();
      test_Prime (n, len);
      printf("Time elapsed: %f\n", (double) (clock() - t)/CLOCKS_PER_SEC);
    }

    if (tests & 2) {
      t = clock();
      test_PrimeFT (n, len);
      printf("Time elapsed: %f\n", (double) (clock() - t)/CLOCKS_PER_SEC);
    }
    
    if (tests & 4) {
      t = clock();
      test_RSAFactor (n, len);
      printf("Time elapsed: %f\n", (double) (clock() - t)/CLOCKS_PER_SEC);
    }
    
    if (tests & 8) {
      t = clock();
      test_RSAFactorFT (n, len);
      printf("Time elapsed: %f\n", (double) (clock() - t)/CLOCKS_PER_SEC);
    }

    if (tests & 16) {
      t = clock();
      test_NonSmooth (n, len);
      printf("Time elapsed: %f\n", (double) (clock() - t)/CLOCKS_PER_SEC);
    }

    if (tests & 32) {
      t = clock();
      test_Smooth (n, len);
      printf("Time elapsed: %f\n", (double) (clock() - t)/CLOCKS_PER_SEC);
    }

    if (tests & 64) {
      t = clock();
      test_Random (n, len);
      printf("Time elapsed: %f\n", (double) (clock() - t)/CLOCKS_PER_SEC);
    }

    return 0;
  } catch (std::exception& e) {
    printf ("Exception caught: %s\n", e.what());
    return 1;
  }  
}
