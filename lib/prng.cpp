// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Génération de clés de signature RSA / DSA / ECDSA (version 1.2)
//
// Fonctions et classes générales concernant les PRNG
//
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#include "anssipki-crypto.h"

#include <stdlib.h>
#include <iostream>


static const char hexa_str[] = "0123456789abcdef";

void PRNG::refresh (PRNG& src, const size_t input_len) {
  String s = src.getRandomString (input_len);
  refresh (s.toChar(), s.size());
}


String PRNG::getRandomString (size_t output_len) {
  String res;
  char buf[1024];

  for (size_t i = 0; i < output_len; i += 1024) {
    size_t rndlen = (output_len - i) >= 1024 ? 1024 : (output_len - i);
    getRandomBytes (buf, rndlen);
    res += String (buf, rndlen);
  }

  return res;
}


void PRNG::getRandomInt (mpz_t output, size_t output_nbits, bool init_mpz) {
  // TODO: vérifier les bornes pour output_nbits (0 et une valeur trop grande)

  char* raw_output;
  char* hexa_output;
  size_t size = (output_nbits + 7) / 8;
  size_t i;

  raw_output = (char*) malloc (size);
  if (raw_output == NULL)
    throw std::bad_alloc ();

  hexa_output = (char*) malloc (size * 2 + 1);
  if (hexa_output == NULL) {
    shred (raw_output, size);
    free (raw_output);
    throw std::bad_alloc ();
  }

  getRandomBytes (raw_output, size);

  // On jette de 0 à 7 bits en tête pour se conformer au nombre de bits attendu
  raw_output[0] &= (char) (0xff >> ((size * 8) - output_nbits));
  // On force le bit de poids fort à un pour avoir un nombre de la taille attendue
  raw_output[0] |= (char) (0x80 >> ((size * 8) - output_nbits));
  
  /* Transforme la sortie Barak_Halevi_next en chaîne ASCII, pour être mangée par mpz_set_str */
  for (i=0; i<size; i++) {
    hexa_output[2*i] = hexa_str[(raw_output[i] >> 4) & 0xf];
    hexa_output[2*i + 1] = hexa_str[raw_output[i] & 0xf];
  }
  hexa_output[2*size] = 0;
  if (init_mpz) mpz_init (output);
  mpz_set_str (output, hexa_output, 16);

  shred (hexa_output, 2*size);
  free (hexa_output);

  shred (raw_output, size);
  free (raw_output);
}

void PRNG::getRandomIntNB (mpz_t output, const mpz_t q, bool init_mpz) {
  // TODO: vérifier q positifs

  // On génère un entier de taille : taille(q)+64
  size_t size = mpz_sizeinbase(q, 2) + 64;
  getRandomInt(output, size, init_mpz);
  // On le réduit mod q
  mpz_mod(output, output, q); 
}

PRNG::~PRNG () {}

void PRNG::saveState () {}

CombinedPRNG::~CombinedPRNG () {
  delete (src1);

  if (src1 == src2)
    throw UnexpectedError ("CombinedPRNG called with two identical sources");
  else
    delete (src2);
}

void CombinedPRNG::refresh (const char* input, const size_t input_len) {
  src1->refresh (input, input_len);
  src2->refresh (input, input_len);
}

void CombinedPRNG::getRandomBytes (char* output, size_t output_len) {
  char* tmp = new char[output_len];
  src1->getRandomBytes (output, output_len);
  src2->getRandomBytes (tmp, output_len);

  for (size_t i=0; i<output_len; i++)
    output[i] ^= tmp[i];

  delete[] tmp;
}

void CombinedPRNG::saveState () {
  src1->saveState ();
  src2->saveState ();
}
