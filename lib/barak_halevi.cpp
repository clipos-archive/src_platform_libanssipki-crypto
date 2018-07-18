// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2018 ANSSI. All Rights Reserved.
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
// Génération de clés de signature RSA / DSA / ECDSA (version 1.2)
//
// Routines de génération de nombres aléatoires à la Barak-Halevi
//
//++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#include "anssipki-crypto.h"
#include <anssipki-common.h>

#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <iostream>



// Remarque importante :
// ---------------------
// On considère std::bad_alloc comme une erreur fatale qui doit
// uniquement être rattrapée dans le main () du programme principal
// pour permettre l'appel correct de tous les destructeurs.



/* input est de longueur input_len en octets
   output est de longueur BARAK_HALEVI_ONE_BLOCK_SIZE si double_block vaut false
                          2 * BARAK_HALEVI_ONE_BLOCK_SIZE si double_block vaut true

   generic_fun (input, input_len, output, x, false) effectue l'opération
     output = HASH ([x] | input)

   generic_fun (input, input_len, output, x, true) effectue l'opération
     output = HASH ([x] | input) | HASH ([x+1] | input)
 */
static void generic_fun (const char* input, size_t input_len, char* output, char x, bool double_block) {
  char* tobehashed = NULL;

  // On a besoin d'un octet supplémentaire pour stocker le compteur
  tobehashed = (char*) malloc (input_len + 1);
  if (tobehashed == NULL)
    throw std::bad_alloc ();

  tobehashed[0] = x;
  memcpy (tobehashed + 1, input, input_len);
  UNDERYLING_HASH_FUNCTION (tobehashed, input_len + 1, output);

  if (double_block) {
    tobehashed[0]++;
    UNDERYLING_HASH_FUNCTION (tobehashed, input_len + 1,
			      output + BARAK_HALEVI_ONE_BLOCK_SIZE);
  }

  free (tobehashed);
}



// G1 utilise x=0 et x=1 (car on renvoie quelquechose deux fois plus grand que l'état interne)
// output doit avoir pour taille 2 * BARAK_HALEVI_STATE_BYTE_SIZE
static inline void G (const char* state, char* output) {
  generic_fun (state, BARAK_HALEVI_STATE_BYTE_SIZE, output, 0, true);
}

// G2 utilise x=3
// output doit avoir pour taille BARAK_HALEVI_STATE_BYTE_SIZE
static inline void G_prime (const char* state, char* output) {
  generic_fun (state, BARAK_HALEVI_STATE_BYTE_SIZE, output, 3, false);
}
  
// Extract utilise x=2
// output doit avoir pour taille BARAK_HALEVI_STATE_BYTE_SIZE
static inline void Extract (const char* input, size_t input_len, char* output) {
  generic_fun (input, input_len, output, 2, false);
}



BarakHaleviPRNG::BarakHaleviPRNG () {
  memset (_state, 0, BARAK_HALEVI_STATE_BYTE_SIZE);
}


BarakHaleviPRNG::~BarakHaleviPRNG () {
  shred (_state, BARAK_HALEVI_STATE_BYTE_SIZE);
}


/* Raffraîchissement de l'état Barak-Halevi */
void BarakHaleviPRNG::refresh (const char* input_x, size_t input_x_len) {
  char Ext_result [BARAK_HALEVI_STATE_BYTE_SIZE];
  size_t i;

  /* Extract */
  Extract (input_x, input_x_len, Ext_result);
  
  /* Xor le résultat avec l'état */
  for (i=0; i<BARAK_HALEVI_STATE_BYTE_SIZE; i++)
    _state[i] ^= Ext_result[i];
    
  /* generic_fun utilisant une variable temporaire "tobehashed", on
     peut donner comme entrée et comme sortie le même pointeur et
     gagner un memcpy */
  G_prime (_state, _state);
  
  shred (Ext_result, BARAK_HALEVI_STATE_BYTE_SIZE);
}


/* Fonction next, pour sortir de l'aléa de l'état */
void BarakHaleviPRNG::getRandomBytes (char* output, size_t output_len) {
  char G1_result [2 * BARAK_HALEVI_STATE_BYTE_SIZE];
  size_t howmuch;

  while (output_len > 0) {
    G (_state, G1_result);

    howmuch = (output_len > BARAK_HALEVI_STATE_BYTE_SIZE) ? BARAK_HALEVI_STATE_BYTE_SIZE : output_len;
    memcpy (output, G1_result, howmuch);
    memcpy (_state, G1_result + BARAK_HALEVI_STATE_BYTE_SIZE, BARAK_HALEVI_STATE_BYTE_SIZE);

    output += howmuch;
    output_len -= howmuch;
  }

  shred (G1_result, 2 * BARAK_HALEVI_STATE_BYTE_SIZE);
}




StatefulBarakHaleviPRNG::StatefulBarakHaleviPRNG (const char* filename,
						  const int autoSaveEvery) {
  bool error = true;
  int fd;
  ssize_t  res;

  _filename = NULL;
  _autoSaveEvery = 1;
  counter = 0;

  // TODO: Libérer filename + mise à NULL en cas d'exception

  fd = open (filename, O_RDONLY);
  if (fd < 0) goto end;

  _filename = new char[strlen (filename) + 1];
  strcpy (_filename, filename);

  _autoSaveEvery = autoSaveEvery;

  while (flock (fd, LOCK_SH) < 0) {
    if (errno == EINTR) continue;
    goto close_and_return;
  }

  res = reallyRead (fd, _state, BARAK_HALEVI_STATE_BYTE_SIZE);

  if (res != BARAK_HALEVI_STATE_BYTE_SIZE)
    goto close_and_return;

  while (flock (fd, LOCK_UN) < 0) {
    if (errno == EINTR) continue;
    goto close_and_return;
  }
  error = false;

 close_and_return:
  close (fd);
 end:
  if (error)
    throw ANSSIPKIException (E_CRYPTO_PRNG_STATE_ERROR, filename);  
}


StatefulBarakHaleviPRNG::StatefulBarakHaleviPRNG (const char* filename, PRNG& source,
						  const int autoSaveEvery) {
  _filename = new char[strlen (filename) + 1];
  strcpy (_filename, filename);

  source.getRandomBytes (_state, BARAK_HALEVI_STATE_BYTE_SIZE);

  _autoSaveEvery = autoSaveEvery;
  counter = 0;

  saveState();
}


StatefulBarakHaleviPRNG::StatefulBarakHaleviPRNG (const char* filename, char* seed, size_t seed_len,
						  const int autoSaveEvery) {
  _filename = new char[strlen (filename) + 1];
  strcpy (_filename, filename);

  _autoSaveEvery = autoSaveEvery;
  counter = 0;

  refresh (seed, seed_len);
}


StatefulBarakHaleviPRNG::~StatefulBarakHaleviPRNG () {
  saveState ();
  if (_filename != NULL)
    delete[] _filename;
}



void StatefulBarakHaleviPRNG::refresh (const char* input, const size_t input_len) {
  BarakHaleviPRNG::refresh (input, input_len);
  saveState();
}

void StatefulBarakHaleviPRNG::getRandomBytes (char* output, size_t output_len) {
  BarakHaleviPRNG::getRandomBytes (output, output_len);
  if (++counter >= _autoSaveEvery) {
    saveState ();
    counter = 0;
  }
}



void StatefulBarakHaleviPRNG::saveState () {
  bool error = true;
  int fd;
  ssize_t res;

  fd = open (_filename, O_WRONLY | O_CREAT, 0600);
  if (fd < 0) goto end;

  while (flock (fd, LOCK_SH) < 0) {
    if (errno == EINTR) continue;
    goto close_and_return;
  }

  while (ftruncate (fd, 0) < 0) {
    if (errno == EINTR) continue;
    goto close_and_return;
  }

  res = reallyWrite (fd, _state, BARAK_HALEVI_STATE_BYTE_SIZE);

  if (res != BARAK_HALEVI_STATE_BYTE_SIZE)
    goto close_and_return;

  while (flock (fd, LOCK_UN) < 0) {
    if (errno == EINTR) continue;
    goto close_and_return;
  }
  error = false;

 close_and_return:
  close (fd);

 end:
  if (error) throw ANSSIPKIException (E_CRYPTO_PRNG_STATE_ERROR, _filename);
}
