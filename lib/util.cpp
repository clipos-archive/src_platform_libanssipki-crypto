// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
/**
 * @file
 * @author Olivier Levillain <clipos@ssi.gouv.fr>
 *
 * @section DESCRIPTION
 *
 * This file contains some useful functions.
 */


#include "anssipki-common.h"

#include <unistd.h>
#include <errno.h>
#include <zlib.h>
#include <string.h>



/********************
 * Useful Functions *
 ********************/

ssize_t reallyWrite (int fd, const char* data, size_t len) {
  ssize_t n;
  ssize_t written = 0;

  while (len > 0) {
    n = write (fd, data, len);
    switch (n) {
    case -1:
      if (errno == EINTR)
	continue;
      else
	return -1;

    default:
      len -= n;
      written += n;
      data += n;
    }
  }

  return written;
}


ssize_t reallyRead (int fd, char* data, size_t len) {
  ssize_t n;
  ssize_t bytes_read = 0;

  while (len > 0) {
    n = read (fd, data, len);
    switch (n) {
    case -1:
      if (errno == EINTR)
	continue;
      else
	return -1;

    case 0:
      return bytes_read;

    default:
      len -= n;
      bytes_read += n;
      data += n;
    }
  }

  return bytes_read;
}


void mpz_shred (mpz_t n) {
  int i;

  /// We mark tab as volatile to avoid optimizations during the compilation
  volatile mp_limb_t* tab = n[0]._mp_d;

  for(i=0; i<n[0]._mp_alloc; i++)
    tab[i]=0;

  for(i=0; i<n[0]._mp_alloc; i++)
    tab[i]--;

  mpz_clear(n);
}


void shred (char* buf, size_t len) {
  volatile char* s = buf;
  for (size_t i=0; i < len; i++) s[i]='\xff';  
  for (size_t i=0; i < len; i++) s[i]='\x00';
}


size_t naive_entropy (const String& s) {
  static const uint BUFFER_SIZE = 1024;
  const size_t len = s.size();

  z_stream strm;
  Bytef out[BUFFER_SIZE];
  Bytef* in;
  size_t res = 0;

  /// Stream initialization
  strm.zalloc = Z_NULL;
  strm.zfree = Z_NULL;
  strm.opaque = Z_NULL;
  if (deflateInit(&strm, Z_DEFAULT_COMPRESSION) != Z_OK)
    throw UnexpectedError ("Erreur lors de l'initialisation de la bibliothèque zlib.");

  /// The entry is the String s
  strm.avail_in = (uInt) len;
  strm.next_in = (in = new Bytef[len]);
  memcpy (in, s.toChar(), len);

  /// This loop feeds the compressing engine with its input
  do {
    strm.avail_out = BUFFER_SIZE;
    strm.next_out = out;
    if (deflate(&strm, Z_FINISH) == Z_STREAM_ERROR)
      throw UnexpectedError ("Erreur lors de la compression de la chaîne de caractères.");

    res += BUFFER_SIZE - strm.avail_out;
  } while (strm.avail_out == 0);

  if (strm.avail_in != 0)
    throw UnexpectedError ("Erreur lors de la compression de la chaîne de caractères.");


  /// We do a bit of cleaning
  shred ((char*) in, len);
  delete[] in;
  shred ((char*) out, BUFFER_SIZE);
  (void)deflateEnd(&strm);

  return res;
}
