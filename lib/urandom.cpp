// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright © 2000-2018 ANSSI. All Rights Reserved.
#include "anssipki-crypto.h"
#include <anssipki-common.h>

#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

DevUrandomPRNG::DevUrandomPRNG () {
  fd = open ("/dev/urandom", O_RDONLY);
  if (fd < 0)
    throw ANSSIPKIException (E_CRYPTO_PRNG_STATE_ERROR, "/dev/urandom");
}

DevUrandomPRNG::~DevUrandomPRNG () {
  close (fd);
}

void DevUrandomPRNG::getRandomBytes (char* output, size_t output_len) {
  ssize_t res = reallyRead (fd, output, output_len);

  if (res <= 0 || res != (ssize_t) output_len)
    throw ANSSIPKIException (E_CRYPTO_PRNG_STATE_ERROR, "/dev/urandom");
}



