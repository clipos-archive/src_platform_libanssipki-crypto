# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2000-2018 ANSSI. All Rights Reserved.
AM_CPPFLAGS= -I../lib/
AM_LDFLAGS= -L../lib/ -lanssipki-crypto

bin_PROGRAMS = anssipki-genrsa
anssipki_genrsa_SOURCES = anssipki-genrsa.cpp

check_PROGRAMS = test_sha1 test_sha2 test_barak_halevi test_prime test_prime_perfs test_RSA_factor test_rsa

test_sha1_SOURCES = test_sha1.cpp
test_sha2_SOURCES = test_sha2.cpp
test_barak_halevi_SOURCES = test_barak_halevi.cpp
test_prime_SOURCES = test_prime.cpp
test_prime_perfs_SOURCES = test_prime_perfs.cpp
test_RSA_factor_SOURCES = test_RSA_factor.cpp
test_rsa_SOURCES = test_rsa.cpp

#TESTS =
TESTS = test_sha1 test_sha2 test_barak_halevi test_prime test_prime_perfs test_rsa
