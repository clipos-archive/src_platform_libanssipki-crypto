# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2000-2018 ANSSI. All Rights Reserved.
lib_LTLIBRARIES = libanssipki-crypto.la

libanssipki_crypto_la_SOURCES = \
	string.cpp exception.cpp util.cpp \
	asn1.cpp \
	tbs.cpp \
	sha1.cpp sha2.cpp \
	prng.cpp urandom.cpp barak_halevi.cpp \
	prime.cpp rsa.cpp

libanssipki_crypto_la_LDFLAGS = -version-info @VERSION_INFO@

include_HEADERS = anssipki-common.h anssipki-asn1.h anssipki-crypto.h

