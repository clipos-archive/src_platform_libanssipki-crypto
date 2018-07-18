# SPDX-License-Identifier: LGPL-2.1-or-later
# Copyright © 2000-2018 ANSSI. All Rights Reserved.
AC_PREREQ(2.59)

m4_define(lib_name, libanssipki-crypto)
m4_define(lib_author, [clipos@ssi.gouv.fr])

# Increment if the interface has additions, changes, removals.
m4_define(version_major, 2)
# Increment any time the source changes; set to
# 0 if you increment CURRENT
m4_define(version_minor, 1)
m4_define(version_micro, 0)
# Increment if any interfaces have been added; set to 0
# if any interfaces have been removed. removal has
# precedence over adding, so set to 0 if both happened.
m4_define(version_age, 0)


AC_INIT(lib_name, version_major.version_minor.version_micro, lib_author)
AM_INIT_AUTOMAKE([1.10])


# libtool shared library version
LIB_CURRENT=version_major()
LIB_REVISION=version_micro()
LIB_AGE=0
VERSION_INFO="$LIB_CURRENT:$LIB_REVISION:$LIB_AGE"
AC_SUBST(VERSION_INFO)
LIB_CURRENT_MINUS_AGE=`expr $LIB_CURRENT - $LIB_AGE`
AC_SUBST(LIB_CURRENT_MINUS_AGE)



AC_PROG_CXX
AC_PROG_LIBTOOL
AC_STDC_HEADERS
AC_PROG_INSTALL

PKG_PROG_PKG_CONFIG
AC_CONFIG_FILES([libanssipki-crypto.pc])

AC_CHECK_LIB(gmp, __gmpz_init, ,
	     [AC_MSG_ERROR(["Could not find libgmp"])])
AC_CHECK_LIB(z, deflate, ,
	     [AC_MSG_ERROR(["Could not find libz"])])

AC_CHECK_HEADERS([stdint.h sys/types.h])

dnl Use lots of warning flags with GCC
WARN_CFLAGS=""
WARN_CXXFLAGS=""
if test "x$GCC" = "xyes"; then
        WARN_CFLAGS="-Wall -Wextra -Werror\
        -Wstrict-prototypes \
        -Wcast-qual -Wcast-align -Wpointer-arith \
        -Wwrite-strings -Wconversion \
        -Wnested-externs"
        WARN_CXXFLAGS="-Wall -Wextra -Werror\
        -Wcast-qual -Wcast-align -Wpointer-arith \
        -Wwrite-strings -Wconversion"
fi
CFLAGS="$WARN_CFLAGS -O3 -fPIC -fstack-protector-all"
CXXFLAGS="$WARN_CXXFLAGS -O3 -fPIC -fstack-protector-all"




usrlibdir="/usr${PREFIX#/usr}/lib"
AC_SUBST(usrlibdir)


AC_CONFIG_FILES([Makefile lib/Makefile exe/Makefile])

AC_OUTPUT
