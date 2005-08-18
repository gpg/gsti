# Configure.ac script for GSTI
#     Copyright (C) 1999 Werner Koch
#     Copyright (C) 2004 g10 COde GmbH
#
# This file is part of GSTI.
#
# GSTI is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2.1 of the License, or
# (at your option) any later version.
#
# GSTI is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
# or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
# License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
#
# (Process this file with autoconf to produce a configure script.)
AC_PREREQ(2.59)
min_automake_version="1.9.3"

# Version number: Remember to change it immediately *after* a release
# but remove a "-cvs" prefix right *before* a release and append it
# soon later.
AC_INIT(gsti, 0.3.0, gcrypt-devel@gnupg.org)

# LT Version numbers, remember to change them just *before* a release.
#   (Interfaces removed:    CURRENT++, AGE=0, REVISION=0)
#   (Interfaces added:      CURRENT++, AGE++, REVISION=0)
#   (No interfaces changed:                   REVISION++)
LIBGSTI_LT_CURRENT=0
LIBGSTI_LT_AGE=0
LIBGSTI_LT_REVISION=1

# If the API is changed in an incompatible way: increment the next counter.
LIBGSTI_CONFIG_API_VERSION=1

#
# Required library versions.
#
NEED_GPG_ERROR_VERSION=1.0

NEED_LIBGCRYPT_API=1
NEED_LIBGCRYPT_VERSION=1.2.0


#
# Setup standard defines
#
PACKAGE=$PACKAGE_NAME
VERSION=$PACKAGE_VERSION

AC_CONFIG_SRCDIR([src/gsti.h])
AM_INIT_AUTOMAKE($PACKAGE, $VERSION)
AM_CONFIG_HEADER(config.h)

AC_SUBST(LIBGSTI_LT_CURRENT)
AC_SUBST(LIBGSTI_LT_AGE)
AC_SUBST(LIBGSTI_LT_REVISION)
AC_SUBST(PACKAGE)
AC_SUBST(VERSION)
AC_DEFINE_UNQUOTED(PACKAGE, "$PACKAGE", [Name of this package])
AC_DEFINE_UNQUOTED(VERSION, "$VERSION", [Version of this package])


AC_GNU_SOURCE
AM_MAINTAINER_MODE

have_gpg_error=no
have_libgcrypt=no 




#
# Configure options
#
AC_MSG_CHECKING([whether to enable internal ZLIB compression support])
AC_ARG_ENABLE(newzlib,
    [  --enable-newzlib          enable internal ZLIB compression support],
    use_newzlib=yes, use_newzlib=no)
AC_MSG_RESULT($use_newzlib)
if test "$use_newzlib" = yes; then
    AC_DEFINE(USE_NEWZLIB, 1, [Define to include internal ZLIB support])
fi


#
# Checks for programs
#
missing_dir=`cd $ac_aux_dir && pwd`
AM_MISSING_PROG(ACLOCAL, aclocal, $missing_dir)
AM_MISSING_PROG(AUTOCONF, autoconf, $missing_dir)
AM_MISSING_PROG(AUTOMAKE, automake, $missing_dir)
AM_MISSING_PROG(AUTOHEADER, autoheader, $missing_dir)
AM_MISSING_PROG(MAKEINFO, makeinfo, $missing_dir)
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

AC_C_INLINE

AM_PROG_LIBTOOL

if test "$GCC" = yes; then
    CFLAGS="$CFLAGS -Wall -Wcast-align -Wshadow -Wstrict-prototypes"
fi


#
# Checks for header files
#
AC_HEADER_STDC
AC_CHECK_HEADERS([string.h])


#
# Checks for typedefs and structures
#

#
# Checks for compiler features
#

#
# Checks for library functions
#

#
# libgpg-error is a library with error codes shared between GnuPG
# related projects.
#
AM_PATH_GPG_ERROR("$NEED_GPG_ERROR_VERSION",
                  have_gpg_error=yes,have_gpg_error=no)
AC_DEFINE(GPG_ERR_SOURCE_DEFAULT, GPG_ERR_SOURCE_GSTI,
          [The default error source for GPGME.])

#
# Libgcrypt is our generic crypto library
#
AM_PATH_LIBGCRYPT("$NEED_LIBGCRYPT_API:$NEED_LIBGCRYPT_VERSION",
        have_libgcrypt=yes,have_libgcrypt=no)   


#
# Checks for system services
#

#
# Make the version number in src/gsti.h is the same as the one here.
# (this is easier than to have a .in file just for one substitution)
#
GNUPG_FIX_HDR_VERSION([src/gsti.h], GSTI_VERSION)

#
# Stuff to be used is gsti-config
#
LIBGSTI_CONFIG_LIBS="-lgsti"
LIBGSTI_CONFIG_CFLAGS=""
AC_SUBST(LIBGSTI_CONFIG_API_VERSION)
AC_SUBST(LIBGSTI_CONFIG_LIBS)
AC_SUBST(LIBGSTI_CONFIG_CFLAGS)


#
# Print errors here so that they are visible all
# together and the user can acquire them all together.
#
die=no
if test "$have_gpg_error" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***  
*** You need libgpg-error to build this program.
**  This library is for example available at
***   ftp://ftp.gnupg.org/pub/gcrypt/alpha/libgpg-error
*** (at least version $NEED_GPG_ERROR_VERSION is required.)
***]])
fi
if test "$have_libgcrypt" = "no"; then
   die=yes
   AC_MSG_NOTICE([[
***  
*** You need libgcrypt to build this program.
**  This library is for example available at
***   ftp://ftp.gnupg.org/pub/gcrypt/alpha/libgcrypt/
*** (at least version $NEED_LIBGCRYPT_VERSION using API $NEED_LIBGCRYPT_API) is required.)
***]])
fi
if test "$die" = "yes"; then
    AC_MSG_ERROR([[
***
*** Required libraries not found. Please consult the above messages
*** and install them before running configure again.
***]])
fi


#
# Write config files
#
AC_CONFIG_FILES([
Makefile
src/Makefile
src/gsti-config
examples/Makefile
tests/Makefile
doc/Makefile
])
AC_OUTPUT
