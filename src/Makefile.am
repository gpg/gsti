## Process this file with automake to produce Makefile.in
# Copyright (C) 1999, 2000 Free Software Foundation
# Copyright (C) 2002 Timo Schulz
# Copyright (C) 2004 g10 Code GmbH
#
# This file is part of GSTI.
#
# GSTI is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# GSTI is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA


EXTRA_DIST = gsti-config.in  gsti.m4
bin_SCRIPTS = gsti-config
include_HEADERS = gsti.h
lib_LTLIBRARIES = libgsti.la
m4datadir = $(datadir)/aclocal
m4data_DATA = gsti.m4

AM_CFLAGS = @GPG_ERROR_CFLAGS@ @LIBGCRYPT_CFLAGS@

libgsti_la_LDFLAGS = -version-info \
       @LIBGSTI_LT_CURRENT@:@LIBGSTI_LT_REVISION@:@LIBGSTI_LT_AGE@

libgsti_la_SOURCES = \
	gsti.h \
	ssh.h \
	error.c \
	bstring.h bstring.c \
	buffer.h buffer.c \
	auth.c \
	api.h \
	types.h \
	pubkey.c pubkey.h \
	logging.c \
	main.c \
	fsm.c \
	channel.c \
	memory.h memory.c \
	utils.h utils.c \
	stream.h stream.c \
	packet.h packet.c \
	kex.h kex.c \
	zlib.c \
	moduli.h

