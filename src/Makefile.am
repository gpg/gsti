# Process this file with automake to produce Makefile.in

EXTRA_DIST = gsti-config.in  gsti.m4

bin_SCRIPTS = gsti-config

m4datadir = $(datadir)/aclocal
m4data_DATA = gsti.m4

include_HEADERS = gsti.h

lib_LTLIBRARIES = libgsti.la

libgsti_la_LDFLAGS = #-version-info 0:0:0
libgsti_la_SOURCES = \
	gsti.h \
	api.h \
	types.h \
	pubkey.c \
	main.c \
	fsm.c \
	memory.h memory.c \
	utils.h utils.c \
	stream.h stream.c \
	packet.h packet.c \
	kex.h kex.c \
	buffer.c buffer.h		

INCLUDES = -I$(top_srcdir)/lib $(LIB_GCRYPT_CFLAGS)
LDADD = $(LIB_GCRYPT_LIBS)
