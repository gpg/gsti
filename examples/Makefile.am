## Process this file with automake to produce Makefile.in

noinst_PROGRAMS = server client keytool

client_SOURCES = client.c
server_SOURCES = server.c
keytool_SOURCES = keytool.c

INCLUDES = -I$(top_srcdir)/src $(LIB_GCRYPT_CFLAGS)
LDADD = ../src/libgsti.la $(LIB_GCRYPT_LIBS)

