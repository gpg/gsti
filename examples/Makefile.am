## Process this file with automake to produce Makefile.in

noinst_PROGRAMS = server client

client_SOURCES = client.c
server_SOURCES = server.c


INCLUDES = -I$(top_srcdir)/src $(GCRYPT_CFLAGS)
LDADD = ../src/libgsti.la $(GCRYPT_LIBS)

