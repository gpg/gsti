## Process this file with automake to produce Makefile.in

noinst_PROGRAMS = server client keytool dump-mod

EXTRA_DIST = dsa.pub dsa.sec

INCLUDES = -I$(top_srcdir)/src $(LIBGCRYPT_CFLAGS)

client_SOURCES = client.c
server_SOURCES = server.c
keytool_SOURCES = keytool.c
dump_mod_SOURCES = dump-mod.c

client_LDADD = ../src/libgsti.la $(LIBGCRYPT_LIBS)
server_LDADD = ../src/libgsti.la $(LIBGCRYPT_LIBS)
keytool_LDADD = ../src/libgsti.la $(LIBGCRYPT_LIBS)



