/* client.c  -	An example how to use gsti
   Copyright (C) 1999 Werner Koch
   Copyright (C) 2004 g10 Code GmbH

   This file is part of GSTI.

   GSTI is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   GSTI is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA  */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <gsti.h>

#define PGMNAME "ex-client: "
/*#define SECKEY "dsa.sec"*/
#define SECKEY "rsa.sec"

struct sock_ctx_s 
{
  int conn_fd;
};


static void
log_rc (int rc, const char *text)
{
  const char *s;
  if (!*(s = gsti_strerror (rc)) || !strcmp (s, "[?]"))
    fprintf (stderr, PGMNAME "gsti_%s: rc=%d\n", text, rc);
  else
    fprintf (stderr, PGMNAME "gsti_%s: %s\n", text, s);
}

static void
make_connection (int *r_conn_fd, const char *host)
{
  struct sockaddr_in name;
  struct hostent *hostinfo;
  int conn_fd;

  *r_conn_fd = -1;
  conn_fd = socket (PF_INET, SOCK_STREAM, 0);
  if (conn_fd == -1)
    {
      fprintf (stderr, PGMNAME "socket() failed: %s\n", strerror (errno));
      exit (2);
    }

  hostinfo = gethostbyname (host);
  if (!hostinfo)
    {
      fprintf (stderr, PGMNAME "unknown host `%s'\n", host);
      exit (1);
    }
  name.sin_family = AF_INET;
  name.sin_port = htons (9000);
  name.sin_addr = *(struct in_addr *) hostinfo->h_addr;
  if (connect (conn_fd, (struct sockaddr *) &name, sizeof name))
    {
      fprintf (stderr, PGMNAME "connect() failed: %s\n", strerror (errno));
      exit (2);
    }
  *r_conn_fd = conn_fd;
}


static gsti_error_t
myread (void * ctx, void *buffer, size_t to_read, size_t * nbytes)
{
  struct sock_ctx_s * c = ctx;
  int n;

  do
    {
      n = read (c->conn_fd, buffer, to_read);
    }
  while (n == -1 && errno == EINTR);
  if (n == -1)
    {
      fprintf (stderr, PGMNAME "myread: error: %s\n", strerror (errno));
      return gsti_error_from_errno (errno);
    }
  /*dump_hexbuf( stderr, "myread: ", buffer, n ); */
  *nbytes = n;
  return 0;
}


static gsti_error_t
mywrite (void * ctx, const void *buffer, size_t to_write, size_t *nbytes)
{
  struct sock_ctx_s * c = ctx;
  int n, nn=0;
  const char *p = buffer;

  if (!buffer)
    return 0;			/* no need for flushing */
  do
    {
      /*dump_hexbuf( stderr, "mywrite: ", p, nbytes ); */
      n = write (c->conn_fd, p, to_write);
      if (n == -1)
	{
	  fprintf (stderr, PGMNAME "mywrite: error: %s\n", strerror (errno));
	  return gsti_error_from_errno (errno);
	}
      to_write -= n;
      p += n;
      nn += n;
    }
  while (to_write);
  *nbytes = nn;
  return 0;
}



int
main (int argc, char **argv)
{
  struct sock_ctx_s fd;
  gpg_error_t err;
  gsti_ctx_t ctx;
  struct gsti_pktdesc_s pkt;
  unsigned short c_prefs[8] = {0}, h_prefs[3] = {0};
  int i;

  if (argc)
    {
      argc--;
      argv++;
    }

  /* Initialize our local context object. */
  memset (&fd, 0, sizeof fd);

  /* Make sure we get secure memory. */
  gsti_control (GSTI_SECMEM_INIT);

  /* We are single-threaded, thus no locking is required. */
  gsti_control (GSTI_DISABLE_LOCKING);

  /* Initialize a GSTI context. */
  err = gsti_init (&ctx);
  log_rc (err, "init");

  /* This context should be logged at debug level. */
  gsti_set_log_level (ctx, GSTI_LOG_DEBUG);

  /* Enable DH group exchange */
  /*gsti_set_dhgex (ctx, 1024, 1024, 4096);*/

  /* Set personal kex preferences */
  c_prefs[0] = GSTI_CIPHER_CAST128;
  c_prefs[1] = GSTI_CIPHER_SERPENT128;
  c_prefs[2] = 0;
  err = gsti_set_kex_prefs (ctx, GSTI_PREFS_ENCR, c_prefs, 2);
  log_rc (err, "set_kex_prefs (encr)");

  h_prefs[0] = GSTI_HMAC_SHA1;
  h_prefs[1] = GSTI_HMAC_RMD160;
  h_prefs[2] = GSTI_HMAC_MD5;
  h_prefs[3] = 0;
  err = gsti_set_kex_prefs (ctx, GSTI_PREFS_HMAC, h_prefs, 3);
  log_rc (err, "set_kex_prefs (hmac)");

  /* Register our read/write functions. */
  gsti_set_readfnc (ctx, myread, &fd);
  gsti_set_writefnc (ctx, mywrite, &fd);

  /* Register a key and a user. */
  err = gsti_set_client_key (ctx, SECKEY);
  log_rc (err, "set_client_key");
  err = gsti_set_client_user (ctx, "twoaday");
  log_rc (err, "set_client_user");

#if 0
  rc = gsti_set_service (ctx, "log-lines@gnu.org");
  log_rc (rc, "set-service");
#endif

  /* Create a conenction to the host given on the command line or to
     localhost if no args are given. */
  make_connection (&fd.conn_fd, argc ? *argv : "localhost");

  /* Start the processing by sending 2 simple data packets. */
  for (i = 0; i < 2; i++)
    {
      memset (&pkt, 0, sizeof pkt);
      pkt.data = "\xf0\x01\x00\x00\x00\x04" "hallo" "\x00\x00\x00\x00";
      pkt.datalen = 15;
      err = gsti_put_packet (ctx, &pkt);
      log_rc (err, "put_packet");

      err = gsti_put_packet (ctx, NULL);
      log_rc (err, "flush_packet");

      printf ("seqno %lu\n", pkt.seqno);
    }

  /* Release the context. */
  gsti_deinit (ctx);

  /* And the secure memory. */
  gsti_control (GSTI_SECMEM_RELEASE);

  return 0;
}
