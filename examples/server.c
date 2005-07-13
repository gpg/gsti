/* server.c  -	An example how to use gsti
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

/*#define PUBKEY "dsa.pub"
  #define SECKEY "dsa.sec"*/
#define SECKEY "rsa.sec"

#define PGMNAME "ex-server: "

struct sock_ctx_s
{
  int listen_fd;
  int conn_fd;
};


void
dump_hexbuf (FILE * fp, const char *prefix, const unsigned char *buf,
	     size_t len)
{
  fputs (prefix, fp);
  for (; len; len--, buf++)
    fprintf (fp, "%02X ", *buf);
  putc ('\n', fp);
}

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
wait_connection (int * listen_fd, int * conn_fd)
{
  struct sockaddr_in name;
  struct sockaddr_in peer_name;
  socklen_t namelen;
  int one = 1;

  if (*listen_fd != -1)
    close (*listen_fd);

  *listen_fd = socket (PF_INET, SOCK_STREAM, 0);
  if (*listen_fd == -1)
    {
      fprintf (stderr, PGMNAME "socket() failed: %s", strerror (errno));
      exit (2);
    }

  if (setsockopt (*listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one))
    {
      fprintf (stderr, PGMNAME "setsocketopt() failed: %s", strerror (errno));
      exit (2);
    }

  name.sin_family = AF_INET;
  name.sin_port = htons (9000);
  name.sin_addr.s_addr = htonl (INADDR_ANY);
  if (bind (*listen_fd, (struct sockaddr *) &name, sizeof name))
    {
      fprintf (stderr, PGMNAME "bind() failed: %s", strerror (errno));
      exit (2);
    }

  if (listen (*listen_fd, 1))
    {
      fprintf (stderr, PGMNAME "listen() failed: %s\n", strerror (errno));
      exit (2);
    }

  namelen = sizeof peer_name;
  *conn_fd = accept (*listen_fd, (struct sockaddr *) &peer_name, &namelen);
  if (*conn_fd == -1)
    {
      fprintf (stderr, PGMNAME "accept() failed: %s\n", strerror (errno));
      exit (2);
    }
  close (*listen_fd);
  *listen_fd = -1;		/* not needed anymore */
}


static gsti_error_t
reader_loop (struct sock_ctx_s *ctx, gsti_ctx_t gsti_ctx)
{
  gsti_error_t err = 0;
  char buffer[512];
  int res;

  do
    {
      do
	{
	  res = read (ctx->conn_fd, buffer, sizeof(buffer));
	}
      while (res == -1 && errno == EINTR);
      
      if (res == -1)
	{
	  fprintf (stderr, PGMNAME "myread: error: %s\n", strerror (errno));
	  err = gsti_error_from_errno (errno);
	}
      else
	{
	  /*dump_hexbuf (stderr, "myread: ", buffer, res); */
	  
	  err = gsti_push_data (gsti_ctx, buffer, res);
	}
    }
  while (!err && res);

  return err;
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
	  return -1;
	}
      to_write -= n;
      p += n;
      nn += n;
    }
  while (to_write);
  *nbytes = nn;
  return 0;
}


gsti_error_t
mypkt_handler (gsti_ctx_t ctx, void *arg, gsti_pktdesc_t pkt)
{
  dump_hexbuf (stderr, "got packet: ", pkt->data, pkt->datalen);

  return 0;
}


/* Example how to influence the authentication in depence of its values.
   For example to reject one or more users system access or to perform checks
   if the users public key is valid (too short, not expired, revoked or
   whatever the local system policy is) */
static gsti_error_t
my_auth_cb (void * ctx, int authid, const void * buf, size_t buflen)
{
  FILE * fp;
  unsigned char keybuf[512];
  size_t n;

  if (!buflen)
    {
      fprintf (stderr, "** auth callback: no data.\n");
      return 0;
    }
  
  switch (authid)
    {
    case GSTI_AUTHID_USER:
      fprintf (stderr, "** auth callback user: id=%d val=%s (%d)\n",
               authid, (const char*)buf, buflen);
      /* do not allow root logins */
      if (!memcmp (buf, "root", 4))
        return gsti_error (GPG_ERR_INV_NAME);
      break;

    case GSTI_AUTHID_PUBKEY:
      fprintf (stderr, "** auth callback pubkey: id=%d len=%d\n",
               authid, buflen);
      /* check against rsa.pub */
      fp = fopen ("rsa.pub", "rb");
      if (!fp)
        return gsti_error_from_errno (errno);
      n = fread (keybuf, 1, 512, fp);
      fclose (fp);
      if (n != buflen || memcmp (buf, keybuf, buflen))
        return gsti_error (GPG_ERR_BAD_PUBKEY);
      break;
    }

  return 0;
}


int
main (int argc, char **argv)
{
  gpg_error_t err;
  struct sock_ctx_s fd;
  gsti_ctx_t ctx;

  if (argc)
    {
      argc--;
      argv++;
    }

  /* Initialize our local context object. */
  memset (&fd, 0, sizeof fd);

  /* Make sure we get secure memory. */
  gsti_control (GSTI_SECMEM_INIT);

  /* Initialize a GSTI context. */
  err = gsti_init (&ctx);
  log_rc (err, "init");

  /* This context should be logged at debug level. */
  gsti_set_log_level (ctx, GSTI_LOG_DEBUG);

  /* Register our host key. */
  err = gsti_set_hostkey (ctx, SECKEY);
  log_rc (err, "set_hostkey");

  /* Register our read/write functions. */
  gsti_set_packet_handler_cb (ctx, mypkt_handler, 0);
  gsti_set_writefnc (ctx, mywrite, &fd);

  /* Register our auth callback function */
  gsti_set_auth_callback (ctx, my_auth_cb, NULL);

  /* Set simple banner message */
  gsti_set_auth_banner (ctx, "Eddie lives somewhere in time...", 0);

#if 0
  err = gsti_set_service (ctx, "log-lines@gnu.org,dummy@gnu.org");
  log_err (err, "set-service");
#endif

  /* Wait for a client to connect. */
  wait_connection (&fd.listen_fd, &fd.conn_fd);

  /* Fire up the engine.  */
  err = gsti_start (ctx);
  log_rc (err, "start");

  /* Process incoming data.  */
  err = reader_loop (&fd, ctx);
  log_rc (err, "reader_loop");

  /* Release the context. */
  gsti_deinit (ctx);

  /* And the secure memory. */
  gsti_control (GSTI_SECMEM_RELEASE);

  return 0;
}
