/* stream.c - input output buffering
   Copyright (C) 1999 Werner Koch
   Copyright (C) 2002 Timo Schulz
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <gcrypt.h>
#include <errno.h>

#include "types.h"
#include "memory.h"
#include "stream.h"


#define STREAM_BUFSIZE 512

/* Create a new read stream.  */
gsti_error_t
_gsti_read_stream_new (read_stream_t * r_shd,
                       gsti_read_fnc_t readfnc, void * fnc_ctx)
{
  read_stream_t a;

  a = _gsti_xcalloc (1, sizeof *a + STREAM_BUFSIZE - 1);
  a->readfnc = readfnc;
  a->fnc_ctx = fnc_ctx;
  a->size = STREAM_BUFSIZE;
  *r_shd = a;
  
  return 0;
}


void
_gsti_read_stream_free (read_stream_t a)
{
  _gsti_free (a);
}


/* This is the function version of the stream_get() macro.  It is used
   internally to to the underflow handling.  It may be used directly.
   the function returns -1 on EOF.  */
int
_gsti_stream_getbyte (read_stream_t a)
{
  gsti_error_t rc;
  size_t n;

  if (a->start < a->len)
    return a->buf[a->start++];
  if (a->read_eof)
    return -1;

  a->len = 0;
  a->start = 0;
  n = a->size;
  rc = a->readfnc (a->fnc_ctx, a->buf, n, &n);
  if (rc)
    {
      a->error = rc;
      return -1;
    }
  if (!n)
    {
      a->read_eof = 1;
      return -1;
    }
  a->len = n;
  return a->buf[a->start++];
}


/* Read NBYTES from A and store it in buffer. If BUFFER is NULL the
   given anpount is actually skipped.  Returns 0 on success or an
   error code.  */
gsti_error_t
_gsti_stream_readn (read_stream_t a, byte * buffer, size_t nbytes)
{
  int c;

  while (nbytes)
    {
      c = _gsti_stream_get (a);
      if (c == -1)
        return a->error ? a->error : gsti_error (GPG_ERR_EOF);
      if (buffer)
	{
	  *buffer = c;
	  buffer++;
	}
      nbytes--;
    }

  return 0;
}


gsti_error_t
_gsti_write_stream_new (write_stream_t * r_shd,
                        gsti_write_fnc_t writefnc, void * fnc_ctx)
{
  write_stream_t a;

  a = _gsti_xcalloc (1, sizeof *a + STREAM_BUFSIZE - 1);
  a->writefnc = writefnc;
  a->fnc_ctx = fnc_ctx;
  a->size = STREAM_BUFSIZE;
  *r_shd = a;
  
  return 0;
}


void
_gsti_write_stream_free (write_stream_t a)
{
  _gsti_free (a);
}


/* This is the function version of the stream_put() macro.  It is used
   internally to do the flush handling.  It may be used directly.  */
int
_gsti_stream_putbyte (write_stream_t a, int c)
{
  size_t n;
  gsti_error_t rc;

  if (!a->used)
    return 0;

  rc = a->writefnc (a->fnc_ctx, a->buf, a->used, &n);
  if (rc)
    {
      a->error = rc;
      return -1;
    }
  a->used = 0;
  return _gsti_stream_put (a, c);
}


gsti_error_t
_gsti_stream_flush (write_stream_t a)
{
  size_t n;
  gsti_error_t rc;

  rc = a->used ? a->writefnc (a->fnc_ctx, a->buf, a->used, &n) : 0;
  if (rc)
    {
      a->error = rc;
      return rc;
    }
  a->used = 0;
  rc = a->writefnc (a->fnc_ctx, NULL, 0, NULL);
  if (rc)
    {
      a->error = rc;
      return rc;
    }
  return 0;
}


/* Write NBYTES from buffer. If BUFFER is NULL the strong random bytes
   are written.  Returns 0 on success or an error code.  */
gsti_error_t
_gsti_stream_writen (write_stream_t a, const void *buffer, size_t nbytes)
{
  gsti_error_t err = 0;
  const unsigned char *s = buffer;

  if (buffer)
    {
      while (nbytes)
	{
	  if (_gsti_stream_put (a, *s))
	    {
              err = a->error;
	      break;
	    }
	  s++;
	  nbytes--;
	}
    }
  else
    {				/* write random padding */
      byte * pad = _gsti_xcalloc (1, nbytes);
      gcry_create_nonce (pad, nbytes);
      err = _gsti_stream_writen (a, pad, nbytes);
      gcry_free (pad);
    }

  return err;
}
