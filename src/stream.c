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
READ_STREAM
_gsti_read_stream_new (GSTI_READ_FNC readfnc)
{
  READ_STREAM a;

  a = _gsti_xcalloc (1, sizeof *a + STREAM_BUFSIZE - 1);
  a->readfnc = readfnc;
  a->size = STREAM_BUFSIZE;
  return a;
}


void
_gsti_read_stream_free (READ_STREAM a)
{
  _gsti_free (a);
}


/* This is the function version of the stream_get() macro.  It is used
   internally to to the underflow handling.  It may be used directly.
   the function returns -1 on EOF.  */
int
_gsti_stream_getbyte (READ_STREAM a)
{
  int rc;
  size_t n;

  if (a->start < a->len)
    return a->buf[a->start++];
  if (a->read_eof)
    return -1;

  a->len = 0;
  a->start = 0;
  n = a->size;
  rc = a->readfnc (NULL, a->buf, &n);
  if (rc)
    {
      a->error = 1;
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
_gsti_stream_readn (READ_STREAM a, byte * buffer, size_t nbytes)
{
  int c;

  while (nbytes)
    {
      c = _gsti_stream_get (a);
      if (c == -1)
	/* FIXME */
	return gsti_error_from_errno (EIO);
      if (buffer)
	{
	  *buffer = c;
	  buffer++;
	}
      nbytes--;
    }

  return 0;
}


WRITE_STREAM
_gsti_write_stream_new (GSTI_WRITE_FNC writefnc)
{
  WRITE_STREAM a;

  a = _gsti_xcalloc (1, sizeof *a + STREAM_BUFSIZE - 1);
  a->writefnc = writefnc;
  a->size = STREAM_BUFSIZE;
  return a;
}


void
_gsti_write_stream_free (WRITE_STREAM a)
{
  _gsti_free (a);
}


/* This is the function version of the stream_put() macro.  It is used
   internally to do the flush handling.  It may be used directly.  */
int
_gsti_stream_putbyte (WRITE_STREAM a, int c)
{
  int rc;

  if (!a->used)
    return 0;

  rc = a->writefnc (NULL, a->buf, a->used);
  if (rc)
    {
      a->error = 1;
      return -1;
    }
  a->used = 0;
  return _gsti_stream_put (a, c);
}


gsti_error_t
_gsti_stream_flush (WRITE_STREAM a)
{
  int rc;

  rc = a->used ? a->writefnc (NULL, a->buf, a->used) : 0;
  if (rc)
    {
      a->error = 1;
      /* FIXME.  */
      return gsti_error_from_errno (EIO);
    }
  a->used = 0;
  rc = a->writefnc (NULL, NULL, 0);
  if (rc)
    {
      a->error = 1;
      /* FIXME.  */
      return gsti_error_from_errno (EIO);
    }
  return 0;
}


/* Write NBYTES from buffer. If BUFFER is NULL the strong random bytes
   are written.  Returns 0 on success or an error code.  */
gsti_error_t
_gsti_stream_writen (WRITE_STREAM a, const byte * buffer, size_t nbytes)
{
  gsti_error_t err = 0;
  const byte *s = buffer;

  if (buffer)
    {
      while (nbytes)
	{
	  if (_gsti_stream_put (a, *s))
	    {
	      /* FIXME.  */
	      err = gsti_error_from_errno (EIO);
	      break;
	    }
	  s++;
	  nbytes--;
	}
    }
  else
    {				/* write random padding */
      byte *pad = gcry_random_bytes (nbytes, GCRY_WEAK_RANDOM);
      err = _gsti_stream_writen (a, pad, nbytes);
      gcry_free (pad);
    }

  return err;
}
