/* utils.c -  some utility functions
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
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <gcrypt.h>

#include "types.h"
#include "memory.h"
#include "utils.h"
#include "buffer.h"


/****************
 * Take a comma separated list of algorithm identifiers and
 * return a STRLIST with these algorithms.
 */
STRLIST
_gsti_algolist_parse (const byte * string, size_t length)
{
  const byte *comma, *s;
  size_t n;
  STRLIST item, list, *listp;

  list = NULL;
  listp = &list;
  for (;;)
    {
      comma = memchr (string, ',', length);
      n = comma ? (comma - string) : length;
      if (n)
	{
	  for (s = string; n && *s && isspace (*s); n--, s++)
	    ;
	  if (*s && n)
	    {			/* we have at least one non-space charcater */
	      item = _gsti_xmalloc (sizeof *item + n);
	      item->next = NULL;
	      memcpy (item->d, string, n);
	      /* and trim trailing spaces */
	      for (n--; n && isspace (item->d[n]); n--)
		;
	      item->d[++n] = 0;
	      *listp = item;
	      listp = &item->next;
	    }
	}

      if (!comma)
	return list;
      comma++;
      length -= comma - string;
      string = comma;
    }
}

size_t
_gsti_algolist_build (byte * buffer, size_t length, STRLIST list)
{
  size_t n;
  int any = 0;
  byte *p = buffer;

  if (length < 4)
    return 0;			/* not event enough space to hold the length */
  length -= 4;
  p += 4;
  for (; list; list = list->next)
    {
      n = strlen (list->d);
      if (n)
	{
	  if (n + any > length)
	    return 0;		/* too short */
	  if (any)
	    {
	      *p++ = ',';
	      length--;
	    }
	  else
	    any = 1;
	  memcpy (p, list->d, n);
	  p += n;
	  length -= n;
	}
    }
  n = (p - buffer) - 4;
  p = buffer;
  p[0] = n >> 24;
  p[1] = n >> 16;
  p[2] = n >> 8;
  p[3] = n;

  return n + 4;
}


int
_gsti_algolist_find (STRLIST list, const char *algo)
{
  STRLIST l;

  for (l = list; l; l = l->next)
    {
      if (!strcmp (l->d, algo))
	return 1;
    }
  return 0;
}


void
_gsti_print_string (const char *string, size_t n)
{
  const byte *p = string;

  for (; n; n--, p++)
    {
      if (iscntrl (*p))
	{
	  _gsti_log_info (0, "%c", '\\');
	  if (*p == '\n')
	    _gsti_log_info (0, "%c", 'n');
	  else if (*p == '\r')
	    _gsti_log_info (0, "%c", 'r');
	  else if (*p == '\f')
	    _gsti_log_info (0, "%c", 'f');
	  else if (*p == '\v')
	    _gsti_log_info (0, "%c", 'v');
	  else if (*p == '\b')
	    _gsti_log_info (0, "%c", 'b');
	  else if (!*p)
	    _gsti_log_info (0, "%c", '0');
	  else
	    _gsti_log_info (0, "x%02x", *p);
	}
      else
	_gsti_log_info (0, "%c", *p);
    }
}


void
_gsti_dump_object (const char *prefix, int type, void *opaque, size_t len)
{
  if (!opaque)
    return;
  switch (type)
    {
    case TYPE_HEXBUF:
      {
	byte *buf = opaque;
	_gsti_log_info (0, "%s", prefix);
	for (; len; len--, buf++)
	  _gsti_log_info (0, "%02X ", *buf);
	_gsti_log_info (0, "\n");
	break;
      }
    case TYPE_STRLIST:
      {
	STRLIST list = opaque;
	int i;
	for (i = 0; list; list = list->next, i++)
	  _gsti_log_info (0, "%s[%d]: `%s'\n", prefix, i, list->d);
	break;
      }
    case TYPE_MPI:
      {
	gcry_mpi_t a = opaque;
	byte buf[400];
	size_t n;

	if (gcry_mpi_print (GCRYMPI_FMT_HEX, buf, sizeof buf, &n, a))
	  strcpy (buf, "[can't print value]");
	_gsti_log_info (0, "%s%s\n", prefix, buf);
	break;
      }
    case TYPE_BSTRING:
      {
	BSTRING a = opaque;
	_gsti_log_info (0, "%s", prefix);
	if (a)
	  _gsti_print_string (a->d, a->len);
	_gsti_log_info (0, "\n");
	break;
      }
    case TYPE_BUFFER:
      {
	BUFFER buf = opaque;
	int i;
	for (i = buf->off; i < _gsti_buf_getlen (buf); i++)
	  _gsti_log_info (0, "%4x", buf->d[i]);
	_gsti_log_info (0, "\n");
	break;
      }

    }
}

void
_gsti_bstring_hash (gcry_md_hd_t md, BSTRING a)
{
  byte buf[4];
  size_t n = a->len;

  buf[0] = n >> 24;
  buf[1] = n >> 16;
  buf[2] = n >> 8;
  buf[3] = n;
  gcry_md_write (md, buf, 4);
  gcry_md_write (md, a->d, n);
}
