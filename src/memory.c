/* memory.c - Memory allocation wrappers.
   Copyright (C) 1999, 2002 Werner Koch
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
   along with GSTI; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <gcrypt.h>

#include "memory.h"

static void
out_of_core (void)
{
  fputs ("\nfatal: out of memory\n", stderr);
  exit (2);
}


void *
_gsti_xmalloc (size_t n)
{
  void *p = gcry_xmalloc (n);
  if (!p)
    out_of_core ();
  return p;
}


void *
_gsti_xcalloc (size_t n, size_t m)
{
  void *p = gcry_xcalloc (n, m);
  if (!p)
    out_of_core ();
  return p;
}


void *
_gsti_xrealloc (void *p, size_t n)
{
  void *pp = gcry_realloc (p, n);
  if (!pp)
    out_of_core ();
  return pp;
}


void
_gsti_free (void *p)
{
  gcry_free (p);
}


char *
_gsti_xstrdup (const char *string)
{
  char *p = gcry_xstrdup (string);
  if (!p)
    out_of_core ();
  return p;
}


gsti_strlist_t
_gsti_strlist_insert (gsti_strlist_t head, const char *s)
{
  gsti_strlist_t item;

  item = _gsti_xmalloc (sizeof *item + strlen (s));
  item->next = head;
  strcpy (item->d, s);
  return item;
}


void
_gsti_strlist_free (gsti_strlist_t a)
{
  while (a)
    {
      gsti_strlist_t a2 = a->next;
      _gsti_free (a);
      a = a2;
    }
}
