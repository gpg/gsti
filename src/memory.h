/* memory.h
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
   along with GSTI; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  */

#ifndef GSTI_MEMORY_H
#define GSTI_MEMORY_H	1

#include "types.h"

void *_gsti_xmalloc (size_t n);
void *_gsti_xcalloc (size_t n, size_t m);
void *_gsti_xrealloc (void *p, size_t n);
char *_gsti_xstrdup (const char *string);
void _gsti_free (void *);

STRLIST _gsti_strlist_insert (STRLIST head, const char *s);
void _gsti_strlist_free (STRLIST a);

#endif	/* GSTI_MEMORY_H */
