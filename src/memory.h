/* memory.h
 *	Copyright (C) 1999 Free Software Foundation, Inc.
 *
 * This file is part of GSTI.
 *
 * GSTI is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GSTI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef GSTI_MEMORY_H
#define GSTI_MEMORY_H

#include "types.h"

void *gsti_malloc( size_t n );
void *gsti_calloc( size_t n, size_t m );
void  gsti_free( void * );
char *gsti_strdup( const char* string );

STRLIST insert_strlist( STRLIST head, const char *s );
void gsti_free_strlist( STRLIST a );

#define free_strlist(a) gsti_free_strlist((a))

BSTRING make_bstring( const char *buffer, size_t length );
#define free_bstring(a)  gsti_free((a))

#endif /* GSTI_MEMORY_H */
