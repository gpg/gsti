/* memory.c -  memory allocation wrappers
 *	Copyright (C) 1999 Free Software Foundation, Inc.
 *      Copyright (C) 2002 Timo Schulz
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

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <gcrypt.h>

#include "memory.h"


void *
_gsti_malloc( size_t n )
{
    return gcry_xmalloc( n );
}


void *
_gsti_calloc( size_t n, size_t m )
{
    return gcry_xcalloc( n, m );
}


void *
_gsti_realloc( void *p, size_t n )
{
    return gcry_realloc( p, n );
}


void
_gsti_free( void *p )
{
    gcry_free( p );
}


char *
_gsti_strdup( const char *string )
{
    return gcry_xstrdup( string );
}


STRLIST
_gsti_strlist_insert( STRLIST head, const char *s )
{
    STRLIST item;

    item = _gsti_malloc( sizeof *item + strlen(s) );
    item->next = head;
    strcpy( item->d, s );
    return item;
}


void
_gsti_strlist_free( STRLIST a )
{
    while( a ) {
	STRLIST a2 = a->next;
	_gsti_free( a );
	a = a2;
    }
}

BSTRING
_gsti_bstring_make( const byte *buffer, size_t length )
{
    BSTRING a;

    a = _gsti_malloc( sizeof *a + length - 1  );
    a->len = length;
    if( buffer )
	memcpy( a->d, buffer, length );
    return a;
}

void
_gsti_bstring_free( BSTRING a )
{
    _gsti_free( a );
}





