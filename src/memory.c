/* memory.c -  memory allocation wrappers
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

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <gcrypt.h>

#include "memory.h"


void *
gsti_malloc( size_t n )
{
    return gcry_xmalloc( n );
}

void *
gsti_calloc( size_t n, size_t m )
{
    return gcry_xcalloc( n, m );
}


void
gsti_free( void *p )
{
    gcry_free( p );
}


char *
gsti_strdup( const char *string )
{
    return gcry_xstrdup( string );
}


STRLIST
insert_strlist( STRLIST head, const char *s )
{
    STRLIST item;

    item = gsti_malloc( sizeof *item + strlen(s) );
    item->next = head;
    strcpy(item->d, s);
    return item;
}


void
gsti_free_strlist( STRLIST a )
{
    while( a ) {
	STRLIST a2 = a->next;
	gsti_free(a);
	a = a2;
    }
}

BSTRING
make_bstring( const char *buffer, size_t length )
{
    BSTRING a;

    a = gsti_malloc( sizeof *a + length - 1  );
    a->len = length;
    if( buffer )
	memcpy( a->d, buffer, length );
    return a;
}

