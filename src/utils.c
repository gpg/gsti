/* utils.c -  some utility functions
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
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <gcrypt.h>

#include "types.h"
#include "memory.h"
#include "utils.h"

static ulong
buftou32( const byte *buffer )
{
    ulong a;
    a =  *buffer << 24;
    a |= buffer[1] << 16;
    a |= buffer[2] << 8;
    a |= buffer[3];
    return a;
}

/****************
 * Take a comma separated list of algorithm identifiers and
 * return a STRLIST with these algorithms.
 */
STRLIST
parse_algorithm_list( const byte *string, size_t length )
{
    const byte *comma, *s;
    size_t n;
    STRLIST item, list, *listp;

    list = NULL;
    listp = &list;
    for(;;) {
	comma = memchr( string, ',' , length );
	n = comma? (comma - string) : length;
	if( n ) {
	    for( s = string; n && *s && isspace(*s); n--, s++ )
		;
	    if( *s && n ) { /* we have at least one non-space charcater*/
		item = gsti_malloc( sizeof *item + n );
		item->next = NULL;
		memcpy(item->d, string, n);
		/* and trim trailing spaces */
		for(n--; n && isspace(item->d[n]); n-- )
		    ;
		item->d[++n] = 0;
		*listp = item;
		listp = &item->next;
	    }
	}

	if( !comma )
	    return list;
	comma++;
	length -= comma - string;
	string = comma;
    }
}

size_t
build_algorithm_list( char *buffer, size_t length, STRLIST list )
{
    size_t n;
    int any=0;
    byte *p = buffer;

    if( length < 4 )
	return 0;  /* not event enough space to hold the length */
    length -= 4;  p += 4;
    for( ; list; list = list->next ) {
	n = strlen( list->d );
	if( n ) {
	    if( n+any > length )
		return 0; /* too short */
	    if( any ) {
		*p++ = ',';
		length--;
	    }
	    else
		any = 1;
	    memcpy( p, list->d, n );
	    p += n;
	    length -= n;
	}
    }
    n = ((char*)p - buffer) - 4;
    p = buffer;
    p[0] = n >> 24;
    p[1] = n >> 16;
    p[2] = n >> 8;
    p[3] = n;

    return n+4;
}


/****************
 * Parse a SSH string object.  The object is in string which has
 * *length.  The scanned length is return in *length.
 */
BSTRING
parse_bstring( const byte *string, size_t *length  )
{
    ulong len;
    BSTRING a;

    if( *length < 4 )
	return NULL; /* too short */

    len = buftou32( string ); string += 4; *length -= 4;
    if( len > *length )
	return NULL; /* too large */

    a = make_bstring( string, len );
    *length = 4+len;
    return a;
}

size_t
build_bstring( char *buffer, size_t length, BSTRING bstring )
{
    size_t n = bstring? bstring->len : 0;
    byte *p = buffer;

    if( length < 4 )
	return 0;  /* not event enough space to hold the length */
    p[0] = n >> 24;
    p[1] = n >> 16;
    p[2] = n >> 8;
    p[3] = n;
    if( !n )
	return 4;
    length -= 4;  p += 4;
    if( length < n )
	return 0;  /* does not fit */
    memcpy( p, bstring->d, n );
    return 4+n;
}


int
cmp_bstring( BSTRING a, BSTRING b )
{
    if( a->len == b->len && !memcmp( a->d, b->d, a->len ) )
	return 0;
    return -1; /* fixme: return the correct value */
}


void
gsti_print_string( FILE *fp, const char *string, size_t n )
{
    const byte *p = string;

    for( ; n; n--, p++ ) {
	if( iscntrl( *p ) ) {
	    putc('\\', fp);
	    if( *p == '\n' )
		putc('n', fp);
	    else if( *p == '\r' )
		putc('r', fp);
	    else if( *p == '\f' )
		putc('f', fp);
	    else if( *p == '\v' )
		putc('v', fp);
	    else if( *p == '\b' )
		putc('b', fp);
	    else if( !*p )
		putc('0', fp);
	    else
		fprintf(fp, "x%02x", *p );
	}
	else
	    putc(*p, fp);
    }
}


void
dump_hexbuf( FILE *fp, const char *prefix, const byte *buf, size_t len )
{
    fputs( prefix, fp );
    for( ; len ; len--, buf++ )
	fprintf(fp, "%02X ", *buf );
    putc('\n', fp );
}

void
dump_strlist( FILE *fp, const char *prefix, STRLIST list )
{
    int i;
    for(i=0 ; list ; list = list->next, i++ )
	fprintf(fp, "%s[%d]: `%s'\n", prefix, i, list->d );
}


void
dump_mpi( FILE *fp, const char *prefix, MPI a )
{
    char buf[400];
    size_t n = sizeof buf;

    if( gcry_mpi_print( GCRYMPI_FMT_HEX, buf, &n, a ) )
	strcpy(buf,"[can't print value]");
    fprintf( fp, "%s%s\n", prefix, buf );
}

void
dump_bstring( FILE *fp, const char *prefix, BSTRING a )
{
    fputs( prefix, fp );
    if( a )
	gsti_print_string( fp, a->d, a->len );
    putc('\n', fp );
}

size_t
dump_bstring_msg( FILE *fp, const char *prefix,
		  const char *buffer, size_t length )
{
    size_t n;

    if( prefix )
	fputs( prefix, fp );
    if( length < 4 ) {
	fputs( "[invalid length in bstring]\n", fp );
	return 0;
    }

    n = buftou32( buffer ); buffer += 4; length -= 4;
    if( n > length ) {
	fputs( "[bstring is too long]\n", fp );
	return 0;
    }
    gsti_print_string( fp, buffer, n );
    if( prefix )
	putc('\n', fp );
    return n+4;
}


int
debug_rc( int rc, const char *format, ... )
{
    va_list arg_ptr ;

    va_start( arg_ptr, format ) ;
    vfprintf( stderr, format, arg_ptr );
    va_end( arg_ptr );
    fprintf(stderr,": rc=%d\n", rc );
    return rc;
}

