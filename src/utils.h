/* utils.h
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

#ifndef GSTI_UTILS_H
#define GSTI_UTILS_H

#include <gcrypt.h>

enum {
    TYPE_HEXBUF  = 1,
    TYPE_STRLIST = 2,
    TYPE_MPI     = 3,
    TYPE_BSTRING = 4,
    TYPE_BUFFER  = 5,
};

void _gsti_bstring_hash( GCRY_MD_HD md, BSTRING a );

STRLIST _gsti_algolist_parse( const byte *string, size_t length );
size_t _gsti_algolist_build( byte *buffer, size_t length, STRLIST list );
int _gsti_algolist_find( STRLIST list, const char *algo );
void _gsti_dump_object(const char *prefix, int type, void *opaque, size_t len);

#define _gsti_dump_bstring( prefix, str ) \
_gsti_dump_object( (prefix), TYPE_BSTRING, (str), 0 )

#define _gsti_dump_hexbuf( prefix, buf, len ) \
_gsti_dump_object( (prefix), TYPE_HEXBUF, (buf), (len) )

#define _gsti_dump_mpi( prefix, mpi ) \
_gsti_dump_object( (prefix), TYPE_MPI, (mpi), 0 )

#define _gsti_dump_strlist( prefix, list ) \
_gsti_dump_object( (prefix), TYPE_STRLIST, (list), 0 )

#define _gsti_dump_buffer( prefix, buf ) \
_gsti_dump_object( (prefix), TYPE_BUFFER, (buf), 0 )

void _gsti_print_string( const char *string, size_t n );

/*-- main.c --*/
void _gsti_log_info( const char *fmt, ... );
int _gsti_log_rc( int rc, const char *fmt, ... );
int _gsti_get_log_level( void );
void _gsti_log_debug( const char *fmt, ... );

/*-- zlib.c --*/
void _gsti_compress_init( void );
int  _gsti_compress_block( byte *block,int len, byte **outblock, int *outlen );
void _gsti_decompress_init( void );
int _gsti_decompress_block( byte *block, int len,byte **outblock,int *outlen );


#endif /* GSTI_UTILS_H */

