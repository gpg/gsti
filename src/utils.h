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

STRLIST _gsti_algolist_parse( const byte *string, size_t length );
size_t _gsti_algolist_build( byte *buffer, size_t length, STRLIST list );
int _gsti_algolist_find( STRLIST list, const char *algo );

int  cmp_bstring( BSTRING a, BSTRING b );

void gsti_print_string( FILE *fp, const char *string, size_t n );

void dump_hexbuf( FILE *fp, const char *prefix, const byte *buf, size_t len );
void dump_strlist( FILE *fp, const char *prefix, STRLIST list );
void dump_mpi( FILE *fp, const char *prefix, GCRY_MPI a );
void dump_bstring( FILE *fp, const char *prefix, BSTRING a );

int debug_rc( int rc, const char *format, ... );
void log_info( const char *format, ... );

#endif /* GSTI_UTILS_H */
