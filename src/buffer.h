/* buffer.h - Buffer handling
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
 * along with GSTI; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */
#ifndef BUFFER_H
#define BUFFER_H

struct buffer_s {
    unsigned char *d;
    unsigned size;
    unsigned end;
    unsigned off;  
};
typedef struct buffer_s *BUFFER;

int buffer_init( BUFFER *r_ctx );
void buffer_free( BUFFER ctx );
size_t buffer_get_len( BUFFER ctx );
void* buffer_get_ptr( BUFFER ctx );
int buffer_put_ulong( BUFFER ctx, u32 val );
u32 buffer_get_ulong( BUFFER ctx );
int buffer_put_string( BUFFER ctx, const byte *buf, size_t len );
byte* buffer_get_string( BUFFER ctx, size_t *r_n );
int buffer_put_byte( BUFFER ctx, int val );
int buffer_get_byte( BUFFER ctx );
int buffer_put_raw( BUFFER ctx, const byte *buf, size_t len );
int buffer_get_raw( BUFFER ctx, byte *buf, size_t reqlen );
int buffer_skip( BUFFER ctx, int nbytes );
int buffer_put_mpi( BUFFER ctx, GCRY_MPI a );
int buffer_get_mpi( BUFFER ctx, GCRY_MPI *ret_a, size_t *r_n );
int buffer_get_bstring( BUFFER ctx, BSTRING *r_bstr );
void buffer_dump( BUFFER ctx );

#define buffer_getc( ctx ) buffer_get_byte( (ctx) )
#define buffer_putc( ctx, val ) buffer_put_byte( (ctx), (val) )

#endif /*BUFFER_H*/










