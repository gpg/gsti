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

typedef struct buffer_s {
    unsigned char *d;
    unsigned size;
    unsigned end;
    unsigned off;  
} *BUFFER;


int _gsti_buf_init( BUFFER *r_ctx );
void _gsti_buf_free( BUFFER ctx );
size_t _gsti_buf_getlen( BUFFER ctx );
void* _gsti_buf_getptr( BUFFER ctx );
void _gsti_buf_putint( BUFFER ctx, u32 val );
unsigned _gsti_buf_getint( BUFFER ctx );
void _gsti_buf_putstr( BUFFER ctx, const byte *buf, size_t len );
byte* _gsti_buf_getstr( BUFFER ctx, size_t *r_n );
int _gsti_buf_putmpi( BUFFER ctx, GCRY_MPI a );
int _gsti_buf_getmpi( BUFFER ctx, GCRY_MPI *ret_a, size_t *r_n );
int _gsti_buf_getbstr( BUFFER ctx, BSTRING *r_bstr );
void _gsti_buf_putbstr( BUFFER ctx, BSTRING bstr );
void _gsti_buf_putc( BUFFER ctx, int val );
int _gsti_buf_getc( BUFFER ctx );
void _gsti_buf_putraw( BUFFER ctx, const byte *buf, size_t len );
int _gsti_buf_getraw( BUFFER ctx, byte *buf, size_t reqlen );
void _gsti_buf_dump( BUFFER ctx );


#endif /*BUFFER_H*/










