/* buffer.c - Buffer handling
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

#ifdef HAVE_CONFIG_H
 #include <config.h>
#endif
#include <unistd.h>
#include <stdio.h>
#include <gcrypt.h>

#include "types.h"
#include "api.h"
#include "memory.h"
#include "buffer.h"

static void
buffer_realloc( BUFFER ctx, size_t len )
{
    if( ctx->end >= ctx->size ) {        
        ctx->size += len;
        ctx->d = _gsti_realloc( ctx->d, ctx->size );
    }
}

int
_gsti_buf_init( BUFFER *r_ctx )
{
    BUFFER ctx;

    ctx = _gsti_calloc( 1, sizeof *ctx );
    ctx->d = _gsti_calloc( 1, 4096 );
    ctx->size = 4096;
    *r_ctx = ctx;

    return 0;
}


void
_gsti_buf_free( BUFFER ctx )
{
    if( !ctx )
        return;
    ctx->size = 0;
    ctx->end = 0;
    ctx->off = 0;
    _gsti_free( ctx->d );
    _gsti_free( ctx );
}


size_t
_gsti_buf_getlen( BUFFER ctx )
{
    return ctx->end - ctx->off;
}


void*
_gsti_buf_getptr( BUFFER ctx )
{
    return ctx->d + ctx->off;
}


void
_gsti_buf_putint( BUFFER ctx, unsigned val )
{
    int i = ctx->end;

    if( ctx->end + 4 >= ctx->size )
        buffer_realloc( ctx, 1024 );
    ctx->d[i++] = val >> 24;
    ctx->d[i++] = val >> 16;
    ctx->d[i++] = val >>  8;
    ctx->d[i++] = val;
    ctx->end = i;
}


unsigned
_gsti_buf_getint( BUFFER ctx )
{
    int i = ctx->off;
    u32 val;
    
    if( ctx->end < 4 )
        return 0;
    val  = ctx->d[i++] << 24;
    val |= ctx->d[i++] << 16;
    val |= ctx->d[i++] <<  8;
    val |= ctx->d[i++];
    ctx->off = i;

    return val;
}


void
_gsti_buf_putstr( BUFFER ctx, const byte *buf, size_t len )
{
    _gsti_buf_putint( ctx, len );
    if( ctx->end + len > ctx->size )
        buffer_realloc( ctx, len );
    if( buf ) {
        memcpy( ctx->d + ctx->end, buf, len );
        ctx->end += len;
    }
}


byte*
_gsti_buf_getstr( BUFFER ctx, size_t *r_n )
{
    byte *p;
    size_t len;

    len = _gsti_buf_getint( ctx );
    if( !len ) {
        *r_n = 4;
        return NULL;
    }
    p = _gsti_calloc( 1, len + 1 );
    _gsti_buf_getraw( ctx, p, len );
    p[len] = 0;
    *r_n = len;
    
    return p;
}

int
_gsti_buf_putmpi( BUFFER ctx, GCRY_MPI a )
{
    byte buf[512];
    size_t buflen = sizeof buf -1;
    int rc;

    rc = gcry_mpi_print( GCRYMPI_FMT_SSH, buf, &buflen, a );
    if( rc )
        return map_gcry_rc( rc );
    _gsti_buf_putraw( ctx, buf, buflen );
    
    return 0;
}

int
_gsti_buf_getmpi( BUFFER ctx, GCRY_MPI *ret_a, size_t *r_n )
{
    byte buf[512+4];
    size_t buflen;
    int rc;

    buflen = _gsti_buf_getint( ctx );
    if( !buflen || buflen > 512 )
        return GSTI_INV_ARG;
    buf[0] = buflen >> 24;
    buf[1] = buflen >> 16;
    buf[2] = buflen >>  8;
    buf[3] = buflen;
    buflen += 4;
    *r_n = buflen;
    _gsti_buf_getraw( ctx, buf + 4, buflen - 4 );
    rc = gcry_mpi_scan( ret_a, GCRYMPI_FMT_SSH, buf, &buflen );
    if( rc )
        return map_gcry_rc( rc );

    return 0;
}


int
_gsti_buf_getbstr( BUFFER ctx, BSTRING *r_bstr )
{
    BSTRING a;
    byte *p;
    size_t len;

    p = _gsti_buf_getstr( ctx, &len );
    if( len < 4 )
        return GSTI_TOO_SHORT;
    a = _gsti_bstring_make( p, len );
    *r_bstr = a;
    _gsti_free( p );
    return 0;
}

void
_gsti_buf_putc( BUFFER ctx, int val )
{
    int i = ctx->end;
    
    if( ctx->end + 1 >= _gsti_buf_getlen( ctx ) )
        buffer_realloc( ctx, 1024 );
    ctx->d[i++] = val & 0xff;
    ctx->end = i;
}


int
_gsti_buf_getc( BUFFER ctx )
{
    int i = ctx->off, val = 0;

    if( ctx->off > ctx->end )
        return -1;
    val = ctx->d[i++] & 0xff;
    ctx->off = i;

    return val;
}


void
_gsti_buf_putraw( BUFFER ctx, const byte *buf, size_t len )
{
    if( ctx->end + len >= ctx->size )
        buffer_realloc( ctx, len + 1024 );
    memcpy( ctx->d + ctx->end, buf, len );
    ctx->end += len;
}


int
_gsti_buf_getraw( BUFFER ctx, byte *buf, size_t reqlen )
{
    size_t len = _gsti_buf_getlen( ctx );
    
    if( reqlen > len )
        reqlen = len;
    memcpy( buf, ctx->d + ctx->off, reqlen );
    ctx->off += reqlen;

    return 0;
}


void
_gsti_buf_dump( BUFFER ctx )
{
    int i = 0;

    for( i = ctx->off; i < _gsti_buf_getlen( ctx ); i++ )
        printf( "%4x", ctx->d[i] );
    printf( "\n" );
}

