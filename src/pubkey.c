/* pubkey.c
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
#include <stdio.h>
#include <sys/stat.h>
#include <gcrypt.h>

#include "types.h"
#include "pubkey.h"
#include "api.h"
#include "memory.h"
#include "buffer.h"

static struct {
    const char *algname;
    const char *key_elements;
    size_t nkey;
    const char *sig_elements;
    size_t nsig;
} pk_table[] = {
    { "none",    "dummy", 0 , "dummy", 0 },
    { "ssh-dss", "pqgy",  4,  "rs",    2 },
    {0},
};

GCRY_MPI
get_mpissh( GCRY_MPI dat )
{
    GCRY_MPI a = NULL;
    byte buf[512+4];
    size_t n = sizeof buf -5;
    int rc;
    
    rc = gcry_mpi_print( GCRYMPI_FMT_SSH, buf, &n, dat );
    if( !rc )
        rc = gcry_mpi_scan( &a, GCRYMPI_FMT_SSH, buf, &n );
    if( !rc )
        gcry_mpi_release( dat );
    return a;
}

static int
sexp_get_sshmpi( GCRY_SEXP s_sig, int pktype, GCRY_MPI sig[2] )
{
    GCRY_SEXP list;
    GCRY_MPI tmp;
    size_t n = 0;
    const char *s;
    char name[2];

    if( pktype > 1 )
        return GSTI_BUG;
    s = pk_table[pktype].sig_elements;
    while( s && n < pk_table[pktype].nsig ) {
        name[0] = *s;
        name[1] = 0;
        list = gcry_sexp_find_token( s_sig, name, 0 );
        if( !list )
            return GSTI_INV_OBJ;
        tmp = gcry_sexp_nth_mpi( list, 1, 0 );
        sig[n++] = get_mpissh( tmp );
        gcry_sexp_release( list );
        s++;
    }

    return 0;
}

static int
sexp_from_buffer( GCRY_SEXP *r_a, const byte *buf, size_t buflen )
{
    GCRY_SEXP s_a;
    GCRY_MPI a;
    size_t n = buflen;
    int rc;

    rc = gcry_mpi_scan( &a, GCRYMPI_FMT_USG, buf, &n );
    if( rc )
        return map_gcry_rc( rc );
    rc = gcry_sexp_build( &s_a, NULL, "%m", a );
    gcry_mpi_release( a );
    *r_a = s_a;
    return map_gcry_rc( rc );
}

static void
free_mpi_array( GCRY_MPI *a, size_t na )
{
    size_t i;
    
    if( !a )
        return;
    for( i = 0; i < na; i++ ) {
        gcry_mpi_release( a[i] );
        a[i] = NULL;
    }
}

int
_gsti_dss_sign( GSTI_KEY ctx, const byte *hash, GCRY_MPI sig[2] )
{
    GCRY_SEXP s_hash = NULL, s_key = NULL, s_sig = NULL;
    int dlen = gcry_md_get_algo_dlen( GCRY_MD_SHA1 );
    int rc;

    if( ctx->type != SSH_PK_DSS )
        return GSTI_BUG;
    if( !ctx->secret )
        return GSTI_INV_OBJ;
    
    rc = sexp_from_buffer( &s_hash, hash, dlen );
    if( !rc )
        rc = gcry_sexp_build( &s_key, NULL,
                              "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
                              ctx->key[0], /* p */
                              ctx->key[1], /* q */
                              ctx->key[2], /* g */
                              ctx->key[3], /* y */
                              ctx->key[4]  /* x */ );

    if( !rc )
        rc = gcry_pk_sign( &s_sig, s_hash, s_key );
    if( !rc )
        rc = sexp_get_sshmpi( s_sig, SSH_PK_DSS, sig );

    gcry_sexp_release( s_key );
    gcry_sexp_release( s_hash );
    gcry_sexp_release( s_sig );
    
    return map_gcry_rc( rc );
}


int
_gsti_dss_verify( GSTI_KEY ctx, const byte *hash, GCRY_MPI sig[2] )
{
    GCRY_SEXP s_key, s_md, s_sig;
    int dlen = gcry_md_get_algo_dlen( GCRY_MD_SHA1 );
    int rc;

    if( ctx->type != SSH_PK_DSS )
        return GSTI_BUG;
    
    rc = sexp_from_buffer( &s_md, hash, dlen );
    if( !rc )
        rc = gcry_sexp_build( &s_key, NULL,
                              "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
                              ctx->key[0], /* p */
                              ctx->key[1], /* q */
                              ctx->key[2], /* g */
                              ctx->key[3]  /* y */ );
    if( !rc )
        rc = gcry_sexp_build( &s_sig, NULL, "(sig-val(dsa(r%m)(s%m)))",
                              sig[0], /* r */
                              sig[1]  /* s */ );
    if( !rc )
        rc = gcry_pk_verify( s_sig, s_md, s_key );

    gcry_sexp_release( s_key );
    gcry_sexp_release( s_md );
    gcry_sexp_release( s_sig );
    
    return map_gcry_rc( rc );
}

static int
read_bstring( FILE *fp, int ismpi, BSTRING *r_a )
{
    struct stat statbuf;
    BSTRING a;
    byte buf[4];
    u32 len = 0, n;

    if( fstat( fileno( fp ), &statbuf ) )
        return GSTI_FILE;
    for( n = 0; n < 4; n++ )
        buf[n] = fgetc( fp );
    len = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
    if( len > statbuf.st_size ) {
        log_info( "read_bstring: %d: string larger than file.\n", len );
        return GSTI_INV_OBJ;
    }
    a = _gsti_bstring_make( NULL, ismpi? len + 4: len );
    if( ismpi ) {
        a->d[0] = len >> 24;
        a->d[1] = len >> 16;
        a->d[2] = len >>  8;
        a->d[3] = len;
        n = 4;
    }
    else
        n = 0;
    /*log_info( "got string with a length of %d\n", len );*/
    while( len-- )
        a->d[n++] = fgetc( fp );
    *r_a = a;
    return 0;
}

static GCRY_MPI
bstring_to_sshmpi( BSTRING bstr )
{
    GCRY_MPI a;
    size_t n = bstr->len;
    
    if( bstr->len < 5 )
        return NULL;
    if( gcry_mpi_scan( &a, GCRYMPI_FMT_SSH, bstr->d, &n ) )
        return NULL;
    return a;
}


static int
read_dss_key( FILE *fp, int keytype, GSTI_KEY ctx )
{
    BSTRING a;
    size_t n;
    int rc, i;

    n = pk_table[SSH_PK_DSS].nkey;
    if( keytype )
        n++; /* secret key */
    rc = read_bstring( fp, 0, &a );
    if( rc )
        return rc;
    if( a->len != 7 || strncmp( a->d, "ssh-dss", 7 ) ) {
        log_info( "read_dss_key: %s: not a dss key blob\n", a->d );
        _gsti_bstring_free( a );
        return GSTI_INV_OBJ;
    }
    _gsti_bstring_free( a );
    for( i = 0; i < n; i++ ) {
        rc = read_bstring( fp, 1, &a );
        if( rc )
            break;
        ctx->key[i] = bstring_to_sshmpi( a );
        _gsti_bstring_free( a );
    }
    if( !rc )
        ctx->type = SSH_PK_DSS;
    if( !rc )
        ctx->nkey = n;
    if( !rc )
        ctx->secret = keytype? 1 : 0;

    return rc;
}


static int
parse_key_entry( FILE *fp, int pktype, int keytype, GSTI_KEY *r_ctx )
{
    GSTI_KEY ctx;
    int rc;

    ctx = _gsti_calloc( 1, sizeof *ctx );
    ctx->type = SSH_PK_NONE;
    switch( pktype ) {
    case SSH_PK_DSS: rc = read_dss_key( fp, keytype, ctx ); break;
    default:         rc = GSTI_GENERAL; break;
    }
    *r_ctx = ctx;

    return rc;
}

/****************
 * Read a public key from the given file.
 * The file only expect that the file contains one key and as a result,
 * only the first record will be read!
 */
int
gsti_key_load( const char *file, int pktype, int keytype, GSTI_KEY *r_ctx )
{
    FILE *inp;
    int rc;

    inp = fopen( file, "r" );
    if( !inp )
        return GSTI_FILE;
    rc = parse_key_entry( inp, pktype, keytype, r_ctx );
    fclose( inp );
    return rc;
}

static byte *
get_sshkeyname( int pktype, int asbstr, size_t *r_n )
{
    const char *s;
    size_t len, n = 0;
    byte *p;

    if( pktype > 1 )
        return NULL;
    s = pk_table[pktype].algname;
    len = strlen( s );
    if( asbstr )
        n = 4;
    p = _gsti_malloc( n + len + 1 );
    if( asbstr ) {
        p[0] = len >> 24;
        p[1] = len >> 16;
        p[2] = len >>  8;
        p[3] = len;
    }
    memcpy( p + n, s, len );
    p[n + len] = 0;
    *r_n = n + len;
    return p;
}

static int
pkalgo_get_nkey( int algid, const char *name )
{
    const char *s;
    int i;
    
    if( algid == 1 )
        return pk_table[algid].nkey;
    else if( name ) {
        for( i = 0; (s = pk_table[i].algname); i++ ) {
            if( !strncmp( s, name, strlen( s ) ) )
                return pk_table[i].nkey;
        }
    }
    return -1;
}


GSTI_KEY
_gsti_key_fromblob( BSTRING blob )
{
    BUFFER buf;
    GSTI_KEY pk = NULL;
    byte *p;
    size_t n, i;
    int rc = 0;

    if( blob->len == 4 )
        return NULL;
    _gsti_buf_init( &buf );
    _gsti_buf_putraw( buf, blob->d, blob->len );
    p = _gsti_buf_getstr( buf, &n );
    if( n != 7 || strcmp( p, "ssh-dss" ) ) {
        _gsti_free( p );
        goto leave; /* not supported */
    }
    pk = _gsti_calloc( 1, sizeof *pk );
    pk->secret = 0;
    for( i = 0; i < pkalgo_get_nkey( 0, p ); i++ ) {
        rc = _gsti_buf_getmpi( buf, &pk->key[i], &n );
        if( rc )
            break;
    }
    _gsti_free( p );
 leave:
    _gsti_buf_free( buf );
    if( !rc )
        pk->type = SSH_PK_DSS;
    if( !rc )
        pk->nkey = 4;
    return pk;
}

BSTRING
_gsti_key_getblob( GSTI_KEY pk )
{
    BUFFER buf;
    BSTRING a;
    byte *p;
    size_t n;

    if( !pk || pk->type > 1 )
        return _gsti_bstring_make( NULL, 4 );
    _gsti_buf_init( &buf );
    p = get_sshkeyname( pk->type, 0, &n );
    _gsti_buf_putstr( buf, p, n );
    for( n = 0; n < pk_table[pk->type].nkey; n++ )
        _gsti_buf_putmpi( buf, pk->key[n] );

    a = _gsti_bstring_make( _gsti_buf_getptr( buf ), _gsti_buf_getlen( buf ) );

    _gsti_free( p );
    _gsti_buf_free( buf );

    return a;
}   
    

byte*
gsti_key_fingerprint( GSTI_KEY ctx, int mdalgo )
{
    GCRY_MD_HD hd;
    byte buf[512], *hash, *name;
    size_t n = sizeof buf -1;
    int i, dlen;

    hd = gcry_md_open( mdalgo, 0 );
    if( !hd )
        return NULL;
    dlen = gcry_md_get_algo_dlen( mdalgo );
    name = get_sshkeyname( ctx->type, 1, &n );
    gcry_md_write( hd, name, n );
    for( i = 0; i < pkalgo_get_nkey( ctx->type, NULL ); i++ ) {
        n = sizeof buf -1;
        if( !gcry_mpi_print( GCRYMPI_FMT_SSH, buf, &n, ctx->key[i] ) )
            gcry_md_write( hd, buf, n );
    }
    gcry_md_final( hd );
    hash = gcry_malloc( dlen + 1 );
    hash[dlen] = 0;
    memcpy( hash, gcry_md_read( hd, 0 ), dlen );
    gcry_md_close( hd );
    _gsti_free( name );

    return hash;
}


void
gsti_key_free( GSTI_KEY ctx )
{
    if( !ctx )
        return;
    free_mpi_array( ctx->key, ctx->nkey );
    _gsti_free( ctx );
}


int
_gsti_sig_decode( BSTRING key, BSTRING sig, const byte *hash, GSTI_KEY *r_pk )
{
    BUFFER buf;
    GSTI_KEY pk;
    GCRY_MPI _sig[2];
    byte *p = NULL;
    size_t n;
    int rc;

    pk = _gsti_key_fromblob( key );
    if( !pk )
        return GSTI_INV_OBJ;
    _gsti_buf_init( &buf );
    _gsti_buf_putraw( buf, sig->d, sig->len );
    p = _gsti_buf_getstr( buf, &n );
    if( n != 7 || strcmp( p, "ssh-dss" ) ) {
        rc = GSTI_INV_OBJ;
        goto leave;
    }
    _gsti_free( p );
    p = _gsti_buf_getstr( buf, &n );
    if( n != 40 ) {
        rc = GSTI_BUG;
        goto leave;
    }
    /* there is no separation for the both mpis so we say the first
       has a maximum of 160 bits (20 bytes). */
    n = 20;
    rc = gcry_mpi_scan( &_sig[0], GCRYMPI_FMT_USG, p, &n );
    if( !rc )
        rc = gcry_mpi_scan( &_sig[1], GCRYMPI_FMT_USG, p + n, &n );
    if( !rc )
        rc = _gsti_dss_verify( pk, hash, _sig );
    free_mpi_array( _sig, 2 );

 leave:
    _gsti_free( p );
    _gsti_buf_free( buf );
    if( !rc )
        *r_pk = pk;
    return rc;
} /* _gsti_sig_decode */


BSTRING
_gsti_sig_encode( const char *file, const byte *hash  )
{
    GSTI_KEY sk;
    GCRY_MPI sig[2];
    BUFFER buf;
    BSTRING a;
    byte *p, buffer[128];
    size_t n, n2;
    int rc;

    if( !file )
        return _gsti_bstring_make( NULL, 4 );
    rc = gsti_key_load( file, GSTI_PK_DSS, 1, &sk );
    if( rc ) {
        log_info( "could not load secret key\n" );
        return NULL;
    }
    rc = _gsti_dss_sign( sk, hash, sig );
    gsti_key_free( sk );
    if( rc ) {
        log_info( "signing failed rc=%d\n", rc );
        return NULL;
    }
    p = get_sshkeyname( GSTI_PK_DSS, 0, &n );
    _gsti_buf_init( &buf );
    _gsti_buf_putstr( buf, p, n );
    n = sizeof buffer -1;
    n2 = sizeof buffer -1;
    rc = gcry_mpi_print( GCRYMPI_FMT_USG, buffer, &n, sig[0] );
    if( !rc )
        rc = gcry_mpi_print( GCRYMPI_FMT_USG, buffer + n, &n2, sig[1] );
    if( !rc )
        _gsti_buf_putstr( buf, buffer, n + n2 );
    free_mpi_array( sig, 2 );
    
    a = _gsti_bstring_make( _gsti_buf_getptr( buf ), _gsti_buf_getlen( buf ) );
    
    _gsti_free( p );
    _gsti_buf_free( buf );

    return a;
}
