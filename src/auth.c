/* auth.c - Public key authentication
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
#include <assert.h>
#include <stdio.h>

#include "types.h"
#include "utils.h"
#include "buffer.h"
#include "api.h"
#include "packet.h"
#include "memory.h"
#include "pubkey.h"


static int
check_auth_id( const char *buf )
{
    if( !strncmp( buf, "publickey", 9 ) )
        return GSTI_AUTH_PUBLICKEY;
    return -1; /* not supported */
}


static int
build_auth_request( MSG_auth_request *ath, struct packet_buffer_s *pkt )
{
    BUFFER buf;
    size_t len;

    assert( pkt->size > 100 );
    
    _gsti_buf_init( &buf );
    _gsti_buf_putc( buf, 0 );
    _gsti_buf_putbstr( buf, ath->user );
    _gsti_buf_putbstr( buf, ath->svcname );
    _gsti_buf_putbstr( buf, ath->method );
    _gsti_buf_putc( buf, ath->false );
    _gsti_buf_putbstr( buf, ath->pkalgo );
    _gsti_buf_putbstr( buf, ath->key );
    if( ath->sig )
        _gsti_buf_putbstr( buf, ath->sig );

    len = _gsti_buf_getlen( buf );
    pkt->type = SSH_MSG_USERAUTH_REQUEST;
    pkt->payload_len = len;
    memcpy( pkt->payload, _gsti_buf_getptr( buf ), len );

    _gsti_buf_free( buf );
    return 0;
}


static void
free_auth_request( MSG_auth_request *ath )
{
    if( ath ) {
        _gsti_bstring_free( ath->user );
        _gsti_bstring_free( ath->svcname );
        _gsti_bstring_free( ath->method );
        _gsti_bstring_free( ath->pkalgo );
        _gsti_bstring_free( ath->key );
        _gsti_bstring_free( ath->sig );
    }
}


static int
init_auth_request( MSG_auth_request *ath, const char *user, int false,
                   GSTI_KEY pk )
{
    const char *svc = "ssh-userauth", *mthd = "publickey";
    byte *p;
    size_t n;

    if( !user || !pk )
        return GSTI_INV_ARG;
    
    ath->user = _gsti_bstring_make( user, strlen( user ) );
    ath->svcname = _gsti_bstring_make( svc, strlen( svc ) );
    ath->method = _gsti_bstring_make( mthd, strlen( mthd ) );
    ath->false = false;
    p = _gsti_ssh_get_pkname( pk->type, 0, &n );
    ath->pkalgo = _gsti_bstring_make( p, n );
    _gsti_free( p );
    ath->key = _gsti_key_getblob( pk );
    
    /* Due to the fact we need to hash the packet first before we
       can sign, we always add the signature later and not here. */

    return 0;
}
    

static void
dump_auth_request( MSG_auth_request *ath )
{
    _gsti_log_debug( "\nMSG_auth_request:\n" );
    _gsti_dump_bstring( "user: ", ath->user );
    _gsti_dump_bstring( "service: ", ath->svcname );
    _gsti_dump_bstring( "method: ", ath->method );
    _gsti_log_debug( "false=%d\n", ath->false );
    _gsti_dump_bstring( "key: ", ath->key );
    _gsti_dump_bstring( "signature: ", ath->sig );
    _gsti_log_debug( "\n" );
}


int
auth_send_accept_packet( GSTIHD hd )
{
    struct packet_buffer_s *pkt = &hd->pkt;
    int rc;
    
    pkt->type = SSH_MSG_USERAUTH_SUCCESS;
    pkt->payload_len = 1;
    rc = _gsti_packet_write( hd );
    if( !rc )
        rc = _gsti_packet_flush( hd );
    return rc;
}


int
auth_proc_accept_packet( GSTIHD hd )
{
    struct packet_buffer_s *pkt = &hd->pkt;
    
    if( pkt->type != SSH_MSG_USERAUTH_SUCCESS )
        return GSTI_BUG;
    if( pkt->payload_len != 1 )
        return GSTI_INV_PKT;
    return 0;
}


int
auth_send_init_packet( GSTIHD hd )
{
    MSG_auth_request ath;
    int rc;
    
    memset( &ath, 0, sizeof ath );
    rc = init_auth_request( &ath, hd->auth.user, 0, hd->auth.key );
    if( !rc )
        rc = build_auth_request( &ath, &hd->pkt );
    if( !rc )
        rc = _gsti_packet_write( hd );
    if( !rc )
        rc = _gsti_packet_flush( hd );

    free_auth_request( &ath );
    return rc;
}


static BSTRING
read_bstring( BUFFER buf )
{
    BSTRING dst = NULL;
    size_t n;
    byte *p = _gsti_buf_getstr( buf, &n );
    if( p )
        dst = _gsti_bstring_make( p, n );
    _gsti_free( p );
    return dst;
}


static int
parse_auth_request( MSG_auth_request *ath, const BUFFER buf )
{
    int rc = 0;
    
    memset( ath, 0, sizeof *ath );
    if( _gsti_buf_getlen( buf ) < (4+4+4+1+4+4) )
        return GSTI_TOO_SHORT;
    if( _gsti_buf_getc( buf ) != SSH_MSG_USERAUTH_REQUEST )
        return GSTI_BUG;
    ath->user = read_bstring( buf );
    ath->svcname = read_bstring( buf );
    ath->method = read_bstring( buf );
    ath->false = _gsti_buf_getc( buf );
    ath->pkalgo = read_bstring( buf );
    ath->key = read_bstring( buf );
    if( _gsti_buf_getlen( buf ) )
        ath->sig = read_bstring( buf );
    if( _gsti_buf_getlen( buf ) )
        rc = GSTI_INV_PKT;

    return rc;
}


int
auth_proc_init_packet( GSTIHD hd )
{
    MSG_auth_request ath;
    int rc;
    
    if( hd->pkt.type != SSH_MSG_USERAUTH_REQUEST )
        return GSTI_BUG;

    rc = parse_auth_request( &ath, hd->pktbuf );
    if( rc )
        return rc;
    if( check_auth_id( ath.method->d ) == -1 ) {
        free_auth_request( &ath );
        return GSTI_NOT_IMPL;
    }
    hd->auth.user = _gsti_xstrdup( ath.user->d );
    hd->auth.key = _gsti_key_fromblob( ath.key );
    
    dump_auth_request( &ath );
    free_auth_request( &ath );    
    return rc;
}


static int
calc_sig_hash( BSTRING sessid, MSG_auth_request *ath, BSTRING *r_digest )
{
  gpg_error_t err;
  gcry_md_hd_t md;
  int dlen = gcry_md_get_algo_dlen( GCRY_MD_SHA1 );

    err = gcry_md_open (&md, GCRY_MD_SHA1, 0 );
    if( err )
        return map_gcry_rc( err );
    _gsti_bstring_hash( md, sessid );
    gcry_md_putc( md, SSH_MSG_USERAUTH_REQUEST );
    _gsti_bstring_hash( md, ath->user );
    _gsti_bstring_hash( md, ath->svcname );
    _gsti_bstring_hash( md, ath->method );
    gcry_md_putc( md, ath->false );
    _gsti_bstring_hash( md, ath->pkalgo );
    _gsti_bstring_hash( md, ath->key );

    gcry_md_final( md );
    *r_digest = _gsti_bstring_make( gcry_md_read( md, 0 ), dlen );
    gcry_md_close( md );
    
    return 0;
}


static void
free_auth_pkok( MSG_auth_pkok *ok )
{
    if( ok ) {
        _gsti_bstring_free( ok->pkalgo );
        _gsti_bstring_free( ok->key );
    }
}


static int
build_pkok_packet( MSG_auth_pkok *ok, struct packet_buffer_s *pkt )
{
    BUFFER buf;
    size_t len;
    
    _gsti_buf_init( &buf );
    _gsti_buf_putc( buf, 0 );
    _gsti_buf_putbstr( buf, ok->pkalgo );
    _gsti_buf_putbstr( buf, ok->key );

    len = _gsti_buf_getlen( buf );
    pkt->type = SSH_MSG_USERAUTH_PK_OK;
    pkt->payload_len = len;
    memcpy( pkt->payload, _gsti_buf_getptr( buf ), len );

    _gsti_buf_free( buf );
    return 0;
}


int
auth_send_pkok_packet( GSTIHD hd )
{
    MSG_auth_pkok ok;
    GSTI_KEY pk;
    byte *p;
    size_t n;
    int rc;
    
    memset( &ok, 0, sizeof ok );
    pk = hd->auth.key;
    if( !pk )
        return GSTI_INV_OBJ;
    p = _gsti_ssh_get_pkname( pk->type, 0, &n );
    ok.pkalgo = _gsti_bstring_make( p, n );
    ok.key = _gsti_key_getblob( pk );
    rc = build_pkok_packet( &ok, &hd->pkt );
    if( !rc )
        rc = _gsti_packet_write( hd );
    if( !rc )
        rc = _gsti_packet_flush( hd );

    _gsti_free( p );
    free_auth_pkok( &ok );
    return rc;
}


static int
parse_pkok_packet( MSG_auth_pkok *ok, const BUFFER buf )
{
    byte *p;
    size_t n;

    memset( ok, 0, sizeof *ok );
    if( _gsti_buf_getlen( buf ) < (4+4) )
        return GSTI_TOO_SHORT;
    if( _gsti_buf_getc( buf ) != SSH_MSG_USERAUTH_PK_OK )
        return GSTI_INV_PKT;
    p = _gsti_buf_getstr( buf, &n );
    ok->pkalgo = _gsti_bstring_make( p, n );
    _gsti_free( p );
    
    p = _gsti_buf_getstr( buf, &n );
    ok->key = _gsti_bstring_make( p, n );
    _gsti_free( p );

    return 0;
}

    
int
auth_proc_pkok_packet( GSTIHD hd )
{
    int rc;
    MSG_auth_pkok ok;
    BSTRING alg;
    
    if( hd->pkt.type != SSH_MSG_USERAUTH_PK_OK )
        return GSTI_BUG;

    rc = parse_pkok_packet( &ok, hd->pktbuf );
    if( rc )
        return rc;
    alg = ok.pkalgo;
    rc = _gsti_ssh_cmp_pkname( hd->auth.key->type, alg->d, alg->len );
    if( !rc ) {
        GSTI_KEY a = _gsti_key_fromblob( ok.key );
        if( a ) {
            rc = _gsti_ssh_cmp_keys( a, hd->auth.key );
            gsti_key_free( a );
        }
    }
    free_auth_pkok( &ok );
    return rc;
}


int
auth_send_second_packet( GSTIHD hd )
{
    MSG_auth_request ath;
    BSTRING sig = NULL, hash;
    int rc;

    memset( &ath, 0, sizeof ath );
    rc = init_auth_request( &ath, hd->auth.user, 1, hd->auth.key );
    if( !rc )
        rc = calc_sig_hash( hd->session_id, &ath, &hash );
    if( !rc )
        sig = _gsti_sig_encode( hd->auth.key, hash->d );
    if( sig )
        ath.sig = sig;
    else
        goto leave;
    if( !rc )
        rc = build_auth_request( &ath, &hd->pkt );
    if( !rc )
        rc = _gsti_packet_write( hd );
    if( !rc )
        rc = _gsti_packet_flush( hd );

 leave:
    free_auth_request( &ath );
    _gsti_bstring_free( hash );

    return rc;
}


int
auth_proc_second_packet( GSTIHD hd )
{
    MSG_auth_request ath;
    BSTRING hash;
    int rc;

    rc = parse_auth_request( &ath, hd->pktbuf );
    if( !rc )
        rc = calc_sig_hash( hd->session_id, &ath, &hash );
    if( !rc )
        rc = _gsti_sig_decode( ath.key, ath.sig, hash->d, NULL );

    _gsti_bstring_free( hash );    
    free_auth_request( &ath );
    return rc;
}

