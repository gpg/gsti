/* auth.c
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
#include "api.h"
#include "packet.h"
#include "memory.h"
#include "pubkey.h"
#include "buffer.h"
#include "utils.h"
     
static int
build_auth_request( MSG_auth_request *ath, struct packet_buffer_s *pkt )
{
    BUFFER buf;
    size_t len;

    assert( pkt->size > 100 );
    
    _gsti_buf_init( &buf );
    _gsti_buf_putstr( buf, ath->user->d, ath->user->len );
    _gsti_buf_putstr( buf, ath->svcname->d, ath->svcname->len );
    _gsti_buf_putstr( buf, ath->methd->d, ath->methd->len );
    _gsti_buf_putc( buf, ath->false );
    _gsti_buf_putstr( buf, ath->pkalgo->d, ath->pkalgo->len );
    _gsti_buf_putstr( buf, ath->key->d, ath->key->len );
    if( ath->sig )
        _gsti_buf_putstr( buf, ath->sig->d, ath->sig->len );

    len = _gsti_buf_getlen( buf );
    pkt->type = SSH_MSG_USERAUTH_REQUEST;
    pkt->payload_len = len + 1;
    memcpy( pkt->payload + 1, _gsti_buf_getptr( buf ), len );
    
    _gsti_buf_free( buf );
    return 0;
}

static void
free_auth_request( MSG_auth_request *ath )
{
    _gsti_bstring_free( ath->user );
    _gsti_bstring_free( ath->svcname );
    _gsti_bstring_free( ath->methd );
    _gsti_bstring_free( ath->pkalgo );
    _gsti_bstring_free( ath->key );
    _gsti_bstring_free( ath->sig );
}

static int
init_auth_request( MSG_auth_request *ath, const char *user, int false,
                   GSTI_KEY pk, const byte *sigblob, size_t siglen )
{
    const char *s;
    byte *p;
    size_t n;
    
    ath->user = _gsti_bstring_make( user, strlen( user ) );
    s = "ssh-userauth";
    ath->svcname = _gsti_bstring_make( s, strlen( s ) );
    s = "publickey";
    ath->methd = _gsti_bstring_make( s, strlen( s ) );
    ath->false = false;
    p = _gsti_ssh_get_pkname( pk->type, 0, &n );
    ath->pkalgo = _gsti_bstring_make( p, n );
    _gsti_free( p );
    ath->key = _gsti_key_getblob( pk );
    if( sigblob )
        ath->sig = _gsti_bstring_make( sigblob, siglen );

    return 0;
}
    

static void
dump_auth_request( MSG_auth_request *ath )
{
    _gsti_log_debug( "MSG_auth_request:\n" );
    _gsti_dump_bstring( "user: ", ath->user );
    _gsti_dump_bstring( "service: ", ath->svcname );
    _gsti_dump_bstring( "method: ", ath->methd );
    _gsti_log_debug( "false=%d\n", ath->false );
    _gsti_dump_bstring( "key: ", ath->key );
    _gsti_dump_bstring( "signature: ", ath->sig );
    _gsti_log_debug( "\n" );
}

int
auth_send_init_packet( GSTIHD hd, const char *user, GSTI_KEY pk )
{
    MSG_auth_request ath;
    int rc;
    
    memset( &ath, 0, sizeof ath );
    rc = init_auth_request( &ath, user, 0, pk, NULL, 0 );
    if( !rc )
        rc = build_auth_request( &ath, &hd->pkt );
    if( !rc )
        rc = _gsti_packet_write( hd );

    free_auth_request( &ath );
    return rc;
}


static int
parse_auth_request( MSG_auth_request *ath, const byte *msg, size_t msglen )
{
    BUFFER buf;
    byte *p;
    size_t n;
    int rc = 0;
    
    memset( ath, 0, sizeof *ath );
    if( msglen < (4+4+4+1+4+4) )
        return GSTI_TOO_SHORT;

    _gsti_buf_init( &buf );
    _gsti_buf_putraw( buf, msg, msglen );
    if( _gsti_buf_getc( buf ) != SSH_MSG_USERAUTH_REQUEST ) {
        rc = GSTI_BUG;
        goto leave;
    }
    p = _gsti_buf_getstr( buf, &n );
    if( p )
        ath->user = _gsti_bstring_make( p, n );
    _gsti_free( p );

    p = _gsti_buf_getstr( buf, &n );
    if( p )
        ath->svcname = _gsti_bstring_make( p, n );
    _gsti_free( p );

    p = _gsti_buf_getstr( buf, &n );
    if( p )
        ath->methd = _gsti_bstring_make( p, n );
    _gsti_free( p );

    ath->false = _gsti_buf_getc( buf );

    p = _gsti_buf_getstr( buf, &n );
    if( p )
        ath->pkalgo = _gsti_bstring_make( p, n );
    _gsti_free( p );

    p = _gsti_buf_getstr( buf, &n );
    if( p )
        ath->key = _gsti_bstring_make( p, n );
    _gsti_free( p );

    if( _gsti_buf_getlen( buf ) )
        rc = GSTI_INV_PKT;

leave:
    _gsti_buf_free( buf );
    
    return rc;
}


int
auth_proc_init_packet( GSTIHD hd )
{
    MSG_auth_request ath;
    int rc;
    
    if( hd->pkt.type != SSH_MSG_USERAUTH_REQUEST )
        return GSTI_BUG;

    rc = parse_auth_request( &ath, hd->pkt.payload, hd->pkt.payload_len );
    if( rc )
        return rc;
    hd->auth.user = _gsti_strdup( ath.user->d );
    hd->auth.peer_pk = _gsti_key_fromblob( ath.key );
    
    dump_auth_request( &ath );

    free_auth_request( &ath );
    
    return rc;
}


int
calc_sig_hash( BSTRING sessid, MSG_auth_request *ath, BSTRING *r_digest )
{
    GCRY_MD_HD md;
    int dlen = gcry_md_get_algo_dlen( GCRY_MD_SHA1 );

    md = gcry_md_open( GCRY_MD_SHA1, 0 );
    if( !md )
        return map_gcry_rc( gcry_errno() );
    _gsti_bstring_hash( md, sessid );
    gcry_md_putc( md, SSH_MSG_USERAUTH_REQUEST );
    _gsti_bstring_hash( md, ath->user );
    _gsti_bstring_hash( md, ath->svcname );
    _gsti_bstring_hash( md, ath->methd );
    gcry_md_putc( md, 1 );
    _gsti_bstring_hash( md, ath->pkalgo );
    _gsti_bstring_hash( md, ath->key );

    gcry_md_final( md );
    *r_digest = _gsti_bstring_make( gcry_md_read( md, 0 ), dlen );
    gcry_md_close( md );
    
    return 0;
}
    

int
auth_send_second_packet( GSTIHD hd, const char *user, GSTI_KEY sk )
{
    MSG_auth_request ath;
    BSTRING sig = NULL, hash;
    int rc;

    memset( &ath, 0, sizeof ath );
    rc = init_auth_request( &ath, user, 1, sk, NULL, 0 );
    if( !rc )
        rc = calc_sig_hash( hd->session_id, &ath, &hash );
    if( !rc )
        sig = _gsti_sig_encode( sk, hash->d );
    if( sig )
        ath.sig = sig;
    else
        goto leave;
    if( !rc )
        rc = build_auth_request( &ath, &hd->pkt );
    if( !rc )
        rc = _gsti_packet_write( hd );

 leave:
    free_auth_request( &ath );
    _gsti_bstring_free( hash );
    _gsti_bstring_free( sig );

    return rc;
}

    
