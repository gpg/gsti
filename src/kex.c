/* kex.c - connect, key exchange and service request
 *	Copyright (C) 1999 Free Software Foundation, Inc.
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
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "api.h"
#include "memory.h"
#include "stream.h"
#include "packet.h"
#include "utils.h"
#include "kex.h"
#include "buffer.h"
#include "pubkey.h"

static const char host_version_string[] =
	"SSH-2.0-GSTI_0.2 GNU Transport Library";

static const byte diffie_hellman_group1_prime[130] = { 0x04, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
    0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
    0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
    0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
    0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
    0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
    0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
    0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
    0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
    0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF  };

static algorithm_list hmac_list[] = {
    { "hmac-sha1",      SSH_HMAC_SHA1,   0, 0, 20 },
    { "hmac-sha1-96",   SSH_HMAC_SHA1,   0, 0, 12 },
    { "hmac-md5",       SSH_HMAC_MD5,    0, 0, 16 },
    { "hmac-md5-96",    SSH_HMAC_MD5,    0, 0, 12 },
    { "hmac-ripemd160", SSH_HMAC_RMD160, 0, 0, 20 },
    {0}
};


static algorithm_list cipher_list[] = {
    { "3des-cbc",       SSH_CIPHER_3DES,        8, GCRY_CIPHER_MODE_CBC, 24 },
    { "blowfish-cbc",   SSH_CIPHER_BLOWFISH,    8, GCRY_CIPHER_MODE_CBC, 16 },
    { "cast128-cbc",    SSH_CIPHER_CAST128,     8, GCRY_CIPHER_MODE_CBC, 16 },
    { "twofish256-cbc", SSH_CIPHER_TWOFISH256, 16, GCRY_CIPHER_MODE_CBC, 32 },
    { "aes128-cbc",     SSH_CIPHER_AES128,     16, GCRY_CIPHER_MODE_CBC, 16 },
    {0}
};


static int
cmp_bstring( BSTRING a, BSTRING b )
{
    int rc = 0;
    
    if ( a->len < b->len )
        rc = -1;
    else if ( a->len > b->len )
        rc = 1;
    else if ( a->len == b->len )
        rc = memcmp( a->d, b->d, a->len );
    return rc;    
}


int
kex_send_version( GSTIHD hd )
{
    WRITE_STREAM wst = hd->write_stream;
    const char *ver = host_version_string;

    if( _gsti_stream_writen( wst, ver, strlen( ver ) ) )
        return GSTI_WRITE_ERROR;
    if( _gsti_stream_writen( wst, "\r\n", 2 ) )
        return GSTI_WRITE_ERROR;
    if( _gsti_stream_flush( wst ) )
        return GSTI_WRITE_ERROR;
    return 0;
}


/****************
 * This functions reads from the input source until it either finds
 * a valid version string, which it will parse ans store away for
 * later reference.  If it does not find such a string it returns
 * an error.
 */
int
kex_wait_on_version( GSTIHD hd )
{
    static int initstr[4] = { 0x53, 0x53, 0x48, 0x2d };  /* "SSH-" in ascii */
    READ_STREAM rst = hd->read_stream;
    char version[300];
    int any = 0, pos = 0;
    int c;

    /* wait for the initial 4 bytes */
    while( (c = _gsti_stream_get( rst )) != -1 ) {
        any = 1;
        if( c == '\n' )
            pos = 0;
        else if( pos < 4 ) {
            if( initstr[pos] != c )
                pos = 4; /* skip this line */
            else if( pos == 3 )
                break;
            else
                pos++;
        }
        else if( pos < 100 ) /* to avaoid integer overflow ;-) */
            pos++;
    }
    if( c == -1 )
        return any ? GSTI_NO_DATA : GSTI_NOT_SSH;

    /* store the version string */
    memcpy( version, "SSH-", 4 );
    c = 0;
    for( pos = 4; pos < 256; pos++ ) {
        if( (c = _gsti_stream_get( rst )) == -1 || c == '\n' )
            break;
        version[pos] = c;
    }
    if( c == -1 )
        return GSTI_PRE_EOF;
    if( c != '\n' )
        return GSTI_TOO_LARGE;
    if( version[pos-1] == '\r' )
        pos--;
    version[pos] = 0;
    _gsti_free( hd->peer_version_string );
    hd->peer_version_string = _gsti_bstring_make( version, strlen( version ) );

    return 0;
}


static void
free_msg_kexinit( MSG_kexinit *kex )
{
    if( kex ) {
        _gsti_strlist_free( kex->kex_algo );
        _gsti_strlist_free( kex->server_host_key_algos );
        _gsti_strlist_free( kex->encr_algos_c2s );
        _gsti_strlist_free( kex->encr_algos_s2c );
        _gsti_strlist_free( kex->mac_algos_c2s );
        _gsti_strlist_free( kex->mac_algos_s2c );
        _gsti_strlist_free( kex->compr_algos_c2s );
        _gsti_strlist_free( kex->compr_algos_s2c );
    }
}


/****************
 * Parse a SSH_MSG_KEXINIT and return the parsed information in
 * a newly allocated struture.
 * Rteurns: 0 on success or an errorcode.
 */
static int
parse_msg_kexinit( MSG_kexinit *kex, int we_are_server, byte *old_cookie,
                   const byte *msg, size_t msglen )
{
    STRLIST algolist[10] = {NULL};
    BUFFER buf = NULL;
    byte *p;
    u32 len;
    int i, rc = 0;

    memset( kex, 0, sizeof *kex );
    if( msglen < (1+16+10*4+1+4) )
        return GSTI_TOO_SHORT;
    _gsti_buf_init( &buf );
    _gsti_buf_putraw( buf, msg, msglen );
    if( _gsti_buf_getc( buf ) != SSH_MSG_KEXINIT ) {
        rc = GSTI_BUG;
        goto leave;
    }
    if( we_are_server )
        _gsti_buf_getraw( buf, kex->cookie, 16 );
    else {
        /* We skip the cookie the server sent to us. This makes sure both
           sides can calculate the same key data. Instead we use the one
           we generated. */
        for( i = 0; i < 16; i++ )
            _gsti_buf_getc( buf );
        memcpy( kex->cookie, old_cookie, 16 );
    }

    /* get 10 strings */
    for( i = 0; i < 10; i++ ) {
        if( _gsti_buf_getlen( buf ) < 4 ) {
            rc = GSTI_TOO_SHORT;
            goto leave;
        }
        p = _gsti_buf_getstr( buf, &len );
        if( !len ) {
            rc = GSTI_TOO_SHORT;
            goto leave;
        }
        algolist[i] = p? _gsti_algolist_parse( p, len ) : NULL;
        _gsti_free( p );
    }
    kex->kex_algo = algolist[0];
    kex->server_host_key_algos = algolist[1];
    kex->encr_algos_c2s = algolist[2];
    kex->encr_algos_s2c = algolist[3];
    kex->mac_algos_c2s = algolist[4];
    kex->mac_algos_s2c = algolist[5];
    kex->compr_algos_c2s = algolist[6];
    kex->compr_algos_s2c = algolist[7];
    /* (we don't need the two language lists) */

    kex->first_kex_packet_follows = _gsti_buf_getc( buf );
 
    /* make sure that the reserved value is zero */
    if( _gsti_buf_getint( buf ) ) {
        rc = GSTI_INV_PKT;
        goto leave;
    }

    /* make sure the msg length matches */
    if( _gsti_buf_getlen( buf ) )
        rc = GSTI_INV_PKT;

leave:
    _gsti_buf_free( buf );
    if( rc ) {
        free_msg_kexinit( kex );
        memset( kex, 0, sizeof *kex );
    }
    return rc;
}


/****************
 * Build a KEX packet.
 */
static int
build_msg_kexinit( MSG_kexinit *kex, struct packet_buffer_s *pkt )
{
    STRLIST algolist[10];
    byte *p = pkt->payload;
    size_t length = pkt->size, n;
    int i;

    assert( length > 100 );

    pkt->type = SSH_MSG_KEXINIT;
    p++; length--;
    memcpy( p, kex->cookie, 16 );
    p += 16; length -= 16;
    /* put 10 strings */
    algolist[0] = kex->kex_algo;
    algolist[1] = kex->server_host_key_algos;
    algolist[2] = kex->encr_algos_c2s;
    algolist[3] = kex->encr_algos_s2c;
    algolist[4] = kex->mac_algos_c2s;
    algolist[5] = kex->mac_algos_s2c;
    algolist[6] = kex->compr_algos_c2s;
    algolist[7] = kex->compr_algos_s2c;
    algolist[8] = NULL;
    algolist[9] = NULL;
    for( i = 0; i < 10; i++ ) {
        n = _gsti_algolist_build( p, length, algolist[i] );
        if( !n )
            return GSTI_TOO_SHORT;
        assert( n <= length );
        p += n; length -= n;
    }
    if( !length )
        return GSTI_TOO_SHORT;
    *p++ = !!kex->first_kex_packet_follows;
    length--;
    if( length < 4 )
        return GSTI_TOO_SHORT;
    *p++ = 0;	/* a reserved u32 */
    *p++ = 0;
    *p++ = 0;
    *p++ = 0;
    length -= 4;
    pkt->payload_len = p - pkt->payload;

    return 0;
}


static void
dump_msg_kexinit( MSG_kexinit *kex )
{
    _gsti_log_debug( "MSG_kexinit:\n" );
    _gsti_dump_hexbuf( "cookie: ", kex->cookie, 16 );
    _gsti_dump_strlist( "kex_algorithm", kex->kex_algo );
    _gsti_dump_strlist( "server_host_key_algos", kex->server_host_key_algos );
    _gsti_dump_strlist( "encr_algos_c2s", kex->encr_algos_c2s );
    _gsti_dump_strlist( "encr_algos_s2c", kex->encr_algos_s2c );
    _gsti_dump_strlist( "mac_algos_c2s", kex->mac_algos_c2s );
    _gsti_dump_strlist( "mac_algos_s2c",kex->mac_algos_s2c );
    _gsti_dump_strlist( "compr_algos_c2s", kex->compr_algos_c2s );
    _gsti_dump_strlist( "compr_algos_s2c", kex->compr_algos_s2c );
    if( kex->first_kex_packet_follows )
        _gsti_log_debug( "fist_kex_packet_follows\n" );
    _gsti_log_debug( "\n" );
}



/****************
 * Parse a SSH_MSG_KEXDH_INIT and return the parsed information in
 * a newly allocated struture.
 * Rteurns: 0 on success or an errorcode.
 */
static int
parse_msg_kexdh_init( MSG_kexdh_init *kexdh, const byte *msg, size_t msglen )
{
    BUFFER buf = NULL;
    size_t n;
    int rc = 0;

    memset( kexdh, 0, sizeof *kexdh );
    if( msglen < (1+4) )
        return GSTI_TOO_SHORT;
    _gsti_buf_init( &buf );
    _gsti_buf_putraw( buf, msg, msglen );
    if( _gsti_buf_getc( buf ) != SSH_MSG_KEXDH_INIT ) {
        rc = GSTI_BUG;
        goto leave;
    }        
    rc = _gsti_buf_getmpi( buf, &kexdh->e, &n );
    if( rc )
        goto leave;
    /* a value which is not in the range [1, p-1] is considered as a
       protocol violation */
    if( (n-4) > sizeof diffie_hellman_group1_prime )
        return GSTI_PROT_VIOL;

    /* make sure the msg length matches */
    if( _gsti_buf_getlen( buf ) )
        rc = GSTI_INV_PKT;
leave:
    _gsti_buf_free( buf );
    
    return rc;
}

/****************
 * Build a KEXDH packet.
 */
static int
build_msg_kexdh_init( MSG_kexdh_init *kexdh, struct packet_buffer_s *pkt )
{
    BUFFER buf = NULL;
    size_t len;
    int rc;

    assert( pkt->size > 100 );

    _gsti_buf_init( &buf );
    _gsti_buf_putc( buf, 0 );
    rc = _gsti_buf_putmpi( buf, kexdh->e );
    if( rc )
        goto leave;
    len = _gsti_buf_getlen( buf );
    if( len > pkt->size - 1 )
        return GSTI_TOO_LARGE;
    pkt->type = SSH_MSG_KEXDH_INIT;
    pkt->payload_len = len;
    memcpy( pkt->payload, _gsti_buf_getptr( buf ), len );

leave:
    _gsti_buf_free( buf );
    
    return rc;
}


static void
dump_msg_kexdh_init( MSG_kexdh_init *kexdh )
{
    _gsti_log_debug( "MSG_kexdh_init:\n" );
    _gsti_dump_mpi( "e=", kexdh->e );
    _gsti_log_debug( "\n" );
}




/****************
 * Parse a SSH_MSG_KEXDH_REPLY and return the parsed information in
 * a newly allocated struture.
 * Rteurns: 0 on success or an errorcode.
 */
static int
parse_msg_kexdh_reply( MSG_kexdh_reply *dhr, const byte *msg, size_t msglen )
{
    BUFFER buf = NULL;
    size_t n;
    int rc = 0;

    memset( dhr, 0, sizeof *dhr );
    if( msglen < (1+4+4+4) )
        return GSTI_TOO_SHORT;
    _gsti_buf_init( &buf );
    _gsti_buf_putraw( buf, msg, msglen );
    if( _gsti_buf_getc( buf ) != SSH_MSG_KEXDH_REPLY ) {
        rc = GSTI_BUG;
        goto leave;
    }

    rc = _gsti_buf_getbstr( buf, &dhr->k_s );
    if( rc )
        goto leave;
    rc = _gsti_buf_getmpi( buf, &dhr->f, &n );
    if( rc )
        goto leave;
    /* a value which is not in the range [1, p-1] is considered as a
       protocol violation */
    if( (n-4) > sizeof diffie_hellman_group1_prime )
        return GSTI_PROT_VIOL;

    rc = _gsti_buf_getbstr( buf, &dhr->sig_h );
    if( rc )
        goto leave;

    msglen = _gsti_buf_getlen( buf );
    /* make sure the msg length matches */
    if( msglen ) {
        _gsti_log_info( "parse_msg_kexdh_reply: %lu bytes remaining\n",
                        (u32)msglen );
        rc = GSTI_INV_PKT;
    }
leave:
    _gsti_buf_free( buf );
    
    return rc;
}

/****************
 * Build a KEXDH_REPLY packet.
 */
static int
build_msg_kexdh_reply( MSG_kexdh_reply *dhr, struct packet_buffer_s *pkt )
{
    BUFFER buf = NULL;
    size_t len;
    int rc;

    assert( pkt->size > 100 );

    pkt->type = SSH_MSG_KEXDH_REPLY;
    _gsti_buf_init( &buf );
    _gsti_buf_putc( buf, 0 );    
    _gsti_buf_putbstr( buf, dhr->k_s );
     
    rc = _gsti_buf_putmpi( buf, dhr->f );
    if( rc )
        goto leave;

    _gsti_buf_putbstr( buf, dhr->sig_h );
    len = _gsti_buf_getlen( buf );
    if( len > pkt->size ) {
        rc = GSTI_TOO_LARGE;
        goto leave;
    }
    memcpy( pkt->payload, _gsti_buf_getptr( buf ), len );
    pkt->payload_len = len;

leave:
    _gsti_buf_free( buf );
    
    return rc;
}


static void
dump_msg_kexdh_reply( MSG_kexdh_reply *dhr )
{
    _gsti_log_debug( "MSG_kexdh_reply:\n" );
    _gsti_dump_bstring( "k_s=", dhr->k_s );
    _gsti_dump_mpi( "f=", dhr->f );
    _gsti_dump_bstring( "sig_h=", dhr->sig_h );
    _gsti_log_debug( "\n" );
}


/****************
 * Choose a random value x and calculate e = g^x mod p.
 * Return: e and if ret_x is not NULL x.
 */
static GCRY_MPI
calc_dh_secret( GCRY_MPI *ret_x )
{
    GCRY_MPI e, g, x, prime;
    size_t n = sizeof diffie_hellman_group1_prime;

    if( gcry_mpi_scan( &prime, GCRYMPI_FMT_STD,
                       diffie_hellman_group1_prime, &n ) )
        abort();
    /*_gsti_dump_mpi( "prime=", prime );*/

    g = gcry_mpi_set_ui( NULL, 2 );
    x = gcry_mpi_snew( 200 );
    gcry_mpi_randomize( x, 200, GCRY_STRONG_RANDOM );

    e = gcry_mpi_new( 1024 );
    gcry_mpi_powm( e, g, x, prime );
    if( ret_x )
        *ret_x = x;
    else
        gcry_mpi_release( x );
    gcry_mpi_release( g );
    gcry_mpi_release( prime );
    return e;
}


static void
hash_mpi( GCRY_MD_HD md, GCRY_MPI a )
{
    byte buf[512];
    size_t n = sizeof buf - 1;

    if( gcry_mpi_print( GCRYMPI_FMT_SSH, buf, &n, a ) )
        _gsti_log_info( "Oops: MPI too large for hashing\n" );
    else
        gcry_md_write( md, buf, n );
}


static GCRY_MPI
calc_dh_key( GCRY_MPI f, GCRY_MPI x )
{
    GCRY_MPI k, prime;
    size_t n = sizeof diffie_hellman_group1_prime;

    if( gcry_mpi_scan( &prime, GCRYMPI_FMT_STD,
                       diffie_hellman_group1_prime, &n ) )
        abort();

    k = gcry_mpi_snew( 1024 );
    gcry_mpi_powm( k, f, x, prime );
    gcry_mpi_release( prime );
    return k;
}


/****************
 * calculate the exchange hash value and put it into the handle.
 */
static int
calc_exchange_hash( GSTIHD hd, BSTRING i_c, BSTRING i_s,
                    BSTRING k_s, GCRY_MPI e,  GCRY_MPI f )
{
    GCRY_MD_HD md;
    BSTRING pp;
    const char *ver = host_version_string;
    int algo = GCRY_MD_SHA1, dlen;

    md = gcry_md_open( algo, 0 );
    if( !md )
        return map_gcry_rc( gcry_errno() );

    if( hd->we_are_server ) {
        _gsti_bstring_hash( md, hd->peer_version_string );
        pp = _gsti_bstring_make( ver, strlen( ver ) );
        _gsti_bstring_hash( md, pp );
        _gsti_free( pp );
    }
    else {
        pp = _gsti_bstring_make( ver, strlen( ver ) );
        _gsti_bstring_hash( md, pp );
        _gsti_free( pp );
        _gsti_bstring_hash( md, hd->peer_version_string );
    }
    _gsti_bstring_hash( md, i_c );
    _gsti_bstring_hash( md, i_s );
    _gsti_bstring_hash( md, k_s );
    hash_mpi( md, e );
    hash_mpi( md, f );
    hash_mpi( md, hd->kex.k );

    dlen = gcry_md_get_algo_dlen( algo );
    hd->kex.h = _gsti_bstring_make( gcry_md_read( md, algo ), dlen );
    if( !hd->session_id ) /* initialize the session id the first time */
        hd->session_id = _gsti_bstring_make( gcry_md_read( md, algo ), dlen );
    gcry_md_close( md );
    _gsti_dump_hexbuf( "SesID=", hd->session_id->d, hd->session_id->len );
    return 0;
}


/* Hmm. We need to have a new_kex structure so that the old
   kex data can be used until we have send the NEWKEYs msg
   Well, doesn't matter for now. */
static BSTRING
construct_one_key( GSTIHD hd, GCRY_MD_HD md1, int algo,
		   const byte *letter, size_t size )
{
    BSTRING hash;
    GCRY_MD_HD md = gcry_md_copy( md1 );
    size_t n, n1;

    hash = _gsti_bstring_make( NULL, size );
    gcry_md_write( md, letter, 1 );
    gcry_md_write( md, hd->session_id->d, hd->session_id->len );
    n = gcry_md_get_algo_dlen( algo );
    if( n > size )
        n = size;
    memcpy( hash->d, gcry_md_read( md, algo ), n );
    while( n < size ) {
        gcry_md_close( md );
        md = gcry_md_copy( md1 );
        gcry_md_write( md, hash->d, n );
        n1 = gcry_md_get_algo_dlen( algo );
        if( n1 > size-n )
            n1 = size-n;
        memcpy( hash->d + n, gcry_md_read( md, algo ), n1 );
        n += n1;
    }
    gcry_md_close( md );

    return hash;
}


static int
construct_keys( GSTIHD hd )
{
    GCRY_MD_HD md;
    int algo = GCRY_MD_SHA1;
    int keylen, blksize, maclen;

    if( hd->kex.iv_a )
        return 0;   /* already constructed */

    md = gcry_md_open( algo, 0 );
    if( !md )
        return map_gcry_rc( gcry_errno() );

    hash_mpi( md, hd->kex.k );
    gcry_md_write( md, hd->kex.h->d, hd->kex.h->len );

    blksize = hd->ciph_blksize;
    maclen = hd->mac_len;
    keylen = gcry_cipher_get_algo_keylen( hd->ciph_algo );

    hd->kex.iv_a = construct_one_key( hd, md, algo, "\x41", blksize );
    hd->kex.iv_b = construct_one_key( hd, md, algo, "\x42", blksize );
    hd->kex.key_c = construct_one_key( hd, md, algo, "\x43", keylen );
    hd->kex.key_d = construct_one_key( hd, md, algo, "\x44", keylen );
    hd->kex.mac_e = construct_one_key( hd, md, algo, "\x45", maclen );
    hd->kex.mac_f = construct_one_key( hd, md, algo, "\x46", maclen );
    gcry_md_close( md );

    _gsti_dump_hexbuf( "key A=", hd->kex.iv_a->d, hd->kex.iv_a->len );
    _gsti_dump_hexbuf( "key B=", hd->kex.iv_b->d, hd->kex.iv_b->len );
    _gsti_dump_hexbuf( "key C=", hd->kex.key_c->d, hd->kex.key_c->len );
    _gsti_dump_hexbuf( "key D=", hd->kex.key_d->d, hd->kex.key_d->len );
    _gsti_dump_hexbuf( "key E=", hd->kex.mac_e->d, hd->kex.mac_e->len );
    _gsti_dump_hexbuf( "key F=", hd->kex.mac_f->d, hd->kex.mac_f->len );

    return 0;
}

static void
build_cipher_list( GSTIHD hd, STRLIST *c2s, STRLIST *s2c )
{
    const char *s;
    int i;

    /* do it in reserved order so it's correct in the list */
    i = DIM( cipher_list ) - 1;
    while( i-- ) {
        s = cipher_list[i].name;
        *s2c = _gsti_strlist_insert( *s2c, s );
        *c2s = _gsti_strlist_insert( *c2s, s );
    }
}
    
static void
build_hmac_list( GSTIHD hd, STRLIST *c2s, STRLIST *s2c )
{
    const char *s;
    int i;

    /* do it in reserved order so it's correct in the list */
    i = DIM( hmac_list ) - 1;
    while( i-- ) {
        s = hmac_list[i].name;
        *s2c = _gsti_strlist_insert( *s2c, s );
        *c2s = _gsti_strlist_insert( *c2s, s );
    }
}


static void
build_compress_list( GSTIHD hd, STRLIST *c2s, STRLIST *s2c )
{
    *c2s = _gsti_strlist_insert( NULL, "none" );
    *s2c = _gsti_strlist_insert( NULL, "none" );
#ifdef USE_NEWZLIB
    if( hd->zlib.use ) {
        *c2s = _gsti_strlist_insert( *c2s, "zlib" );
        *s2c = _gsti_strlist_insert( *s2c, "zlib" );
    }
#endif
}
    

int
kex_send_init_packet( GSTIHD hd )
{
    MSG_kexinit kex;
    const byte *p;
    int rc = 0;

    /* first send our kexinit packet */
    memset( &kex, 0, sizeof kex );

    /* we need the cookie later, so store it */
    gcry_randomize( kex.cookie, 16, GCRY_STRONG_RANDOM );
    memcpy( hd->cookie, kex.cookie, 16 );
    
    kex.kex_algo = _gsti_strlist_insert( NULL, "diffie-hellman-group1-sha1" );
    kex.server_host_key_algos = _gsti_strlist_insert( NULL, "ssh-dss" );
    build_cipher_list( hd, &kex.encr_algos_c2s, &kex.encr_algos_s2c );
    build_hmac_list( hd, &kex.mac_algos_c2s, &kex.mac_algos_s2c );
    build_compress_list( hd, &kex.compr_algos_c2s, &kex.compr_algos_s2c );
    rc = build_msg_kexinit( &kex, &hd->pkt );
    if( !rc )
        rc = _gsti_packet_write( hd );
    if( rc ) {
        free_msg_kexinit( &kex );
        return rc;
    }
    /* must do it here because write_packet fills in the packet type */
    p = hd->pkt.payload;
    hd->host_kexinit_data = _gsti_bstring_make( p, hd->pkt.payload_len );
    rc = _gsti_packet_flush( hd );
    return rc;
}
    

/****************
 * Choose a MAC algorithm that is supported by both sides.
 */
static int
choose_mac_algo( GSTIHD hd, STRLIST cli, STRLIST srv )
{
    STRLIST l;
    const char *s;
    int res = 0, i;

    for( l = cli; l && !res; l = l->next ) {
        res = _gsti_algolist_find( srv, l->d );
        if( !res )
            continue;
        for( i = 0; (s = hmac_list[i].name); i++ ) {
            if( !strcmp( s, l->d ) ) {
                _gsti_log_debug( "chosen mac: %s (maclen %d)\n",
                                 hmac_list[i].name, hmac_list[i].len );
                hd->mac_algo = hmac_list[i].algid;
                hd->mac_len = hmac_list[i].len;
                return 0;
            }
        }
    }
    return GSTI_INV_OBJ;
}

/****************
 * Choose a cipher algorithm which is available on both sides.
 */
static int
choose_cipher_algo( GSTIHD hd, STRLIST cli, STRLIST srv )
{
    STRLIST l;
    const char *s;
    int res = 0, i;

    for( l = cli; l && !res; l = l->next ) {
        res = _gsti_algolist_find( srv, l->d );
        if( !res )
            continue;
        for( i = 0; (s = cipher_list[i].name); i++ ) {
            if( !strcmp( s, l->d ) ) {
                _gsti_log_debug( "chosen cipher: %s (blklen %d, keylen %d)\n",
                                 cipher_list[i].name,
                                 cipher_list[i].blksize,
                                 cipher_list[i].len );
                hd->ciph_blksize = cipher_list[i].blksize;
                hd->ciph_algo = cipher_list[i].algid;
                hd->ciph_mode = cipher_list[i].mode;
                return 0;
            }
        }
    }
    return GSTI_INV_OBJ;
}
        
    
/****************
 * Process a received key init packet.
 */
int
kex_proc_init_packet( GSTIHD hd )
{
    MSG_kexinit kex;
    int rc;

    if( hd->pkt.type != SSH_MSG_KEXINIT )
        return GSTI_BUG;
    rc = parse_msg_kexinit( &kex, hd->we_are_server, hd->cookie,
                            hd->pkt.payload, hd->pkt.payload_len );
    if( rc )
        return rc;
    rc = choose_mac_algo( hd, kex.mac_algos_c2s, kex.mac_algos_s2c );
    if( rc )
        return rc;
    rc = choose_cipher_algo( hd, kex.encr_algos_c2s, kex.encr_algos_s2c );
    if( rc )
        return rc;

    if( !hd->we_are_server ) {
        /* We replace the cookie inside with the right cookie to
           calculate a valid message digest. */
        memcpy( hd->pkt.packet_buffer + 6, hd->cookie, 16 );
        hd->pkt.payload = hd->pkt.packet_buffer + 5;
    }
    else {
        /* The server still has its own cookie in the host data, we
           need to replace this with the received (client) cookie. */
        memcpy( hd->host_kexinit_data->d + 1, kex.cookie, 16 );
    }
    /* make a copy of the received payload which we will need later */
    hd->peer_kexinit_data = _gsti_bstring_make( hd->pkt.payload,
                                                hd->pkt.payload_len );
    
    dump_msg_kexinit( &kex );
    return 0;
}


/****************
 * Send a KEX init packet (we are in the client role)
 */
int
kex_send_kexdh_init( GSTIHD hd )
{
    MSG_kexdh_init kexdh;
    int rc = 0;

    memset( &kexdh, 0, sizeof kexdh );
    kexdh.e = hd->kexdh_e = calc_dh_secret( &hd->secret_x );
    rc = build_msg_kexdh_init( &kexdh, &hd->pkt );
    if( rc )
        return rc;
    rc = _gsti_packet_write( hd );
    if( rc )
        return rc;
    rc = _gsti_packet_flush( hd );
    return rc;
}


/****************
 * Process the received DH init (we are in the server role)
 */
int
kex_proc_kexdh_init( GSTIHD hd )
{
    int rc;
    MSG_kexdh_init kexdh;

    if( hd->pkt.type != SSH_MSG_KEXDH_INIT )
        return GSTI_BUG;

    rc = parse_msg_kexdh_init( &kexdh, hd->pkt.payload, hd->pkt.payload_len );
    if( rc )
        return rc;

    /* we need the received e later */
    hd->kexdh_e = kexdh.e;

    dump_msg_kexdh_init( &kexdh );
    return 0;
}


/****************
 * Send a DH init packet (we are in the server role)
 */
int
kex_send_kexdh_reply( GSTIHD hd )
{
    MSG_kexdh_reply dhr;
    int rc;
    GCRY_MPI y;

    memset( &dhr, 0, sizeof dhr );
    dhr.k_s = _gsti_key_getblob( hd->hostkey );

    /* generate our secret and the public value for it */
    dhr.f = calc_dh_secret( &y );
    /* now we can calculate the shared secret */
    hd->kex.k = calc_dh_key( hd->kexdh_e, y );
    gcry_mpi_release( y );
    /* and the hash */
    rc = calc_exchange_hash( hd, hd->host_kexinit_data, hd->peer_kexinit_data,
                             dhr.k_s, hd->kexdh_e, dhr.f );
    gcry_mpi_release( hd->kexdh_e );
    if( rc )
        return rc;
    dhr.sig_h = _gsti_sig_encode( hd->hostkey, hd->kex.h->d );

    rc = build_msg_kexdh_reply( &dhr, &hd->pkt );
    if( !rc )
        dump_msg_kexdh_reply( &dhr );
    if( !rc )
        rc = _gsti_packet_write( hd );
    if( !rc )
        rc = _gsti_packet_flush( hd );
    return rc;
}

/****************
 * Process the received DH value and take the encryption kes into use.
 * (we are in the client role)
 */
int
kex_proc_kexdh_reply( GSTIHD hd )
{
    int rc;
    MSG_kexdh_reply dhr;

    if( hd->pkt.type != SSH_MSG_KEXDH_REPLY )
        return GSTI_BUG;

    rc = parse_msg_kexdh_reply( &dhr, hd->pkt.payload, hd->pkt.payload_len );
    if( rc )
        return rc;

    dump_msg_kexdh_reply( &dhr );

    hd->kex.k = calc_dh_key( dhr.f, hd->secret_x );
    gcry_mpi_release( hd->secret_x );

    rc = calc_exchange_hash( hd, hd->host_kexinit_data, hd->peer_kexinit_data,
                             dhr.k_s, hd->kexdh_e, dhr.f );
    gcry_mpi_release( hd->kexdh_e );
    if( rc )
        return rc;

    rc = _gsti_sig_decode( dhr.k_s, dhr.sig_h, hd->kex.h->d, &hd->hostkey );

    return rc;
}


int
kex_send_newkeys( GSTIHD hd )
{
    int rc;

    rc = construct_keys( hd );
    if( rc )
        return rc;

    hd->pkt.type = SSH_MSG_NEWKEYS;
    hd->pkt.payload_len = 1;
    rc = _gsti_packet_write( hd );
    if( !rc )
        rc = _gsti_packet_flush( hd );
    if( rc )
        return rc;

    /* now we have to take the encryption keys into use */
    hd->encrypt_hd = gcry_cipher_open( hd->ciph_algo, hd->ciph_mode, 0 );
    if( !hd->ciph_blksize )
        hd->ciph_blksize = gcry_cipher_get_algo_blklen( hd->ciph_algo );
    if( !hd->encrypt_hd )
        rc = map_gcry_rc( gcry_errno() );
    else if( hd->we_are_server ) {
        if( !rc )
            rc = gcry_cipher_setkey( hd->encrypt_hd, hd->kex.key_d->d,
                                     hd->kex.key_d->len );
        if( !rc )
            rc = gcry_cipher_setiv( hd->encrypt_hd, hd->kex.iv_b->d,
                                    hd->kex.iv_b->len );
        rc = map_gcry_rc( rc );
        if( !rc ) {
            hd->send_mac = gcry_md_open( hd->mac_algo, GCRY_MD_FLAG_HMAC );
            if( !hd->send_mac )
                rc = map_gcry_rc( gcry_errno() );
            if( !rc )
                rc = gcry_md_setkey( hd->send_mac, hd->kex.mac_f->d,
                                     hd->kex.mac_f->len );
        }
    }
    else {
        if( !rc )
            rc = gcry_cipher_setkey( hd->encrypt_hd, hd->kex.key_c->d,
                                     hd->kex.key_c->len );
        if( !rc )
            rc = gcry_cipher_setiv( hd->encrypt_hd, hd->kex.iv_a->d,
                                    hd->kex.iv_a->len );
        rc = map_gcry_rc( rc );
        if( !rc ) {
            hd->send_mac = gcry_md_open( hd->mac_algo, GCRY_MD_FLAG_HMAC );
            if( !hd->send_mac )
                rc = map_gcry_rc( gcry_errno() );
            if( !rc )
                rc = gcry_md_setkey( hd->send_mac, hd->kex.mac_e->d,
                                     hd->kex.mac_e->len );
        }
    }
    if( rc )
        return _gsti_log_rc( rc, "setup encryption keys failed\n" );
    return rc;
}

/****************
 * Process a received newkeys message and take the decryption keys in use
 */
int
kex_proc_newkeys( GSTIHD hd )
{
    int rc;

    if( hd->pkt.type != SSH_MSG_NEWKEYS )
        return GSTI_BUG;

    rc = construct_keys( hd );
    if( rc )
        return rc;

    hd->decrypt_hd = gcry_cipher_open( hd->ciph_algo, hd->ciph_mode, 0 );
    if( !hd->ciph_blksize )
        hd->ciph_blksize = gcry_cipher_get_algo_blklen( hd->ciph_algo );
    if( !hd->decrypt_hd )
        rc = map_gcry_rc( gcry_errno() );
    else if( hd->we_are_server ) {
        if( !rc )
            rc = gcry_cipher_setkey( hd->decrypt_hd, hd->kex.key_c->d,
                                     hd->kex.key_c->len );
        if( !rc )
            rc = gcry_cipher_setiv( hd->decrypt_hd, hd->kex.iv_a->d,
                                    hd->kex.iv_a->len );
        rc = map_gcry_rc( rc );
        if( !rc ) {
            hd->recv_mac = gcry_md_open( hd->mac_algo, GCRY_MD_FLAG_HMAC );
            if( !hd->recv_mac )
                rc = map_gcry_rc( gcry_errno() );
            if( !rc )
                rc = gcry_md_setkey( hd->recv_mac, hd->kex.mac_e->d,
                                     hd->kex.mac_e->len );
        }
    }
    else {
        if( !rc )
            rc = gcry_cipher_setkey( hd->decrypt_hd, hd->kex.key_d->d,
                                     hd->kex.key_d->len );
        if( !rc )
            rc = gcry_cipher_setiv( hd->decrypt_hd, hd->kex.iv_b->d,
                                    hd->kex.iv_b->len );
        rc = map_gcry_rc( rc );
        if( !rc ) {
            hd->recv_mac = gcry_md_open( hd->mac_algo, GCRY_MD_FLAG_HMAC );
            if( !hd->recv_mac )
                rc = map_gcry_rc( gcry_errno() );
            if( !rc )
                rc = gcry_md_setkey( hd->recv_mac, hd->kex.mac_f->d,
                                     hd->kex.mac_f->len );
        }
    }

    if( rc )
        return _gsti_log_rc( rc,"setup decryption keys failed\n" );
    return rc;
}


int
kex_send_disconnect( GSTIHD hd, u32 reason )
{
    struct packet_buffer_s *pkt = &hd->pkt;
    BUFFER buf = NULL;
    size_t len;
    int rc = 0;

    pkt->type = SSH_MSG_DISCONNECT;
    _gsti_buf_init( &buf );
    _gsti_buf_putc( buf, 0 );
    _gsti_buf_putint( buf, reason );
    _gsti_buf_putstr( buf, NULL, 4 );
    _gsti_buf_putstr( buf, NULL, 4 );

    len = _gsti_buf_getlen( buf );
    if( len > pkt->size ) {
        rc = GSTI_TOO_LARGE;
        goto leave;
    }
    memcpy( pkt->payload, _gsti_buf_getptr( buf ), len );

leave:
    _gsti_buf_free( buf );
    
    return rc;
}


/****************
 * Parse a SSH_MSG_SERVICE_{ACCEPT,REQUEST} and return the service name.
 * Returns: 0 on success or an errorcode.
 */
static int
parse_msg_service( BSTRING *svcname, const byte *msg, size_t msglen, int type )
{
    BUFFER buf = NULL;
    int rc;

    *svcname = NULL;
    if( msglen < (1+4) )
        return GSTI_TOO_SHORT;
    _gsti_buf_init( &buf );
    _gsti_buf_putraw( buf, msg, msglen );
    if( _gsti_buf_getc( buf ) != type ) {
        rc = GSTI_BUG;
        goto leave;
    }

    rc = _gsti_buf_getbstr( buf, svcname );
    if( rc )
        goto leave;
    
    /* make sure the msg length matches */
    msglen = _gsti_buf_getlen( buf );
    if( msglen ) {
        _gsti_log_info( "parse_msg_service: %lu bytes remaining\n",
                        (u32)msglen );
        rc = GSTI_INV_PKT;
    }
leave:
    _gsti_buf_free( buf );
    
    return rc;
}

/****************
 * Build a SERVICE_{Accept,REQUEST} packet.
 */
static int
build_msg_service( BSTRING svcname, struct packet_buffer_s *pkt, int type )
{
    BUFFER buf = NULL;
    size_t len;
    int rc = 0;

    assert( pkt->size > 100 );
    if( !svcname ) {
	_gsti_log_info( "build_msg_service: no service name\n" );
	return GSTI_BUG;
    }

    pkt->type = type;
    _gsti_buf_init( &buf );
    _gsti_buf_putc( buf, 0 );
    _gsti_buf_putbstr( buf, svcname );

    len = _gsti_buf_getlen( buf );
    if( len > pkt->size ) {
        rc = GSTI_TOO_LARGE;
        goto leave;
    }
    memcpy( pkt->payload, _gsti_buf_getptr( buf ), len );
    pkt->payload_len = len;

leave:
    _gsti_buf_free( buf );
    
    return rc;
}



int
kex_send_service_request( GSTIHD hd, const char *name )
{
    int rc;

    hd->service_name = _gsti_bstring_make( name, strlen( name ) );
    rc = build_msg_service( hd->service_name,
                            &hd->pkt, SSH_MSG_SERVICE_REQUEST );
    if( !rc )
	rc = _gsti_packet_write( hd );
    if( !rc )
	rc = _gsti_packet_flush( hd );
    if( rc ) {
	_gsti_free( hd->service_name );
	hd->service_name = NULL;
    }
    return rc;
}

int
kex_proc_service_request( GSTIHD hd )
{
    int rc;
    BSTRING svcname;

    if( hd->pkt.type != SSH_MSG_SERVICE_REQUEST )
        return GSTI_BUG;
    
    rc = parse_msg_service( &svcname, hd->pkt.payload, hd->pkt.payload_len,
                            SSH_MSG_SERVICE_REQUEST );
    if( rc )
        return rc;

    if( svcname->len < 12 || memcmp( svcname->d, "ssh-userauth", 12 ) )
        return kex_send_disconnect( hd, SSH_DISCONNECT_SERVICE_NOT_AVAILABLE );

    /* store the servicename, so that it can later be answered */
    if( hd->service_name )
        return _gsti_log_rc( GSTI_BUG, "a service is already in use\n" );

    hd->service_name = svcname;
    return rc;
}



int
kex_send_service_accept( GSTIHD hd )
{
    int rc;

    rc = build_msg_service( hd->service_name, &hd->pkt,
                            SSH_MSG_SERVICE_ACCEPT);
    if( !rc )
        rc = _gsti_packet_write( hd );
    if( !rc )
        rc = _gsti_packet_flush( hd );
    return rc;
}


int
kex_proc_service_accept( GSTIHD hd )
{
    int rc;
    BSTRING svcname;

    if( hd->pkt.type != SSH_MSG_SERVICE_ACCEPT )
        return GSTI_BUG;
    
    rc = parse_msg_service( &svcname, hd->pkt.payload, hd->pkt.payload_len,
                            SSH_MSG_SERVICE_ACCEPT );
    if( rc )
        return rc;

    if( !hd->service_name )
        return _gsti_log_rc( GSTI_BUG, "no service request sent\n" );
    rc = cmp_bstring( hd->service_name, svcname );
    _gsti_free( svcname );
    if( rc )
        return _gsti_log_rc( GSTI_PROT_VIOL,
                             "service name does not match requested one\n" );
    return 0;
}
