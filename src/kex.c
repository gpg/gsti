/* kex.c  -  connect, key exchange and service request
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
#include <assert.h>

#include "api.h"
#include "memory.h"
#include "stream.h"
#include "packet.h"
#include "utils.h"
#include "kex.h"


static const char host_version_string[] =
	"SSH-2.0-GSTI_0.0 Gnu Transport Library";

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


int
kex_send_version( GSTIHD hd )
{
    WRITE_STREAM wst = hd->write_stream;

    if( stream_writen( wst, host_version_string, strlen(host_version_string) ))
	return GSTI_WRITE_ERROR;
    if( stream_writen( wst, "\r\n", 2 ))
	return GSTI_WRITE_ERROR;
    if( stream_flush( wst ) )
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
    int c;
    int any = 0;
    int pos = 0;
    READ_STREAM rst = hd->read_stream;
    char version[300];

    /* wait for the initial 4 bytes */
    while( (c=stream_get(rst)) != -1 ) {
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
	if( (c=stream_get(rst)) == -1 || c == '\n' )
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
    gsti_free( hd->peer_version_string );
    hd->peer_version_string = make_bstring( version, strlen(version) );

    return 0;
}




static void
free_msg_kexinit( MSG_kexinit *kex )
{
    free_strlist(kex->kex_algorithm);
    free_strlist(kex->server_host_key_algorithms);
    free_strlist(kex->encryption_algorithms_client_to_server);
    free_strlist(kex->encryption_algorithms_server_to_client);
    free_strlist(kex->mac_algorithms_client_to_server);
    free_strlist(kex->mac_algorithms_server_to_client);
    free_strlist(kex->compression_algorithms_client_to_server);
    free_strlist(kex->compression_algorithms_server_to_client);
}


/****************
 * Parse a SSH_MSG_KEXINIT and return the parsed information in
 * a newly allocated struture.
 * Rteurns: 0 on success or an errorcode.
 */
static int
parse_msg_kexinit( MSG_kexinit *kex, const byte *msg, size_t msglen )
{
    int i, rc = 0;
    STRLIST algolist[10] = { NULL };

    memset( kex, 0, sizeof *kex );
    if( msglen < (1+16+10*4+1+4) )
	return GSTI_TOO_SHORT;
    if( *msg != SSH_MSG_KEXINIT )
	return GSTI_BUG;
    msg++; msglen--;
    /* get the cookie */
    memcpy( kex->cookie, msg, 16 ); msg += 16; msglen -= 16;

    /* get 10 strings */
    for(i=0; i < 10; i++ ) {
	ulong len;

	if( msglen < 4 ) {
	    rc = GSTI_TOO_SHORT;
	    goto leave;
	}
	len = buftou32( msg ); msg += 4; msglen -= 4;
	if( len > msglen ) {
	    rc = GSTI_TOO_LARGE;
	    goto leave;
	}
	algolist[i] = parse_algorithm_list( msg, len );
	msg += len; msglen -= len;
    }
    kex->kex_algorithm				 = algolist[0];
    kex->server_host_key_algorithms		 = algolist[1];
    kex->encryption_algorithms_client_to_server  = algolist[2];
    kex->encryption_algorithms_server_to_client  = algolist[3];
    kex->mac_algorithms_client_to_server	 = algolist[4];
    kex->mac_algorithms_server_to_client	 = algolist[5];
    kex->compression_algorithms_client_to_server = algolist[6];
    kex->compression_algorithms_server_to_client = algolist[7];
    /* (we don't need the two language lists) */

    kex->first_kex_packet_follows = *msg;
    msg++; msglen--;

    /* make sure that the reserved value is zero */
    if( buftou32( msg ) ) {
	rc = GSTI_INV_PKT;
	goto leave;
    }
    msg += 4; msglen -= 4;

    /* make sure the msg length matches */
    if( msglen )
	rc = GSTI_INV_PKT;

  leave:
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
    size_t length = pkt->size;
    int i;

    assert( length > 100 );

    pkt->type = SSH_MSG_KEXINIT;
    p++; length--;
    memcpy( p, kex->cookie, 16 );
    p += 16; length -= 16;
    /* put 10 strings */
    algolist[0] = kex->kex_algorithm			      ;
    algolist[1] = kex->server_host_key_algorithms	      ;
    algolist[2] = kex->encryption_algorithms_client_to_server ;
    algolist[3] = kex->encryption_algorithms_server_to_client ;
    algolist[4] = kex->mac_algorithms_client_to_server	      ;
    algolist[5] = kex->mac_algorithms_server_to_client	      ;
    algolist[6] = kex->compression_algorithms_client_to_server;
    algolist[7] = kex->compression_algorithms_server_to_client;
    algolist[8] = NULL;
    algolist[9] = NULL;
    for(i=0; i < 10; i++ ) {
	size_t n;

	n = build_algorithm_list( p, length, algolist[i] );
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
    fprintf(stderr, "MSG_kexinit:\n" );
    dump_hexbuf( stderr, "cookie: ", kex->cookie, 16 );
    dump_strlist( stderr, "kex_algorithm", kex->kex_algorithm );
    dump_strlist( stderr, "server_host_key_algorithms",              kex->server_host_key_algorithms );
    dump_strlist( stderr, "encryption_algorithms_client_to_server",  kex->encryption_algorithms_client_to_server );
    dump_strlist( stderr, "encryption_algorithms_server_to_client",  kex->encryption_algorithms_server_to_client );
    dump_strlist( stderr, "mac_algorithms_client_to_server",         kex->mac_algorithms_client_to_server );
    dump_strlist( stderr, "mac_algorithms_server_to_client",         kex->mac_algorithms_server_to_client );
    dump_strlist( stderr, "compression_algorithms_client_to_server", kex->compression_algorithms_client_to_server );
    dump_strlist( stderr, "compression_algorithms_server_to_client", kex->compression_algorithms_server_to_client );
    if( kex->first_kex_packet_follows )
	fputs("fist_kex_packet_follows\n", stderr );
    putc('\n', stderr );
}



/****************
 * Parse a SSH_MSG_KEXDH_INIT and return the parsed information in
 * a newly allocated struture.
 * Rteurns: 0 on success or an errorcode.
 */
static int
parse_msg_kexdh_init( MSG_kexdh_init *kexdh, const byte *msg, size_t msglen )
{
    size_t n;
    int rc = 0;

    memset( kexdh, 0, sizeof *kexdh );
    if( msglen < (1+4) )
	return GSTI_TOO_SHORT;
    if( *msg != SSH_MSG_KEXDH_INIT )
	return GSTI_BUG;
    msg++; msglen--;
    n = msglen;
    rc = gcry_mpi_scan( &kexdh->e , GCRYMPI_FMT_SSH, msg, &n );
    if( rc )
	return map_gcry_rc(rc);
    msg += n; msglen -= n;

    /* make sure the msg length matches */
    if( msglen )
	rc = GSTI_INV_PKT;

    return rc;
}

/****************
 * Build a KEXDH packet.
 */
static int
build_msg_kexdh_init( MSG_kexdh_init *kexdh, struct packet_buffer_s *pkt )
{
    int rc;
    size_t n;

    assert( pkt->size > 100 );

    pkt->type = SSH_MSG_KEXDH_INIT;
    n = pkt->size-1;
    rc = gcry_mpi_print( GCRYMPI_FMT_SSH, pkt->payload+1, &n, kexdh->e );
    if( rc )
	return map_gcry_rc(rc);
    pkt->payload_len = 1+n;

    return 0;
}


static void
dump_msg_kexdh_init( MSG_kexdh_init *kexdh )
{
    fprintf(stderr, "MSG_kexdh_init:\n" );
    dump_mpi( stderr, "e=", kexdh->e );
    putc('\n', stderr );
}




/****************
 * Parse a SSH_MSG_KEXDH_REPLY and return the parsed information in
 * a newly allocated struture.
 * Rteurns: 0 on success or an errorcode.
 */
static int
parse_msg_kexdh_reply( MSG_kexdh_reply *dhr, const byte *msg, size_t msglen )
{
    size_t n;
    int rc = 0;

    memset( dhr, 0, sizeof *dhr );
    if( msglen < (1+4+4+4) )
	return GSTI_TOO_SHORT;
    if( *msg != SSH_MSG_KEXDH_REPLY )
	return GSTI_BUG;
    msg++; msglen--;

    n = msglen;
    dhr->k_s = parse_bstring( msg, &n );
    if( !dhr->k_s )
	return GSTI_TOO_SHORT;
    msg += n; msglen -= n;

    n = msglen;
    rc = gcry_mpi_scan( &dhr->f , GCRYMPI_FMT_SSH, msg, &n );
    if( rc )
	return map_gcry_rc(rc);
    msg += n; msglen -= n;

    n = msglen;
    dhr->sig_h = parse_bstring( msg, &n );
    if( !dhr->sig_h )
	return GSTI_TOO_SHORT;
    msg += n; msglen -= n;

    /* make sure the msg length matches */
    if( msglen ) {
	fprintf(stderr, "parse_msg_kexdh_reply: hmmm, %lu bytes remaining\n",
			  (ulong)msglen );
	/*rc = GSTI_INV_PKT;*/
    }
    return rc;
}

/****************
 * Build a KEXDH_REPLY packet.
 */
static int
build_msg_kexdh_reply( MSG_kexdh_reply *dhr, struct packet_buffer_s *pkt )
{
    int rc;
    size_t n;
    byte *p = pkt->payload;
    size_t length = pkt->size;

    assert( pkt->size > 100 );

    pkt->type = SSH_MSG_KEXDH_REPLY;
    p++; pkt->payload_len = 1;

    n = build_bstring( p, length, dhr->k_s );
    if( !n )
	return GSTI_TOO_SHORT; /* provided buffer is too short */
    p += n; length -= n; pkt->payload_len += n;

    n = length;
    rc = gcry_mpi_print( GCRYMPI_FMT_SSH, p, &n, dhr->f );
    if( rc )
	return map_gcry_rc(rc);
    p += n; length -= n; pkt->payload_len += n;

    n = build_bstring( p, length, dhr->sig_h );
    if( !n )
	return GSTI_TOO_SHORT; /* provided buffer is too short */
    p += n; length -= n; pkt->payload_len += n;

    return 0;
}


static void
dump_msg_kexdh_reply( MSG_kexdh_reply *dhr )
{
    fprintf(stderr, "MSG_kexdh_reply:\n" );
    dump_bstring( stderr, "k_s=", dhr->k_s );
    dump_mpi( stderr, "f=", dhr->f );
    dump_bstring( stderr, "sig_h=", dhr->sig_h );
    putc('\n', stderr );
}


/****************
 * Choose a random value x and calculate e = g^x mod p.
 * Return: e and if ret_x is not NULL x.
 */
static MPI
calc_dh_secret( MPI *ret_x )
{
    MPI e, g, x, prime;
    size_t n = sizeof diffie_hellman_group1_prime;

    if( gcry_mpi_scan( &prime, GCRYMPI_FMT_STD,
		       diffie_hellman_group1_prime, &n ) )
	abort();
    /*dump_mpi(stderr, "prime=", prime );*/

    g = mpi_set_ui( NULL, 2 );
    x = mpi_new( 200 );  /* FIXME: allocate in secure memory */
    gcry_mpi_randomize( x, 200, GCRY_STRONG_RANDOM );
    /* fixme: set high bit of x and select a larger one */

    e = mpi_new(1024);
    mpi_powm( e, g, x, prime );

    if( ret_x )
	*ret_x = x;
    else
	mpi_release(x);
    mpi_release(g);
    mpi_release(prime);
    return e;
}



static void
hash_mpi( GCRY_MD_HD md, MPI a )
{
    char buf[400];
    size_t n = sizeof buf;

    if( gcry_mpi_print( GCRYMPI_FMT_SSH, buf, &n, a ) )
	fprintf(stderr,"Oops: MPI too large for hashing\n");
    else
	gcry_md_write( md, buf, n );
}


static void
hash_bstring( GCRY_MD_HD md, BSTRING a )
{
    byte buf[4];
    size_t n = a->len;

    buf[0] = n >> 24;
    buf[1] = n >> 16;
    buf[2] = n >>  8;
    buf[3] = n;
    gcry_md_write( md, buf, 4 );
    gcry_md_write( md, a->d, n );
}



static MPI
calc_dh_key( MPI f, MPI x )
{
    MPI k, prime;
    size_t n = sizeof diffie_hellman_group1_prime;

    if( gcry_mpi_scan( &prime, GCRYMPI_FMT_STD,
		       diffie_hellman_group1_prime, &n ) )
	abort();

    k = mpi_new( 1024 );  /* FIXME: allocate in secure memory */
    mpi_powm( k, f, x, prime );
    mpi_release(prime);
    return k;
}




/****************
 * calculate the exchange hash value and put it into the handle.
 */
static int
calc_exchange_hash( GSTIHD hd, BSTRING i_c, BSTRING i_s,
			       BSTRING k_s, MPI e,  MPI f )
{
    GCRY_MD_HD md;
    int algo = GCRY_MD_SHA1;

    md = gcry_md_open( algo, 0 );
    if( !md )
	return map_gcry_rc( gcry_errno() );

    if( hd->we_are_server ) {
	BSTRING pp;
	hash_bstring( md, hd->peer_version_string );
	pp = make_bstring( host_version_string, strlen(host_version_string) );
	hash_bstring( md, pp );
	gsti_free(pp);
    }
    else {
	BSTRING pp;
	pp = make_bstring( host_version_string, strlen(host_version_string) );
	hash_bstring( md, pp );
	gsti_free(pp);
	hash_bstring( md, hd->peer_version_string );
    }
    hash_bstring( md, i_c );
    hash_bstring( md, i_s );
    hash_bstring( md, k_s );
    hash_mpi( md, e );
    hash_mpi( md, f );
    hash_mpi( md, hd->kex.k );

    hd->kex.h = make_bstring( gcry_md_read( md, algo ),
			      gcry_md_get_algo_dlen(algo) );
    if( !hd->session_id ) /* initialize the session id the first time */
	hd->session_id = make_bstring( gcry_md_read( md, algo ),
				       gcry_md_get_algo_dlen(algo));
    gcry_md_close( md );
/*  dump_hexbuf( stderr, "SesID=", hd->session_id->d, hd->session_id->len );*/
    return 0;
}


/* Hmm. We need to have a new_kex structure so that the old
 * kex data can be used untip we have send the NEWKEYs msg
 * Well, doesn't matter for now.
 */
static BSTRING
construct_one_key( GSTIHD hd, GCRY_MD_HD md1, int algo,
		   const byte *letter, size_t size )
{
    BSTRING hash;
    GCRY_MD_HD md = gcry_md_copy( md1 );
    size_t n, n1;

    hash = make_bstring( NULL, size );
    gcry_md_write( md, letter, 1 );
    gcry_md_write( md, hd->session_id->d, hd->session_id->len );
    n = gcry_md_get_algo_dlen(algo);
    if( n > size )
	n = size;
    memcpy( hash->d, gcry_md_read(md, algo), n );
    while( n < size ) {
	gcry_md_close( md );
	md = gcry_md_copy( md1 );
	gcry_md_write( md, hash->d, n );
	n1 = gcry_md_get_algo_dlen(algo);
	if( n1 > size-n )
	    n1 = size-n;
	memcpy( hash->d+n, gcry_md_read(md, algo), n1 );
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

    if( hd->kex.key_a )
	return 0;   /* already constructed */

    md = gcry_md_open( algo, 0 );
    if( !md )
	return map_gcry_rc( gcry_errno() );

    hash_mpi( md, hd->kex.k );
    gcry_md_write( md, hd->kex.h->d, hd->kex.h->len );

    hd->kex.key_a = construct_one_key( hd, md, algo, "\x41", 8 );
    hd->kex.key_b = construct_one_key( hd, md, algo, "\x42", 8 );
    hd->kex.key_c = construct_one_key( hd, md, algo, "\x43", 24 ); /* des*/
    hd->kex.key_d = construct_one_key( hd, md, algo, "\x44", 24 );
    hd->kex.key_e = construct_one_key( hd, md, algo, "\x45", 20 );
    hd->kex.key_f = construct_one_key( hd, md, algo, "\x46", 20 );
    gcry_md_close( md );
  #if 0
    dump_hexbuf( stderr, "key A=", hd->kex.key_a->d, hd->kex.key_a->len );
    dump_hexbuf( stderr, "key B=", hd->kex.key_b->d, hd->kex.key_b->len );
    dump_hexbuf( stderr, "key C=", hd->kex.key_c->d, hd->kex.key_c->len );
    dump_hexbuf( stderr, "key D=", hd->kex.key_d->d, hd->kex.key_d->len );
    dump_hexbuf( stderr, "key E=", hd->kex.key_e->d, hd->kex.key_e->len );
    dump_hexbuf( stderr, "key F=", hd->kex.key_f->d, hd->kex.key_f->len );
  #endif
    return 0;
}



/****************
 * Prepare a HMAC
 */
static int
prepare_mac( GCRY_MD_HD *rmd, int algo, BSTRING key )
{
    int rc;

    *rmd = gcry_md_open( algo, GCRY_MD_FLAG_HMAC );
    if ( !*rmd )
        return map_gcry_rc( gcry_errno() );
    rc = gcry_md_setkey( *rmd, key->d, key->len );
    if ( rc ) {
        gcry_md_close( *rmd );  *rmd = NULL;
        return map_gcry_rc( rc );
    }
    return 0;
}


/* fixme: must release some data in case of error or when at end */
int
kex_send_init_packet( GSTIHD hd )
{
    MSG_kexinit kex;
    int rc=0;

    /* first send our kexinit packet */
    memset( &kex, 0, sizeof kex );
    memset( kex.cookie, 'w', 16 ); /* fixme: send a random one */
    kex.kex_algorithm = insert_strlist( NULL, "diffie-hellman-group1-sha1" );
    kex.server_host_key_algorithms = insert_strlist( NULL, "ssh-dss");
    kex.encryption_algorithms_client_to_server = insert_strlist( NULL, "3des-cbc");
    kex.encryption_algorithms_server_to_client = insert_strlist( NULL, "3des-cbc");
    kex.mac_algorithms_client_to_server = insert_strlist( NULL, "hmac-sha1");
    kex.mac_algorithms_server_to_client = insert_strlist( NULL, "hmac-sha1");
    kex.compression_algorithms_client_to_server = insert_strlist( NULL, "none");
    kex.compression_algorithms_server_to_client = insert_strlist( NULL, "none");
    rc = build_msg_kexinit( &kex, &hd->pkt );
    if( rc )
	return rc;
    rc = write_packet( hd );
    if( rc )
	return rc;
    /* must do it here because write_packet fills in the packet type */
    hd->host_kexinit_data = make_bstring( hd->pkt.payload, hd->pkt.payload_len );
    rc = flush_packet( hd );
    return rc;
}


/****************
 * Process a received keyinit packet.
 */
int
kex_proc_init_packet( GSTIHD hd )
{
    MSG_kexinit kex;
    int rc;

    if( hd->pkt.type != SSH_MSG_KEXINIT )
	return GSTI_BUG;  /* oops */
    rc = parse_msg_kexinit( &kex, hd->pkt.payload, hd->pkt.payload_len );
    if( rc )
	return rc;
    /* make a copy of the received payload which we will need later */
    hd->peer_kexinit_data = make_bstring( hd->pkt.payload,
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
    int rc=0;

    memset( &kexdh, 0, sizeof kexdh );
    /* FIXME: move secret_x it to secure memory */
    kexdh.e = hd->kexdh_e = calc_dh_secret( &hd->secret_x );
    rc = build_msg_kexdh_init( &kexdh, &hd->pkt );
    if( rc )
	return rc;
    rc = write_packet( hd );
    if( rc )
	return rc;
    rc = flush_packet( hd );
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
	return GSTI_BUG; /* oops */

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
    MPI y;

    memset( &dhr, 0, sizeof dhr );
    dhr.k_s = make_bstring( "servers-pk", 10 ); /* fixme: Get from a DB */

    /* generate our secret and the public value for it */
    dhr.f = calc_dh_secret( &y );
    /* now we can calculate the shared secret */
    hd->kex.k = calc_dh_key( hd->kexdh_e, y );
    mpi_release( y );
    /* and the hash */
    rc = calc_exchange_hash( hd, hd->host_kexinit_data, hd->peer_kexinit_data,
						 dhr.k_s, hd->kexdh_e, dhr.f );
    mpi_release( hd->kexdh_e );
    if( rc )
	return rc;
    dhr.sig_h = make_bstring("signature_of_H", 14 );  /*FIXME*/

    rc = build_msg_kexdh_reply( &dhr, &hd->pkt );
    if( !rc )
	dump_msg_kexdh_reply( &dhr );
    if( !rc )
	rc = write_packet( hd );
    if( !rc )
	rc = flush_packet( hd );
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
	return GSTI_BUG; /* oops */

    rc = parse_msg_kexdh_reply( &dhr, hd->pkt.payload, hd->pkt.payload_len );
    if( rc )
	return rc;

    dump_msg_kexdh_reply( &dhr );

    hd->kex.k = calc_dh_key( dhr.f, hd->secret_x );
    mpi_release( hd->secret_x );

    rc = calc_exchange_hash( hd, hd->host_kexinit_data, hd->peer_kexinit_data,
						 dhr.k_s, hd->kexdh_e, dhr.f );
    mpi_release( hd->kexdh_e );
    if( rc )
	return rc;

    /* FIXME: check that this is the real host */

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
    rc = write_packet( hd );
    if( !rc )
	rc = flush_packet( hd );
    if( rc )
	return rc;

    /* now we have to take the encryption keys into use */
    hd->encrypt_hd = gcry_cipher_open( GCRY_CIPHER_3DES,
				       GCRY_CIPHER_MODE_CBC, 0 );
    if( !hd->encrypt_hd )
	rc = map_gcry_rc( gcry_errno() );
    else if( hd->we_are_server ) {
	if( !rc )
	    rc = gcry_cipher_setkey( hd->encrypt_hd, hd->kex.key_d->d,
						     hd->kex.key_d->len );
	if( !rc )
	    rc = gcry_cipher_setiv( hd->encrypt_hd, hd->kex.key_b->d,
						    hd->kex.key_b->len );
	rc = map_gcry_rc(rc);
	if( !rc )
	    rc = prepare_mac( &hd->send_mac_hd, GCRY_MD_SHA1, hd->kex.key_f );
    }
    else {
	if( !rc )
	    rc = gcry_cipher_setkey( hd->encrypt_hd, hd->kex.key_c->d,
						     hd->kex.key_c->len );
	if( !rc )
	    rc = gcry_cipher_setiv( hd->encrypt_hd, hd->kex.key_a->d,
						    hd->kex.key_a->len );
	rc = map_gcry_rc(rc);
	if( !rc )
	    rc = prepare_mac( &hd->send_mac_hd, GCRY_MD_SHA1, hd->kex.key_e );
    }
    if( rc )
	return debug_rc(rc,"setup encryption keys failed");
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
	return GSTI_BUG; /* ooops */

    rc = construct_keys( hd );
    if( rc )
	return rc;

    hd->decrypt_hd = gcry_cipher_open( GCRY_CIPHER_3DES,
				       GCRY_CIPHER_MODE_CBC, 0 );
    if( !hd->encrypt_hd )
	rc = map_gcry_rc( gcry_errno() );
    else if( hd->we_are_server ) {
	if( !rc )
	    rc = gcry_cipher_setkey( hd->decrypt_hd, hd->kex.key_c->d,
						    hd->kex.key_c->len );
	if( !rc )
	    rc = gcry_cipher_setiv( hd->decrypt_hd, hd->kex.key_a->d,
						    hd->kex.key_a->len );
	rc = map_gcry_rc(rc);
	if( !rc )
	    rc = prepare_mac( &hd->recv_mac_hd, GCRY_MD_SHA1, hd->kex.key_e );
    }
    else {
	if( !rc )
	    rc = gcry_cipher_setkey( hd->decrypt_hd, hd->kex.key_d->d,
						    hd->kex.key_d->len );
	if( !rc )
	    rc = gcry_cipher_setiv( hd->decrypt_hd, hd->kex.key_b->d,
						    hd->kex.key_b->len );
	rc = map_gcry_rc(rc);
	if( !rc )
	    rc = prepare_mac( &hd->recv_mac_hd, GCRY_MD_SHA1, hd->kex.key_f );
    }

    if( rc )
	return debug_rc(rc,"setup decryption keys failed");
    return rc;
}



/****************
 * Parse a SSH_MSG_SERVICE_{ACCEPT,REQUEST} and return the service name.
 * Returns: 0 on success or an errorcode.
 */
static int
parse_msg_service( BSTRING *svcname, const byte *msg, size_t msglen, int type )
{
    size_t n;
    int rc = 0;

    *svcname = NULL;
    if( msglen < (1+4) )
	return GSTI_TOO_SHORT;
    if( *msg != type )
	return GSTI_BUG;
    msg++; msglen--;

    n = msglen;
    *svcname = parse_bstring( msg, &n );
    if( !*svcname )
	return GSTI_TOO_SHORT;
    msg += n; msglen -= n;

    /* make sure the msg length matches */
    if( msglen ) {
	fprintf(stderr,"parse_msg_service: hmmm, %lu bytes remaining\n",
			  (ulong)msglen );
    }
    return rc;
}

/****************
 * Build a SERVICE_{Accept,REQUEST} packet.
 */
static int
build_msg_service( BSTRING svcname, struct packet_buffer_s *pkt, int type )
{
    size_t n;
    byte *p = pkt->payload;
    size_t length = pkt->size;

    assert( pkt->size > 100 );
    if( !svcname ) {
	fprintf(stderr,"build_msg_service: no service name\n");
	return GSTI_BUG;
    }

    pkt->type = type;
    p++; pkt->payload_len = 1;

    n = build_bstring( p, length, svcname );
    if( !n )
	return GSTI_TOO_SHORT; /* provided buffer is too short */
    p += n; length -= n; pkt->payload_len += n;
    return 0;
}



int
kex_send_service_request( GSTIHD hd, const char *name )
{
    int rc;

    hd->service_name = make_bstring( name, strlen(name) );
    rc = build_msg_service( hd->service_name, &hd->pkt,SSH_MSG_SERVICE_REQUEST);
    if( !rc )
	rc = write_packet( hd );
    if( !rc )
	rc = flush_packet( hd );

    if( rc ) {
	gsti_free( hd->service_name );
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
	return GSTI_BUG;  /* oops */
    rc = parse_msg_service( &svcname, hd->pkt.payload, hd->pkt.payload_len,
						    SSH_MSG_SERVICE_REQUEST );
    if( rc )
	return rc;

    /* FIXME: here we should whether we provide this service */

    /* store the servicename, so that it can later be answered */
    if( hd->service_name )
	return debug_rc( GSTI_BUG, "a service is already in use");

    hd->service_name = svcname;
    return rc;
}



int
kex_send_service_accept( GSTIHD hd )
{
    int rc;

    rc = build_msg_service( hd->service_name, &hd->pkt, SSH_MSG_SERVICE_ACCEPT);
    if( !rc )
	rc = write_packet( hd );
    if( !rc )
	rc = flush_packet( hd );
    return rc;
}

int
kex_proc_service_accept( GSTIHD hd )
{
    int rc;
    BSTRING svcname;

    if( hd->pkt.type != SSH_MSG_SERVICE_ACCEPT )
	return GSTI_BUG;  /* oops */
    rc = parse_msg_service( &svcname, hd->pkt.payload, hd->pkt.payload_len,
						    SSH_MSG_SERVICE_ACCEPT );
    if( rc )
	return rc;

    if( !hd->service_name )
	return debug_rc( GSTI_BUG, "no service request sent");
    rc = cmp_bstring( hd->service_name, svcname );
    gsti_free( svcname );
    if( rc )
	return debug_rc( GSTI_PROT_VIOL,
			 "service name does not match requested one" );
    return 0;
}

