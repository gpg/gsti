/* packet.c - packet read/write
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
#include "buffer.h"

static u32
buftou32( const byte *buffer )
{
    u32 a;
    a =    *buffer << 24;
    a |= buffer[1] << 16;
    a |= buffer[2] <<  8;
    a |= buffer[3];
    return a;   
}


static void
print_disconnect_msg( const byte *msg, size_t msglen )
{
    BUFFER buf = NULL;
    BSTRING desc, lang;
    u32 reason;
    
    if( msglen < 13 ) {
	log_info( "SSH_MSG_DISCONNECT is not valid\n" );
	return;
    }
    _gsti_buf_init( &buf );
    _gsti_buf_putraw( buf, msg, msglen );
    if( _gsti_buf_getc( buf ) != SSH_MSG_DISCONNECT )
        goto leave;
    reason = _gsti_buf_getint( buf );
    log_info( "SSH_MSG_DISCONNECT: reason=%lu `", reason );

    if( _gsti_buf_getbstr( buf, &desc ) )
        goto leave;
    dump_bstring( stderr, "description:", desc );
    _gsti_bstring_free( desc );
    
    if( _gsti_buf_getbstr( buf, &lang ) )
        goto leave;
    dump_bstring( stderr, "language-tag:", lang );
    _gsti_bstring_free( lang );

leave:
    msglen = _gsti_buf_getlen( buf );
    _gsti_buf_free( buf );
    if( msglen )
	log_info( "print_msg_disconnect: %lu bytes remaining\n", (u32)msglen );
}

static void
print_debug_msg( const byte *msg, size_t msglen )
{
    BUFFER buf = NULL;
    BSTRING mesag, lang;
    int display;
    
    if( msglen < (1+1+4+4) ) {
	log_info( "SSH_MSG_DEBUG is not valid\n" );
	return;
    }
    _gsti_buf_init( &buf );
    _gsti_buf_putraw( buf, msg, msglen );
    if( _gsti_buf_getc( buf ) != SSH_MSG_DEBUG )
        goto leave;    

    display = _gsti_buf_getc( buf );
    log_info( "SSH_MSG_DEBUG:%s `", display? " (always display)":"" );

    if( _gsti_buf_getbstr( buf, &mesag ) )
        goto leave;
    dump_bstring( stderr, "message:", mesag );
    _gsti_bstring_free( mesag );

    if( _gsti_buf_getbstr( buf, &lang ) )
        goto leave;
    dump_bstring( stderr, "language:", lang );
    _gsti_bstring_free( lang );
    

leave:
    msglen = _gsti_buf_getlen( buf );
    if( msglen )
	log_info( "print_msg_debug: %lu bytes remaining\n", (u32)msglen );
}


void
_gsti_packet_init( GSTIHD hd )
{
    if( !hd->pkt.payload ) {
        hd->pkt.size = PKTBUFSIZE;
        hd->pkt.packet_buffer = _gsti_malloc( hd->pkt.size + 5 );
        hd->pkt.payload = hd->pkt.packet_buffer + 5;
    }
}

void
_gsti_packet_free( GSTIHD hd )
{
    if( hd && hd->pkt.packet_buffer ) {
        _gsti_free( hd->pkt.packet_buffer );
        hd->pkt.payload = NULL;
    }
}

/****************
 * Generate a HMAC for the current packet with the given sequence nr.
 */
static size_t
generate_mac( GSTIHD hd, u32 seqno )
{
    GCRY_MD_HD md;
    byte buf[4];
    byte *p = hd->pkt.packet_buffer;
    size_t n = 5 + hd->pkt.payload_len + hd->pkt.padding_len;
    size_t maclen = hd->mac_len;

    if( !hd->send_mac )
	return 0; /* no MAC requested */

    buf[0] = seqno >> 24;
    buf[1] = seqno >> 16;
    buf[2] = seqno >>  8;
    buf[3] = seqno;

    md = gcry_md_copy( hd->send_mac );
    gcry_md_write( md, buf, 4 );
    gcry_md_write( md, p, n );
    gcry_md_final( md );
    memcpy( p + n, gcry_md_read( md, 0 ), maclen );
    gcry_md_close( md );
    return maclen;
}

/****************
 * Verify a HMAC from the packet.
 */
static int
verify_mac( GSTIHD hd, u32 seqno )
{
    GCRY_MD_HD md;
    byte *p = hd->pkt.packet_buffer;
    size_t n = 5 + hd->pkt.payload_len + hd->pkt.padding_len;
    size_t maclen = hd->mac_len;
    int rc;
    byte buf[4];

    buf[0] = seqno >> 24;
    buf[1] = seqno >> 16;
    buf[2] = seqno >>  8;
    buf[3] = seqno;

    md = gcry_md_copy( hd->recv_mac );
    gcry_md_write( md, buf, 4 );
    gcry_md_write( md, p, n );
    gcry_md_final( md );
    rc = !memcmp( p + n, gcry_md_read( md, 0 ), maclen );
    gcry_md_close( md );
    return rc;
}


/****************
 * Read a new packet from the input and store it in the packet buffer
 * Decompression and decryption is handled too.
 */
int
_gsti_packet_read( GSTIHD hd )
{
    READ_STREAM rst = hd->read_stream;
    ulong pktlen;
    int rc;
    size_t blocksize, n, paylen, padlen, maclen;
    u32 seqno;

    blocksize = hd->ciph_blksize? hd->ciph_blksize : 8;
    maclen = hd->recv_mac? hd->mac_len : 0;
 again:
    seqno = hd->recv_seqno++;
    /* read the first block so we can decipher the packet length */
    rc = _gsti_stream_readn( rst, hd->pkt.packet_buffer, blocksize );
    if( rc )
	return debug_rc( rc, "error reading packet header" );

    if( hd->decrypt_hd ) {
	rc = gcry_cipher_decrypt( hd->decrypt_hd,
				  hd->pkt.packet_buffer, blocksize,
                                  NULL, 0 );
	if( rc )
	    return debug_rc( rc, "error decrypting first block" );
    }

    dump_hexbuf(stderr, "begin of packet: ", hd->pkt.packet_buffer, blocksize);

    pktlen = buftou32( hd->pkt.packet_buffer );
    /* FIXME: It should be 16 but NEWKEYS has 12 for some reason */
    if( pktlen < 12 ) /* minimum packet size as per secsh draft */
	return debug_rc( GSTI_TOO_SHORT, "received pktlen %lu", (u32)pktlen );
    if( pktlen > MAX_PKTLEN )
	return debug_rc( GSTI_TOO_LARGE, "received pktlen %lu", (u32)pktlen );

    padlen = hd->pkt.packet_buffer[4];
    if( padlen < 4 )
	return debug_rc(GSTI_TOO_SHORT, "received padding is %lu",(u32)padlen);

    hd->pkt.packet_len = pktlen;
    hd->pkt.padding_len = padlen;
    hd->pkt.payload_len = paylen = pktlen - padlen - 1;

    n = 5 + paylen + padlen;
    if( (n % blocksize) )
	debug_rc( GSTI_INV_PKT, "length packet is not a "
                  "multiple of the blocksize" );

    /* read the rest of the packet */
    n = 4 + pktlen + maclen;
    if( n >= blocksize )
	n -= blocksize;
    else
	n = 0; /* oops: rest of packet is too short */

#if 0
    log_info( "packet_len=%lu padding=%lu payload=%lu maclen=%lu n=%lu\n",
              (u32)hd->pkt.packet_len, (u32)hd->pkt.padding_len,
              (u32)hd->pkt.payload_len, (u32)maclen, (u32)n );
#endif

    rc = _gsti_stream_readn( rst, hd->pkt.packet_buffer+blocksize, n );
    if( rc )
	return debug_rc( rc,"error reading rest of packet" );
    n -= maclen; /* don't want the maclen anymore */
    if( hd->decrypt_hd ) {
	rc = gcry_cipher_decrypt( hd->decrypt_hd,
				  hd->pkt.packet_buffer+blocksize, n,
                                  NULL, 0 );
	if( rc )
	    return debug_rc( rc,"decrypt failed" );
	/* note: there is no reason to decrypt the padding, but we do
	 * it anyway becuase this is easier
         */
        dump_hexbuf( stderr, "rest of  packet: ",
                     hd->pkt.packet_buffer+blocksize, n );
    }

    if( hd->recv_mac && !verify_mac( hd, seqno ) )
	return debug_rc( GSTI_INV_MAC, "wrong MAC" );

    /* todo: uncompress if needed */

    hd->pkt.type = *hd->pkt.payload;
    log_info( "received packet %lu of type %d\n", (u32)seqno, hd->pkt.type );

    if( hd->pkt.type == SSH_MSG_IGNORE )
	goto again;

    if( hd->pkt.type == SSH_MSG_DEBUG )
	print_debug_msg( hd->pkt.payload, hd->pkt.payload_len );
    if( hd->pkt.type == SSH_MSG_DISCONNECT )
	print_disconnect_msg( hd->pkt.payload, hd->pkt.payload_len );

    return 0;
}



/****************
 * write a new packet from the packet buffer
 * Compression and encryption is handled here.
 * FIXME: make sure that the padding does not cause a buffer overflow!!!
 */
int
_gsti_packet_write( GSTIHD hd )
{
    WRITE_STREAM wst = hd->write_stream;
    int rc;
    int blocksize = 0;
    size_t n, padlen, paylen, maclen;
    u32 seqno = hd->send_seqno++;

    blocksize = hd->ciph_blksize? hd->ciph_blksize : 8;
    hd->pkt.padding_len = blocksize - ((4 + 1 + hd->pkt.payload_len)
                                       % blocksize );
    if( hd->pkt.padding_len < 4 )
	hd->pkt.padding_len += blocksize;

    if( hd->pkt.type == 0 )
        return GSTI_INV_PKT; /* make sure the type is set */
    hd->pkt.payload[0] = hd->pkt.type;
    hd->pkt.packet_len = 1 + hd->pkt.payload_len + hd->pkt.padding_len;

    log_info( "sending packet %lu of type %d\n", (u32)seqno, hd->pkt.type );

    /* fixme: compress if needed */

    /* construct header.  This must be a complete block, so
     * the the encrypt function can handle it */
    n = hd->pkt.packet_len;
    hd->pkt.packet_buffer[0] = n >> 24;
    hd->pkt.packet_buffer[1] = n >> 16;
    hd->pkt.packet_buffer[2] = n >>  8;
    hd->pkt.packet_buffer[3] = n;
    hd->pkt.packet_buffer[4] = hd->pkt.padding_len;
    paylen = hd->pkt.payload_len;
    padlen = hd->pkt.padding_len;
    gcry_randomize( hd->pkt.payload + paylen, padlen, GCRY_WEAK_RANDOM );

    maclen = generate_mac( hd, seqno );

    /* write the payload */
    n = 5 + paylen + padlen;
    assert( !(n % blocksize) );
    if( hd->encrypt_hd ) {
	rc = gcry_cipher_encrypt( hd->encrypt_hd,
				  hd->pkt.packet_buffer, n, NULL, 0 );
	if( rc )
	    return rc;
    }
    n = 5 + paylen + padlen + maclen;
    rc = _gsti_stream_writen( wst, hd->pkt.packet_buffer, n );
    if( rc )
	return rc;

    return 0;
}

int
_gsti_packet_flush( GSTIHD hd )
{
    WRITE_STREAM wst = hd->write_stream;
    int rc;

    rc = _gsti_stream_flush( wst );
    if( rc )
	return GSTI_WRITE_ERROR;
    return 0;
}

