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

#define MAX_PKTLEN 40000  /* sanity limit */
#define PKTBUFSIZE 50000  /* somewhat large size of a packet buffer */



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


static void
print_disconnect_msg( const char *msg, size_t msglen )
{
    size_t n;
    if( msglen < 13 ) {
	fprintf(stderr, "SSH_MSG_DISCONNECT is not valid\n" );
	return;
    }
    msg++; msglen--;
    fprintf(stderr, "SSH_MSG_DISCONNECT: reason=%lu `", buftou32(msg) );
    msg += 4; msglen -= 4;
    n = dump_bstring_msg( stderr, NULL, msg, msglen );
    msg += n; msglen -= n;
    fputs("' [", stderr );
    n = dump_bstring_msg( stderr, NULL, msg, msglen );
    msg += n; msglen -= n;
    fputs("]\n", stderr );
    if( msglen ) {
	fprintf(stderr, "print_msg_disconnect: hmmm, %lu bytes remaining\n",
			  (ulong)msglen );
    }
}

static void
print_debug_msg( const char *msg, size_t msglen )
{
    size_t n;
    if( msglen < (1+1+4+4) ) {
	fprintf(stderr, "SSH_MSG_DEBUG is not valid\n" );
	return;
    }
    msg++; msglen--;
    fprintf(stderr, "SSH_MSG_DEBUG:%s `", *msg? " (always display)":"" );
    msg++; msglen--;
    n = dump_bstring_msg( stderr, NULL, msg, msglen ); /* message */
    msg += n; msglen -= n;
    fputs("' [", stderr );
    n = dump_bstring_msg( stderr, NULL, msg, msglen ); /* language */
    msg += n; msglen -= n;
    fputs("]\n", stderr );
    if( msglen ) {
	fprintf(stderr, "print_msg_debug: hmmm, %lu bytes remaining\n",
			  (ulong)msglen );
    }
}


void
init_packet( GSTIHD hd )
{
    if( !hd->pkt.payload ) {
	hd->pkt.packet_buffer = gsti_malloc( (hd->pkt.size = PKTBUFSIZE)+5 );
	hd->pkt.payload = hd->pkt.packet_buffer + 5;
    }
}


/****************
 * 
 */
static size_t
generate_mac( GSTIHD hd, u32 seqno )
{
    char *p = hd->pkt.packet_buffer;
    size_t n = 5 + hd->pkt.payload_len + hd->pkt.padding_len;
    GCRY_MD_HD md;
    size_t maclen;
    byte buf[4];

    if( !hd->send_mac_hd )
	return 0; /* no MAC requested */

    buf[0] = seqno >> 24;
    buf[1] = seqno >> 16;
    buf[2] = seqno >>  8;
    buf[3] = seqno;

    md = gcry_md_copy( hd->send_mac_hd );
    gcry_md_write( md, buf, 4 );
    gcry_md_write( md, p, n );
    maclen = gcry_md_get_algo_dlen(gcry_md_get_algo(md));
    memcpy(p+n, gcry_md_read(md,0), maclen );
    gcry_md_close(md);
    return maclen;
}

/****************
 * 
 */
static int
verify_mac( GSTIHD hd, u32 seqno )
{
    char *p = hd->pkt.packet_buffer;
    size_t n = 5 + hd->pkt.payload_len + hd->pkt.padding_len;
    GCRY_MD_HD md;
    size_t maclen;
    int rc;
    byte buf[4];

    buf[0] = seqno >> 24;
    buf[1] = seqno >> 16;
    buf[2] = seqno >>  8;
    buf[3] = seqno;

    md = gcry_md_copy( hd->recv_mac_hd );
    gcry_md_write( md, buf, 4 );
    gcry_md_write( md, p, n );
    maclen = gcry_md_get_algo_dlen(gcry_md_get_algo(md));
    rc = !memcmp(p+n, gcry_md_read(md,0), maclen );
    gcry_md_close(md);
    return rc;
}


/****************
 * Read a new packet from the input and store it in the packet buffer
 * Decompression and decryption is handled too.
 */
int
read_packet( GSTIHD hd )
{
    READ_STREAM rst = hd->read_stream;
    ulong pktlen;
    int rc;
    size_t blocksize, n, paylen, padlen, maclen;
    u32 seqno;

    blocksize = 8;
    maclen = hd->recv_mac_hd?
        gcry_md_get_algo_dlen(gcry_md_get_algo(hd->recv_mac_hd)) : 0;
  again:
    seqno = hd->recv_seqno++;
    /* read the first block so we can decipher the packet length */
    rc = stream_readn( rst, hd->pkt.packet_buffer, blocksize );
    if( rc )
	return debug_rc(rc,"error reading packet header");

    if( hd->decrypt_hd ) {
	rc = gcry_cipher_decrypt( hd->decrypt_hd,
				  hd->pkt.packet_buffer, blocksize,
				  hd->pkt.packet_buffer, blocksize );
	if( rc )
	    return debug_rc(rc,"error decrypting first block");
    }

    dump_hexbuf(stderr, "begin of packet: ",
				  hd->pkt.packet_buffer, blocksize );
    pktlen = buftou32( hd->pkt.packet_buffer );
    /* FIXME: It should be 16 but NEWKEYS has 12 for some reason */
    if( pktlen < 12 ) /* minimum packet size as per secsh draft */
	return debug_rc(GSTI_TOO_SHORT, "received pktlen %lu", (ulong)pktlen);
    if( pktlen > MAX_PKTLEN )
	return debug_rc(GSTI_TOO_LARGE, "received pktlen %lu", (ulong)pktlen);

    padlen = hd->pkt.packet_buffer[4];
    if( padlen < 4 )
	return debug_rc(GSTI_TOO_SHORT, "received padding is %lu", (ulong)padlen);

    hd->pkt.packet_len = pktlen;
    hd->pkt.padding_len = padlen;
    hd->pkt.payload_len = paylen = pktlen - padlen - 1;

    n = 5 + paylen + padlen;
    if( (n % blocksize) )
	debug_rc(GSTI_INV_PKT,"length packet is not a "
				      "multiple of the blocksize");

    /* read the rest of the packet */
    n = 4 + pktlen + maclen;
    if( n >= blocksize )
	n -= blocksize;
    else
	n = 0; /* oops: rest of packet is too short */

    fprintf(stderr,"packet_len=%lu padding=%lu payload=%lu maclen=%lu n=%lu\n",
		    (ulong)hd->pkt.packet_len,
		    (ulong)hd->pkt.padding_len,
		    (ulong)hd->pkt.payload_len,
		    (ulong)maclen,
		    (ulong)n );

    rc = stream_readn( rst, hd->pkt.packet_buffer+blocksize, n );
    if( rc )
	return debug_rc(rc,"error reading rest of packet");
    n -= maclen; /* don't want the maclen anymore */
    if( hd->decrypt_hd ) {
	rc = gcry_cipher_decrypt( hd->decrypt_hd,
				  hd->pkt.packet_buffer+blocksize, n,
				  hd->pkt.packet_buffer+blocksize, n );
	if( rc )
	    return debug_rc(rc,"decrypt failed");
	/* note: there is no reason to decrypt the padding, but we do
	 * it anyway becuase this is easier */
       dump_hexbuf(stderr, "rest of  packet: ",
				  hd->pkt.packet_buffer+blocksize, n );
    }

    if( hd->recv_mac_hd && !verify_mac( hd, seqno ) )
	return debug_rc( GSTI_INV_MAC, "wrong MAC");

    /* todo: uncompress if needed */

    hd->pkt.type = *hd->pkt.payload;
    fprintf(stderr, "received packet %lu of type %d\n",
					(ulong)seqno, hd->pkt.type );

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
write_packet( GSTIHD hd )
{
    WRITE_STREAM wst = hd->write_stream;
    int rc;
    int blocksize = 8; /* fixme: take blocksize of cipher into account */
    size_t n, padlen, paylen, maclen;
    u32 seqno = hd->send_seqno++;

    hd->pkt.padding_len = blocksize - ((4 + 1 + hd->pkt.payload_len) % blocksize );
    if( hd->pkt.padding_len < 4 )
	hd->pkt.padding_len += blocksize;

    hd->pkt.payload[0] = hd->pkt.type; /* make sure the type is set */
    hd->pkt.packet_len = 1 + hd->pkt.payload_len + hd->pkt.padding_len;

    fprintf(stderr, "sending packet %lu of type %d\n",
					(ulong)seqno, hd->pkt.type );

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
    memset( hd->pkt.payload+paylen, 'P', padlen ); /* fixme: use random bytes*/

    maclen = generate_mac( hd, seqno );

    /* write the payload */
    n = 5 + paylen + padlen;
    assert( !(n%blocksize) );
    if( hd->encrypt_hd ) {
	rc = gcry_cipher_encrypt( hd->encrypt_hd,
				  hd->pkt.packet_buffer, n,
				  hd->pkt.packet_buffer, n );
	if( rc )
	    return rc;
    }
    n = 5 + paylen + padlen + maclen;
    rc = stream_writen( wst, hd->pkt.packet_buffer, n );
    if( rc )
	return rc;


    return 0;
}

int
flush_packet( GSTIHD hd )
{
    WRITE_STREAM wst = hd->write_stream;
    int rc;

    rc = stream_flush( wst );
    if( rc )
	return GSTI_WRITE_ERROR;
    return 0;
}



