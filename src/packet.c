/* packet.c - packet read/write
   Copyright (C) 1999 Werner Koch
   Copyright (C) 2002 Timo Schulz
   Copyright (C) 2004 g10 Code GmbH

   This file is part of GSTI.

   GSTI is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   GSTI is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA  */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <gcrypt.h>

#include "types.h"
#include "buffer.h"
#include "api.h"
#include "memory.h"
#include "stream.h"
#include "packet.h"


static u32
buftou32 (const byte * buf)
{
  u32 a;
  a = buf[0] << 24;
  a |= buf[1] << 16;
  a |= buf[2] << 8;
  a |= buf[3];
  return a;
}


static void
print_disconnect_msg (const byte * msg, size_t msglen)
{
  BUFFER buf = NULL;
  BSTRING desc, lang;
  u32 reason;

  if (msglen < 13)
    {
      _gsti_log_info (0, "SSH_MSG_DISCONNECT is not valid\n");
      return;
    }
  _gsti_buf_init (&buf);
  _gsti_buf_putraw (buf, msg, msglen);
  if (_gsti_buf_getc (buf) != SSH_MSG_DISCONNECT)
    goto leave;
  reason = _gsti_buf_getint (buf);
  _gsti_log_info (0, "SSH_MSG_DISCONNECT: reason=%lu `", reason);

  if (_gsti_buf_getbstr (buf, &desc))
    goto leave;
  _gsti_dump_bstring ("description:", desc);
  _gsti_bstring_free (desc);

  if (_gsti_buf_getbstr (buf, &lang))
    goto leave;
  _gsti_dump_bstring ("language-tag:", lang);
  _gsti_bstring_free (lang);

leave:
  msglen = _gsti_buf_getlen (buf);
  _gsti_buf_free (buf);
  if (msglen)
    _gsti_log_info (0, "print_msg_disconnect: %lu bytes remaining\n",
		    (u32) msglen);
}


static void
print_debug_msg (const byte * msg, size_t msglen)
{
  BUFFER buf = NULL;
  BSTRING mesag, lang;
  int display;

  if (msglen < (1 + 1 + 4 + 4))
    {
      _gsti_log_info (0, "SSH_MSG_DEBUG is not valid\n");
      return;
    }
  _gsti_buf_init (&buf);
  _gsti_buf_putraw (buf, msg, msglen);
  if (_gsti_buf_getc (buf) != SSH_MSG_DEBUG)
    goto leave;

  display = _gsti_buf_getc (buf);
  _gsti_log_info (0, "SSH_MSG_DEBUG:%s `", display ? " (always display)" : "");

  if (_gsti_buf_getbstr (buf, &mesag))
    goto leave;
  _gsti_dump_bstring ("message:", mesag);
  _gsti_bstring_free (mesag);

  if (_gsti_buf_getbstr (buf, &lang))
    goto leave;
  _gsti_dump_bstring ("language:", lang);
  _gsti_bstring_free (lang);


leave:
  msglen = _gsti_buf_getlen (buf);
  _gsti_buf_free (buf);
  if (msglen)
    _gsti_log_info (0, "print_msg_debug: %lu bytes remaining\n", (u32) msglen);
}


void
_gsti_packet_init (gsti_ctx_t ctx)
{
  if (ctx && !ctx->pkt.payload)
    {
      ctx->pkt.size = PKTBUFSIZE;
      ctx->pkt.packet_buffer = _gsti_xmalloc (ctx->pkt.size + 5);
      ctx->pkt.payload = ctx->pkt.packet_buffer + 5;
    }
}


void
_gsti_packet_free (gsti_ctx_t ctx)
{
  if (ctx && ctx->pkt.packet_buffer)
    {
      _gsti_free (ctx->pkt.packet_buffer);
      ctx->pkt.payload = NULL;
    }
}

/****************
 * Generate a HMAC for the current packet with the given sequence nr.
 */
static size_t
generate_mac (gsti_ctx_t ctx, u32 seqno)
{
  gcry_md_hd_t md;
  byte buf[4];
  byte *p = ctx->pkt.packet_buffer;
  size_t n = 5 + ctx->pkt.payload_len + ctx->pkt.padding_len;

  if (!ctx->send_mac)
    return 0;			/* no MAC requested */

  if (gcry_md_copy (&md, ctx->send_mac))
    return 0;
  buf[0] = seqno >> 24;
  buf[1] = seqno >> 16;
  buf[2] = seqno >> 8;
  buf[3] = seqno;
  gcry_md_write (md, buf, 4);
  gcry_md_write (md, p, n);
  gcry_md_final (md);
  memcpy (p + n, gcry_md_read (md, 0), ctx->mac_len);
  gcry_md_close (md);
  return ctx->mac_len;
}


/* Verify a HMAC from the packet.  */
static gsti_error_t
verify_mac (gsti_ctx_t ctx, u32 seqno)
{
  gsti_error_t err;
  gcry_md_hd_t md;
  byte buf[4];
  byte *p = ctx->pkt.packet_buffer;
  size_t n = 5 + ctx->pkt.payload_len + ctx->pkt.padding_len;
  int res;

  err = gcry_md_copy (&md, ctx->recv_mac);
  if (err)
    return err;
  buf[0] = seqno >> 24;
  buf[1] = seqno >> 16;
  buf[2] = seqno >> 8;
  buf[3] = seqno;
  gcry_md_write (md, buf, 4);
  gcry_md_write (md, p, n);
  gcry_md_final (md);
  res = !memcmp (p + n, gcry_md_read (md, 0), ctx->mac_len);
  gcry_md_close (md);
  return res;
}


/* Read a new packet from the input and store it in the packet buffer
   Decompression and decryption is handled too.  */
gsti_error_t
_gsti_packet_read (gsti_ctx_t ctx)
{
  gsti_error_t err;
  READ_STREAM rst = ctx->read_stream;
  u32 pktlen, seqno;
  size_t blksize, n, paylen, padlen, maclen;
  byte *p;

  blksize = ctx->ciph_blksize ? ctx->ciph_blksize : 8;
  maclen = ctx->recv_mac ? ctx->mac_len : 0;
again:
  seqno = ctx->recv_seqno++;
  /* read the first block so we can decipher the packet length */
  err = _gsti_stream_readn (rst, ctx->pkt.packet_buffer, blksize);
  if (err)
    return _gsti_log_err (ctx, err, "error reading packet header\n");

  if (ctx->decrypt_hd)
    {
      p = ctx->pkt.packet_buffer;
      err = gcry_cipher_decrypt (ctx->decrypt_hd, p, blksize, NULL, 0);
      if (err)
	return _gsti_log_err (ctx, err, "error decrypting first block\n");
    }

  _gsti_dump_hexbuf ("begin of packet: ", ctx->pkt.packet_buffer, blksize);

  pktlen = buftou32 (ctx->pkt.packet_buffer);
  /* FIXME: It should be 16 but NEWKEYS has 12 for some reason.  */
  if (pktlen < 12)		/* minimum packet size as per secsh draft */
    return _gsti_log_err (ctx, gsti_error (GPG_ERR_TOO_SHORT),
			  "received pktlen %lu \n", (u32) pktlen);
  if (pktlen > MAX_PKTLEN)
    return _gsti_log_err (ctx, gsti_error (GPG_ERR_TOO_LARGE),
			  "received pktlen %lu\n", (u32) pktlen);

  padlen = ctx->pkt.packet_buffer[4];
  if (padlen < 4)
    return _gsti_log_err (ctx, gsti_error (GPG_ERR_TOO_SHORT),
			  "received padding is %lu\n", (u32) padlen);

  ctx->pkt.packet_len = pktlen;
  ctx->pkt.padding_len = padlen;
  ctx->pkt.payload_len = paylen = pktlen - padlen - 1;

  n = 5 + paylen + padlen;
  if ((n % blksize))
    _gsti_log_err (ctx, gsti_error (GPG_ERR_INV_PACKET),
		   "length packet is not a multiple of the blksize\n");

  /* Read the rest of the packet.  */
  n = 4 + pktlen + maclen;
  if (n >= blksize)
    n -= blksize;
  else
    n = 0;			/* oops: rest of packet is too short */

  _gsti_log_debug (ctx, "packet_len=%lu padding=%lu payload=%lu "
		   "maclen=%lu n=%lu\n",
		   (u32) ctx->pkt.packet_len, (u32) ctx->pkt.padding_len,
		   (u32) ctx->pkt.payload_len, (u32) maclen, (u32) n);

  err = _gsti_stream_readn (rst, ctx->pkt.packet_buffer + blksize, n);
  if (err)
    return _gsti_log_err (ctx, err, "error reading rest of packet\n");
  n -= maclen;			/* don't want the maclen anymore */
  if (ctx->decrypt_hd)
    {
      p = ctx->pkt.packet_buffer + blksize;
      err = gcry_cipher_decrypt (ctx->decrypt_hd, p, n, NULL, 0);
      if (err)
	return _gsti_log_err (ctx, err, "decrypt failed\n");
      /* Note: There is no reason to decrypt the padding, but we do it
         anyway because this is easier.  */
      _gsti_dump_hexbuf ("rest of packet: ", ctx->pkt.packet_buffer + blksize,
			 n);
    }

  if (ctx->recv_mac && !verify_mac (ctx, seqno))
    return _gsti_log_err (ctx, gsti_error (GPG_ERR_INV_MAC), "wrong MAC\n");

  if (ctx->zlib.use && !ctx->zlib.init)
    {
      _gsti_decompress_init ();
      ctx->zlib.init = 1;
    }
  /* TODO: Do the uncompressions.  */

  ctx->pkt.type = *ctx->pkt.payload;
  _gsti_log_info (ctx, "received packet %lu of type %d\n",
		  (u32) seqno, ctx->pkt.type);
  _gsti_buf_free (ctx->pktbuf);
  _gsti_buf_set (&ctx->pktbuf, ctx->pkt.payload, ctx->pkt.payload_len);

  switch (ctx->pkt.type)
    {
    case SSH_MSG_IGNORE:
      goto again;
      break;

    case SSH_MSG_DEBUG:
      print_debug_msg (ctx->pkt.payload, ctx->pkt.payload_len);
      break;

    case SSH_MSG_DISCONNECT:
      print_disconnect_msg (ctx->pkt.payload, ctx->pkt.payload_len);
      break;
    }

  return 0;
}



/* Write a new packet from the packet buffer.  Compression and
   encryption is handled here.  FIXME: make sure that the padding does
   not cause a buffer overflow!!!  */
gsti_error_t
_gsti_packet_write (gsti_ctx_t ctx)
{
  gsti_error_t err;
  WRITE_STREAM wst = ctx->write_stream;
  size_t n, padlen, paylen, maclen;
  u32 seqno = ctx->send_seqno++;
  byte *p;
  int blksize;

  blksize = ctx->ciph_blksize ? ctx->ciph_blksize : 8;
  ctx->pkt.padding_len = blksize - ((4 + 1 + ctx->pkt.payload_len) % blksize);
  if (ctx->pkt.padding_len < 4)
    ctx->pkt.padding_len += blksize;

  if (ctx->pkt.type == 0)
    return gsti_error (GPG_ERR_INV_PACKET);	/* make sure the type is set */
  ctx->pkt.payload[0] = ctx->pkt.type;
  ctx->pkt.packet_len = 1 + ctx->pkt.payload_len + ctx->pkt.padding_len;

  _gsti_log_info (ctx, "sending packet %lu of type %d\n",
		  (u32) seqno, ctx->pkt.type);

  if (ctx->zlib.use && !ctx->zlib.init)
    {
      _gsti_compress_init ();
      ctx->zlib.init = 1;
    }
  /* FIXME: Do the compression.  */

  /* Construct header.  This must be a complete block, so the the
     encrypt function can handle it.  */
  n = ctx->pkt.packet_len;
  ctx->pkt.packet_buffer[0] = n >> 24;
  ctx->pkt.packet_buffer[1] = n >> 16;
  ctx->pkt.packet_buffer[2] = n >> 8;
  ctx->pkt.packet_buffer[3] = n;
  ctx->pkt.packet_buffer[4] = ctx->pkt.padding_len;
  paylen = ctx->pkt.payload_len;
  padlen = ctx->pkt.padding_len;
  gcry_randomize (ctx->pkt.payload + paylen, padlen, GCRY_WEAK_RANDOM);

  maclen = generate_mac (ctx, seqno);

  /* Write the payload */
  n = 5 + paylen + padlen;
  assert (!(n % blksize));
  if (ctx->encrypt_hd)
    {
      p = ctx->pkt.packet_buffer;
      err = gcry_cipher_encrypt (ctx->encrypt_hd, p, n, NULL, 0);
      if (err)
	return err;
    }
  n = 5 + paylen + padlen + maclen;
  err = _gsti_stream_writen (wst, ctx->pkt.packet_buffer, n);
  if (err)
    return err;

  return 0;
}


gsti_error_t
_gsti_packet_flush (gsti_ctx_t ctx)
{
  WRITE_STREAM wst = ctx->write_stream;

  return _gsti_stream_flush (wst);
}
