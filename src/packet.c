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
#include <errno.h>

#include "types.h"
#include "utils.h"
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


static const char *
msg_id_to_str (int msg_id)
{
  const char *s;

  switch (msg_id)
    {
    case SSH_MSG_DISCONNECT:    s = "disconnect"; break;
    case SSH_MSG_IGNORE:        s = "ignore"; break;
    case SSH_MSG_UNIMPLEMENTED: s = "unimplemented"; break;
    case SSH_MSG_DEBUG:         s = "debug"; break;
    case SSH_MSG_SERVICE_REQUEST: s = "service_request"; break;
    case SSH_MSG_SERVICE_ACCEPT: s = "service_accept"; break;

    case SSH_MSG_KEXINIT:        s = "kexinit"; break;
    case SSH_MSG_NEWKEYS:        s = "newkeys"; break;

      /* Duplicated value:
         case SSH_MSG_KEXDH_INIT:     s = "kexdh_init"; break;
         case SSH_MSG_KEXDH_REPLY:    s = "kexdh_reply"; break; */

    case SSH_MSG_KEX_DH_GEX_REQUEST_OLD: s = "kex_dh_gex_request_old"; break;
    case SSH_MSG_KEX_DH_GEX_GROUP:   s = "kex_dh_gex_group"; break;
    case SSH_MSG_KEX_DH_GEX_INIT:    s = "kex_dh_gex_init"; break;
    case SSH_MSG_KEX_DH_GEX_REPLY:   s = "kex_dh_gex_reply"; break;
    case SSH_MSG_KEX_DH_GEX_REQUEST: s = "kex_dh_gex_request"; break;

    case SSH_MSG_USERAUTH_REQUEST: s = "userauth_request"; break;
    case SSH_MSG_USERAUTH_FAILURE: s = "userauth_failure"; break;
    case SSH_MSG_USERAUTH_SUCCESS: s = "userauth_success"; break;
    case SSH_MSG_USERAUTH_BANNER:  s = "userauth_banner"; break;

      /* Duplicated value:
        case SSH_MSG_USERAUTH_PK_OK:   s = "userauth_pk_ok"; break;*/

    case SSH_MSG_USERAUTH_PASSWORD_CHANGEREQ:
                                   s = "userauth_password_changereq"; break;

    case SSH_MSG_GLOBAL_REQUEST:  s = "global_request"; break;
    case SSH_MSG_REQUEST_SUCCESS: s = "request_success"; break;
    case SSH_MSG_REQUEST_FAILURE: s = "request_failure"; break;
    case SSH_MSG_CHANNEL_OPEN:    s = "channel_open"; break;
    case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
                                        s = "channel_open_confirmation"; break;
    case SSH_MSG_CHANNEL_OPEN_FAILURE:  s = "channel_open_failure"; break;
    case SSH_MSG_CHANNEL_WINDOW_ADJUST: s = "channel_window_adjust"; break;
    case SSH_MSG_CHANNEL_DATA:          s = "channel_data"; break;
    case SSH_MSG_CHANNEL_EXTENDED_DATA: s = "channel_extended_data"; break;
    case SSH_MSG_CHANNEL_EOF:           s = "channel_eof"; break;
    case SSH_MSG_CHANNEL_CLOSE:         s = "channel_close"; break;
    case SSH_MSG_CHANNEL_REQUEST:       s = "channel_request"; break;
    case SSH_MSG_CHANNEL_SUCCESS:       s = "channel_success"; break;
    case SSH_MSG_CHANNEL_FAILURE:       s = "channel_failure"; break;
      
    default: s = "?"; break;
    }
  return s;
}



static void
print_disconnect_msg (gsti_ctx_t ctx, const byte * msg, size_t msglen)
{
  gsti_error_t err;

  gsti_buffer_t buf = NULL;
  gsti_bstr_t desc, lang;
  u32 reason;
  int val;

  if (msglen < 13)
    {
      _gsti_log_info (ctx, "SSH_MSG_DISCONNECT is not valid\n");
      return;
    }

  err = gsti_buf_alloc (&buf);
  if (err)
    return;

  err = gsti_buf_putraw (buf, msg, msglen);
  if (err)
    return;

  err = gsti_buf_getc (buf, &val);
  if (err)
    goto leave;

  if (val != SSH_MSG_DISCONNECT)
    goto leave;

  err = gsti_buf_getuint32 (buf, &reason);
  if (err)
    goto leave;
  _gsti_log_info (ctx, "SSH_MSG_DISCONNECT: reason: %lu\n", reason);

  if (gsti_buf_getbstr (buf, &desc))
    goto leave;
  _gsti_log_info (ctx, "               description: ");
  _gsti_print_string (ctx, gsti_bstr_data (desc), gsti_bstr_length (desc));
  _gsti_log_cont (ctx, "\n");
  gsti_bstr_free (desc);

  if (gsti_buf_getbstr (buf, &lang))
    goto leave;
  _gsti_log_info (ctx, "              language-tag: ", lang);
  _gsti_print_string (ctx, gsti_bstr_data (lang), gsti_bstr_length (lang));
  _gsti_log_cont (ctx, "\n");
  gsti_bstr_free (lang);

leave:
  msglen = gsti_buf_readable (buf);
  gsti_buf_free (buf);
  if (msglen)
    _gsti_log_err (ctx, "print_msg_disconnect: %lu bytes remaining\n",
                   (unsigned long) msglen);
}


static void
print_debug_msg (gsti_ctx_t ctx, const byte * msg, size_t msglen)
{
  gsti_error_t err;
  gsti_buffer_t buf = NULL;
  gsti_bstr_t mesag, lang;
  int val;

  if (msglen < (1 + 1 + 4 + 4))
    {
      _gsti_log_info (ctx, "SSH_MSG_DEBUG is not valid\n");
      return;
    }

  err = gsti_buf_alloc (&buf);
  if (err)
    return;

  err = gsti_buf_putraw (buf, msg, msglen);
  if (err)
    return;

  err = gsti_buf_getc (buf, &val);
  if (err)
    goto leave;
  if (val != SSH_MSG_DEBUG)  /* FIXME: Why is this?? -wk */
    goto leave;

  err = gsti_buf_getbool (buf, &val);
  if (err)
    goto leave;
  if (val)
    _gsti_log_info  (ctx, "SSH_MSG_DEBUG: (always display)\n");
  else
    _gsti_log_debug (ctx, "SSH_MSG_DEBUG:\n");

  if (gsti_buf_getbstr (buf, &mesag))
    goto leave;
  if (val)
    {
      _gsti_log_info (ctx, "              message: ");
      _gsti_print_string (ctx,
                          gsti_bstr_data (mesag), gsti_bstr_length (mesag));
      _gsti_log_cont (ctx, "\n");
    }
  else
    _gsti_dump_bstring (ctx, "          message: ", mesag);
  gsti_bstr_free (mesag);

  if (gsti_buf_getbstr (buf, &lang))
    goto leave;
  if (val)
    {
      _gsti_log_info (ctx, "             language: ");
      _gsti_print_string (ctx, gsti_bstr_data (lang), gsti_bstr_length (lang));
      _gsti_log_cont (ctx, "\n");
    }
  else
    _gsti_dump_bstring (ctx, "         language: ", lang);
  gsti_bstr_free (lang);

leave:
  msglen = gsti_buf_readable (buf);
  gsti_buf_free (buf);
  if (msglen)
    _gsti_log_err (ctx, "print_msg_debug: %lu bytes remaining\n",
                     (unsigned long) msglen);
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
  if (ctx && ctx->pktbuf)
    {
      gsti_buf_free (ctx->pktbuf);
      ctx->pktbuf = NULL;
    }
}

/****************
 * Generate a HMAC for the current packet with the given sequence nr.
 */
static size_t
generate_mac (gsti_ctx_t ctx, struct packet_buffer_s *pkt, u32 seqno)
{
  gcry_md_hd_t md;
  byte buf[4];
  byte *p = pkt->packet_buffer;
  size_t n = 5 + pkt->payload_len + pkt->padding_len;

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
_gsti_handle_packet_data (gsti_ctx_t ctx, char *data, size_t data_len,
			  size_t *amount)
{
  gsti_error_t err = 0;
  size_t blksize;
  size_t maclen;

  blksize = ctx->ciph_blksize ? ctx->ciph_blksize : 8;
  maclen = ctx->recv_mac ? ctx->mac_len : 0;

  /* CTX->state_info is 0 if we are expecting a new packet header, and
     1 if we are waiting for the remainder of the packet to
     arrive.  */

  if (ctx->state_info == 0)
    {
      size_t n;
      size_t paylen;
      size_t padlen;
      byte *p;
      u32 pktlen;

      /* A new packet starts.  */

      /* We need at least the first block so we can decipher the
	 packet length.  */
      if (data_len < blksize)
	{
	  *amount = 0;
	  return 0;
	}

      /* Consume the first BLKSIZE bytes.  */
      *amount = blksize;
      memcpy (ctx->pkt.packet_buffer, data, blksize);

      if (ctx->decrypt_hd)
	{
	  p = ctx->pkt.packet_buffer;
	  err = gcry_cipher_decrypt (ctx->decrypt_hd, p, blksize, NULL, 0);
	  if (err)
	    {
	      _gsti_log_err (ctx, "error decrypting first block: %s\n",
			     gsti_strerror (err));
	      return err;
	    }
	}

      _gsti_dump_hexbuf (ctx, "begin of packet: ",
			 ctx->pkt.packet_buffer, blksize);

      pktlen = buftou32 (ctx->pkt.packet_buffer);
      /* FIXME: It should be 16 but NEWKEYS has 12 for some reason.  */
      /* Minimum packet size as per secsh draft.  */
      if (pktlen < 12)
	{
	  _gsti_log_err (ctx, "invalid packet length; received pktlen=%lu\n",
			 (unsigned long) pktlen);
	  return gsti_error (GPG_ERR_TOO_SHORT);
	}
      if (pktlen > MAX_PKTLEN)
	{
	  _gsti_log_err (ctx, "invalid packet length; received pktlen %lu\n",
			 (unsigned long) pktlen);
	  return gsti_error (GPG_ERR_TOO_LARGE);
	}
  
      padlen = ctx->pkt.packet_buffer[4];
      if (padlen < 4)
	{
	  _gsti_log_err (ctx,
			 "invalid packet length; received padding is %lu\n",
			 (unsigned long) padlen);
	  return gsti_error (GPG_ERR_TOO_SHORT);
	}

      ctx->pkt.packet_len = pktlen;
      ctx->pkt.padding_len = padlen;
      ctx->pkt.payload_len = paylen = pktlen - padlen - 1;

      n = 5 + paylen + padlen;
      if ((n % blksize))
	_gsti_log_err (ctx, "note: length of packet is not a multiple"
		       " of the block size\n");

      ctx->state_info = 1;
      return 0;
    }
  else if (ctx->state_info == 1)
    {
      u32 seqno;
      size_t n;

      /* Read the rest of the packet.  */
      n = 4 + ctx->pkt.packet_len + maclen;
      if (n >= blksize)
	n -= blksize;
      else
	/* Oops: The rest of packet is too short.  */
	n = 0;

      if (n > data_len)
	{
	  *amount = 0;
	  return 0;
	}
      
      _gsti_log_debug (ctx, "packet_len=%lu padding=%lu payload=%lu "
		       "maclen=%lu n=%lu\n",
		       (u32) ctx->pkt.packet_len, (u32) ctx->pkt.padding_len,
		       (u32) ctx->pkt.payload_len, (u32) maclen, (u32) n);

      *amount = n;
      memcpy (ctx->pkt.packet_buffer + blksize, data, n);

      /* Don't want the maclen anymore.  FIXME: What if we set N to 0
	 above?  */
      n -= maclen;
      if (ctx->decrypt_hd)
	{
	  byte *p = ctx->pkt.packet_buffer + blksize;
	  err = gcry_cipher_decrypt (ctx->decrypt_hd, p, n, NULL, 0);
	  if (err)
	    {
	      _gsti_log_err (ctx, "decryption failed: %s\n",
			     gsti_strerror (err));
	      return err;
	    }

	  /* Note: There is no reason to decrypt the padding, but we do it
	     anyway because this is easier.  */
	  _gsti_dump_hexbuf (ctx, "next 16 bytes of packet: ",
			     ctx->pkt.packet_buffer + blksize,
			     n > 16? 16: n);
	}
      
      seqno = ctx->recv_seqno++;

      if (ctx->recv_mac && !verify_mac (ctx, seqno))
	{
	  err = gsti_error (GPG_ERR_INV_MAC);
	  _gsti_log_err (ctx, "decryption failed: %s\n", gsti_strerror (err));
	  return err;
	}

      if (ctx->zlib.use && !ctx->zlib.init)
	{
	  _gsti_decompress_init ();
	  ctx->zlib.init = 1;
	}

      /* TODO: Do the uncompressions.  */

      ctx->pkt.type = *ctx->pkt.payload;
      _gsti_log_debug (ctx, "received packet %lu of type %d (%s)\n",
		       (u32) seqno, ctx->pkt.type,
		       msg_id_to_str (ctx->pkt.type));
      if (!ctx->pktbuf)
	err = gsti_buf_alloc (&ctx->pktbuf);
      if (!err)
	err = gsti_buf_set (ctx->pktbuf, (char *) ctx->pkt.payload,
			    ctx->pkt.payload_len);
      if (err)
	return err;

      switch (ctx->pkt.type)
	{
	case SSH_MSG_DEBUG:
	  print_debug_msg (ctx, ctx->pkt.payload, ctx->pkt.payload_len);
	  break;
	  
	case SSH_MSG_DISCONNECT:
	  print_disconnect_msg (ctx, ctx->pkt.payload, ctx->pkt.payload_len);
	  break;

	default:
	  err = (*ctx->packet_handler) (ctx);
	  if (err)
	    return err;
	} 

      ctx->state_info = 0;
      return 0;
    }
  else
    {
      _gsti_log_err (ctx, "unexpected CTX->state_info %u\n", ctx->state_info);
      return gsti_error (GPG_ERR_BUG);
    }
}


/* Write a new packet from the packet buffer.  Compression and
   encryption is handled here.  FIXME: make sure that the padding does
   not cause a buffer overflow!!!  */
gsti_error_t
_gsti_packet_write (gsti_ctx_t ctx, struct packet_buffer_s *pkt)
{
  gsti_error_t err;
  write_stream_t wst = ctx->write_stream;
  size_t n, padlen, paylen, maclen;
  u32 seqno = ctx->send_seqno++;
  byte *p;
  int blksize;

  /* We exceeded our sequence number limit, start re-keying. */
  if (seqno > (MAX_SEQNO-1))
    ctx->req_newkeys = 1;
  
  blksize = ctx->ciph_blksize ? ctx->ciph_blksize : 8;
  pkt->padding_len = blksize - ((4 + 1 + pkt->payload_len) % blksize);
  if (pkt->padding_len < 4)
    pkt->padding_len += blksize;

  if (pkt->type == 0)
    return gsti_error (GPG_ERR_INV_PACKET);	/* make sure the type is set */
  pkt->payload[0] = pkt->type;
  pkt->packet_len = 1 + pkt->payload_len + pkt->padding_len;

  _gsti_log_debug (ctx, "sending packet %lu of type %d (%s)\n",
		  (u32) seqno, pkt->type, msg_id_to_str (pkt->type));

  if (ctx->zlib.use && !ctx->zlib.init)
    {
      _gsti_compress_init ();
      ctx->zlib.init = 1;
    }
  /* FIXME: Do the compression.  */

  /* Construct header.  This must be a complete block, so the the
     encrypt function can handle it.  */
  n = pkt->packet_len;
  pkt->packet_buffer[0] = n >> 24;
  pkt->packet_buffer[1] = n >> 16;
  pkt->packet_buffer[2] = n >> 8;
  pkt->packet_buffer[3] = n;
  pkt->packet_buffer[4] = pkt->padding_len;
  paylen = pkt->payload_len;
  padlen = pkt->padding_len;
  gcry_create_nonce (pkt->payload + paylen, padlen);

  maclen = generate_mac (ctx, pkt, seqno);

  /* Write the payload */
  n = 5 + paylen + padlen;
  assert (!(n % blksize));
  if (ctx->encrypt_hd)
    {
      p = pkt->packet_buffer;
      err = gcry_cipher_encrypt (ctx->encrypt_hd, p, n, NULL, 0);
      if (err)
	return err;
    }
  n = 5 + paylen + padlen + maclen;
  err = _gsti_stream_writen (wst, pkt->packet_buffer, n);
  if (err)
    return err;

  return 0;
}


gsti_error_t
_gsti_write_packet_from_buffer (gsti_ctx_t ctx, gsti_buffer_t buf)
{
  gsti_error_t err;
  size_t buflen;
  struct packet_buffer_s pkt;

  pkt.size = PKTBUFSIZE;
  pkt.packet_buffer = malloc (pkt.size + 5);
  if (!pkt.packet_buffer)
    return gsti_error_from_errno (errno);
  pkt.payload = pkt.packet_buffer + 5;

  /* Protect against buffer overflow.  */
  buflen = gsti_buf_readable (buf);
  if (buflen > pkt.size)
    return gsti_error (GPG_ERR_TOO_LARGE);

  /* Set up the packet.  */
  err = gsti_buf_getraw (buf, pkt.payload, buflen);
  assert (!err);
  pkt.payload_len = buflen;
  pkt.type = pkt.payload[0];

  /* Send the packet.  */
  err = _gsti_packet_write (ctx, &pkt);

  free (pkt.packet_buffer);

  return err;
}


/* Write a packet and return it's sequence number in pkt->seqno.  If
   pkt is NULL a flush operation is performed. This is needed if the
   protocol which is used on top of this transport protocol must
   assure that a packet has really been sent to the peer.  */
gsti_error_t
gsti_put_packet (gsti_ctx_t ctx, gsti_pktdesc_t pktdesc)
{
  gsti_error_t err;
  const byte *data;
  size_t datalen;
  struct packet_buffer_s pkt;

  if (!pktdesc)
    return _gsti_packet_flush (ctx);

  pkt.size = PKTBUFSIZE;

  data = pktdesc->data;
  datalen = pktdesc->datalen;
  if (!datalen)
    return gsti_error (GPG_ERR_TOO_SHORT);	/* need the packet type */

  if (datalen > pkt.size)
    return gsti_error (GPG_ERR_TOO_LARGE);

  /* The caller is not allowed to supply any of the tranport protocol
     numbers nor one of the reserved numbers.  0 is not defined.  */
  if (!*data || *data <= 49 || (*data >= 128 && *data <= 191))
    return gsti_error (GPG_ERR_INV_ARG);

  pkt.packet_buffer = malloc (pkt.size + 5);
  if (!pkt.packet_buffer)
    return gsti_error_from_errno (errno);

  pkt.type = *data;
  pkt.payload = pkt.packet_buffer + 5;
  pkt.payload_len = datalen;
  memcpy (pkt.payload, data, datalen);

  /* Send the packet.  */
  err = _gsti_packet_write (ctx, &pkt);

  free (pkt.packet_buffer);
  if (!err)
    {
      u32 seqno = ctx->send_seqno - 1;
      pktdesc->seqno = seqno;
    }

  return err;
}


gsti_error_t
_gsti_packet_flush (gsti_ctx_t ctx)
{
  write_stream_t wst = ctx->write_stream;

  return _gsti_stream_flush (wst);
}
