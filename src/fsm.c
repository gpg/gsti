/* fsm.c - state machine for the transport protocol
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

#include "types.h"
#include "utils.h"
#include "buffer.h"
#include "api.h"
#include "memory.h"
#include "stream.h"
#include "packet.h"
#include "kex.h"

#define logrc _gsti_log_err

enum fsm_states
{
  FSM_init = 0,
  FSM_read = 1,
  FSM_write = 2,
  FSM_wait_on_version = 3,
  FSM_send_version = 4,
  FSM_kex_start = 5,
  FSM_kex_wait = 6,
  FSM_kex_wait_newkeys = 7,
  FSM_kex_done = 8,
  FSM_wait_service_request = 9,
  FSM_send_service_request = 10,
  FSM_wait_service_accept = 11,
  FSM_send_service_accept = 12,
  FSM_service_start = 13,
  FSM_auth_start = 14,
  FSM_auth_wait = 15,
  FSM_auth_send_pkok = 16,
  FSM_auth_wait_pkok = 17,
  FSM_auth_send_request = 18,
  FSM_auth_wait_request = 19,
  FSM_auth_send_accept = 20,
  FSM_auth_wait_accept = 21,
  FSM_auth_done = 22,
  FSM_idle = 23,
  FSM_kex_failed = 24,
  FSM_auth_failed = 25,
  FSM_not_implemented = 26,
  FSM_quit = 27,
};


/* Do some initialization.  */
static gsti_error_t
handle_init (gsti_ctx_t ctx, int want_read)
{
  gsti_error_t err = 0;

  if (!ctx->readfnc || !ctx->writefnc)
    return gsti_error (GPG_ERR_INV_ARG);

  err = _gsti_read_stream_new (&ctx->read_stream,
                               ctx->readfnc, ctx->readctx);
  if (err)
      return err;
  err = _gsti_write_stream_new (&ctx->write_stream,
                                ctx->writefnc, ctx->writectx);
  if (err)
      return err;
  if (want_read)
    {
      /* Be the server side.  */
      ctx->we_are_server = 1;
      ctx->state = FSM_wait_on_version;
    }
  else
    {
      /* Be the client side.  */
      ctx->we_are_server = 0;
      ctx->state = FSM_send_version;
    }

  return err;
}



/* Cleanup the connection we are about to quit.  */
static gsti_error_t
handle_quit (gsti_ctx_t ctx)
{
  /* FIXME.  */
  return 0;
}


static void
log_error (gsti_ctx_t ctx)
{
  _gsti_log_info (ctx, "FSM: at new_state: state=%d, packet=%d\n",
		  ctx->state, ctx->pkt.type);
}


static gsti_error_t
request_packet (gsti_ctx_t ctx)
{
  gsti_error_t err;
  int pkttype = 0;

  do
    {
      err = _gsti_packet_read (ctx);
      if (err)
	_gsti_log_info (ctx, "FSM: read packet at state %d failed: %s\n",
			ctx->state, gsti_strerror (err));
      else
	pkttype = ctx->pkt.type;
    }
  while (!err && (pkttype == SSH_MSG_DEBUG || pkttype == SSH_MSG_IGNORE));
  return err;
}


static gsti_error_t
fsm_server_loop (gsti_ctx_t ctx)
{
  gsti_error_t err = 0;

  switch (ctx->state)
    {
    case FSM_init:
      err = handle_init (ctx, 1);
      break;
    case FSM_idle:
      ctx->state = FSM_read;
      break;
    default:
      _gsti_log_info (ctx, "FSM: start fsm_loop: invalid state %d\n",
		      ctx->state);
      err = gsti_error (GPG_ERR_BUG);
      break;
    }

  while (!err && ctx->state != FSM_quit && ctx->state != FSM_idle)
    {
      _gsti_log_info (ctx, "** FSM (server) state=%d\n", ctx->state);
      switch (ctx->state)
	{
	case FSM_wait_on_version:
	  err = kex_wait_on_version (ctx);
	  if (!err)
	    ctx->state = FSM_send_version;
	  break;

	case FSM_send_version:
	  err = kex_send_version (ctx);
	  if (!err)
	    ctx->state = FSM_kex_start;
	  break;

	case FSM_kex_start:
	  err = kex_send_init_packet (ctx);
	  if (!err)
	    err = request_packet (ctx);
	  if (!err)
	    {
	      switch (ctx->pkt.type)
		{
		case SSH_MSG_KEXINIT:
		  err = kex_proc_init_packet (ctx);
		  if (!err)
		    ctx->state = FSM_kex_wait;
		  break;

		default:
		  log_error (ctx);
		  ctx->state = FSM_kex_failed;
		}
	    }
	  break;

	case FSM_kex_wait:
	  err = request_packet (ctx);
	  if (!err)
	    {
	      switch (ctx->pkt.type)
		{
		case SSH_MSG_KEXDH_REPLY:
		  err = logrc (ctx, gsti_error (GPG_ERR_PROTOCOL_VIOLATION),
			       "server got KEXDH_REPLY\n");
		  break;

		case SSH_MSG_KEXDH_INIT:
		  err = kex_proc_kexdh_init (ctx);
		  if (!err)
		    err = kex_send_kexdh_reply (ctx);
		  if (!err)
		    err = kex_send_newkeys (ctx);
		  if (!err)
		    ctx->state = FSM_kex_wait_newkeys;
		  break;
		}
	    }
	  break;

	case FSM_kex_wait_newkeys:
	  err = request_packet (ctx);
	  if (!err)
	    {
	      switch (ctx->pkt.type)
		{
		case SSH_MSG_NEWKEYS:
		  err = kex_proc_newkeys (ctx);
		  if (!err)
		    ctx->state = FSM_kex_done;
		  break;

		default:
		  log_error (ctx);
		  ctx->state = FSM_kex_failed;
		}
	    }
	  break;

	case FSM_kex_done:
	  ctx->state = FSM_wait_service_request;
	  err = request_packet (ctx);
	  break;

	case FSM_wait_service_request:
	  switch (ctx->pkt.type)
	    {
	    case SSH_MSG_SERVICE_REQUEST:
	      err = kex_proc_service_request (ctx);
	      if (!err)
		ctx->state = FSM_send_service_accept;
	      break;

	    default:
	      log_error (ctx);
	      ctx->state = FSM_kex_failed;
	    }
	  break;

	case FSM_send_service_accept:
	  err = kex_send_service_accept (ctx);
	  if (!err)
	    ctx->state = FSM_service_start;
	  break;

	case FSM_service_start:
	  _gsti_log_info (ctx, "service `");
	  _gsti_print_string (gsti_bstr_data (ctx->service_name),
			      gsti_bstr_length (ctx->service_name));
	  _gsti_log_info (ctx, "' has been started (server)\n");
	  ctx->state = FSM_auth_wait;
	  break;

	case FSM_auth_wait:
	  err = request_packet (ctx);
	  if (!err)
	    {
	      switch (ctx->pkt.type)
		{
		case SSH_MSG_USERAUTH_REQUEST:
		  err = auth_proc_init_packet (ctx, ctx->auth);
		  if (!err)
		    ctx->state = FSM_auth_send_pkok;
		  break;

		default:
		  log_error (ctx);
		  ctx->state = FSM_auth_failed;
		}
	    }
	  break;

	case FSM_auth_send_pkok:
	  err = auth_send_pkok_packet (ctx, ctx->auth);
	  if (!err)
	    ctx->state = FSM_auth_wait_request;
	  break;

	case FSM_auth_wait_request:
	  err = request_packet (ctx);
	  if (!err)
	    {
	      switch (ctx->pkt.type)
		{
		case SSH_MSG_USERAUTH_REQUEST:
		  err = auth_proc_second_packet (ctx, ctx->auth);
		  if (!err)
		    ctx->state = FSM_auth_send_accept;
		  break;
		}
	    }
	  break;

	case FSM_auth_send_accept:
	  err = auth_send_accept_packet (ctx);
	  if (!err)
	    ctx->state = FSM_auth_done;
	  break;

	case FSM_auth_done:
	  ctx->state = FSM_read;
	  break;

	case FSM_read:
	  err = request_packet (ctx);
	  if (!err)
	    {
	      if (ctx->pkt.type >= 80 && ctx->pkt.type <= 127)
		err = _gsti_handle_channel_packet (ctx);
	      else		  
		ctx->state = FSM_idle;
	    }
	  break;

	case FSM_quit:
	  err = handle_quit (ctx);
	  _gsti_log_info (ctx, "FSM: returning from quit state: %s\n",
			  gsti_strerror (err));
	  break;

	default:
	  _gsti_log_info (ctx, "FSM: at fsm_loop: invalid state %d\n",
			  ctx->state);
	  err = gsti_error (GPG_ERR_BUG);
	}
    }
  return err;
}


gsti_error_t
fsm_client_loop (gsti_ctx_t ctx)
{
  gsti_error_t err = 0;

  switch (ctx->state)
    {
    case FSM_init:
      err = handle_init (ctx, 0);
      break;
    case FSM_idle:
      ctx->state = FSM_write;
      break;
    default:
      _gsti_log_info (ctx, "FSM: start fsm_loop: invalid state %d\n",
		      ctx->state);
      err = gsti_error (GPG_ERR_BUG);
      break;
    }

  while (!err && ctx->state != FSM_quit && ctx->state != FSM_idle)
    {
      _gsti_log_info (ctx, "** FSM (client) state=%d\n", ctx->state);
      switch (ctx->state)
	{
	case FSM_send_version:
	  err = kex_send_version (ctx);
	  if (!err)
	    ctx->state = FSM_wait_on_version;
	  break;

	case FSM_wait_on_version:
	  err = kex_wait_on_version (ctx);
	  if (!err)
	    ctx->state = FSM_kex_start;
	  break;

	case FSM_kex_start:
	  err = kex_send_init_packet (ctx);
	  if (!err)
	    err = request_packet (ctx);
	  if (!err)
	    err = kex_proc_init_packet (ctx);
	  if (!err)
	    err = kex_send_kexdh_init (ctx);
	  if (!err)
	    ctx->state = FSM_kex_wait;
	  break;

	case FSM_kex_wait:
	  err = request_packet (ctx);
	  if (!err)
	    {
	      switch (ctx->pkt.type)
		{
		case SSH_MSG_KEXDH_INIT:
		  err = logrc (ctx, gsti_error (GPG_ERR_PROTOCOL_VIOLATION),
			       "client got KEXDH_INIT\n");
		  break;

		case SSH_MSG_KEXDH_REPLY:
		  err = kex_proc_kexdh_reply (ctx);
		  if (!err)
		    err = kex_send_newkeys (ctx);
		  if (!err)
		    ctx->state = FSM_kex_wait_newkeys;
		  break;
		}
	    }
	  break;

	case FSM_kex_wait_newkeys:
	  err = request_packet (ctx);
	  if (!err)
	    {
	      switch (ctx->pkt.type)
		{
		case SSH_MSG_NEWKEYS:
		  err = kex_proc_newkeys (ctx);
		  if (!err)
		    ctx->state = FSM_kex_done;
		  break;

		default:
		  log_error (ctx);
		  ctx->state = FSM_kex_failed;
		}
	    }
	  break;

	case FSM_kex_done:
	  ctx->state = FSM_send_service_request;
	  break;

	case FSM_send_service_request:
	  _gsti_log_info (ctx, "is local service? (%d)\n",
			  ctx->local_services ? 1 : 0);
	  err = kex_send_service_request (ctx, ctx->local_services ?
					  ctx->local_services->d
					  : "ssh-userauth");
	  _gsti_log_info (ctx, "\n");
	  if (!err)
	    {
	      ctx->state = FSM_wait_service_accept;
	      err = request_packet (ctx);
	    }
	  break;

	case FSM_wait_service_accept:
	  switch (ctx->pkt.type)
	    {
	    case SSH_MSG_SERVICE_ACCEPT:
	      err = kex_proc_service_accept (ctx);
	      if (!err)
		ctx->state = FSM_service_start;
	      break;

	    default:
	      log_error (ctx);
	      ctx->state = FSM_kex_failed;
	    }
	  break;

	case FSM_service_start:
	  _gsti_log_info (ctx, "service `");
	  _gsti_print_string (gsti_bstr_data (ctx->service_name),
			      gsti_bstr_length (ctx->service_name));
	  _gsti_log_info (ctx, "' has been started (client)\n");
	  ctx->state = FSM_auth_start;
	  break;

	case FSM_auth_start:
	  err = auth_send_init_packet (ctx, ctx->auth);
	  if (!err)
	    ctx->state = FSM_auth_wait_pkok;
	  break;

	case FSM_auth_wait_pkok:
	  err = request_packet (ctx);
	  if (!err)
	    {
	      switch (ctx->pkt.type)
		{
		case SSH_MSG_USERAUTH_PK_OK:
		  err = auth_proc_pkok_packet (ctx, ctx->auth);
		  if (!err)
		    ctx->state = FSM_auth_send_request;
		  break;

		default:
		  log_error (ctx);
		  ctx->state = FSM_auth_failed;
		}
	    }
	  break;

	case FSM_auth_send_request:
	  err = auth_send_second_packet (ctx, ctx->auth);
	  if (!err)
	    ctx->state = FSM_auth_wait_accept;
	  break;

	case FSM_auth_wait_accept:
	  err = request_packet (ctx);
	  if (!err)
	    {
	      switch (ctx->pkt.type)
		{
		case SSH_MSG_USERAUTH_SUCCESS:
		  err = auth_proc_accept_packet (ctx);
		  if (!err)
		    ctx->state = FSM_auth_done;
		  break;

		default:
		  log_error (ctx);
		  ctx->state = FSM_auth_failed;
		}
	    }
	  break;

	case FSM_auth_done:
	  ctx->state = FSM_write;
	  break;

	case FSM_write:
	  err = _gsti_packet_write (ctx);
	  if (!err)
	    ctx->state = FSM_idle;
	  break;

	default:
	  _gsti_log_info (ctx, "FSM: at fsm_loop: invalid state %d\n",
			  ctx->state);
	  err = gsti_error (GPG_ERR_BUG);
	}
    }

  return err;
}


/* This is the main processing loop.  For now we use a simple switch
   based fsm.  */
gsti_error_t
fsm_loop (gsti_ctx_t ctx, int want_read)
{
  if (want_read)
    return fsm_server_loop (ctx);
  else
    return fsm_client_loop (ctx);
}


/* Get a packet from the connection.

   NOTE: The returned buffer is only valid until the next
   gsti_{get,put}_packet and as long as the handle is valid!  */
gsti_error_t
gsti_get_packet (gsti_ctx_t ctx, gsti_pktdesc_t pkt)
{
  gsti_error_t err;

  /* We do an extra loop to initialize the key exchange.  */
  if (!ctx->recv_seqno)
    {
      err = fsm_loop (ctx, 1);
      if (err)
	return err;
    }

  err = fsm_loop (ctx, 1);
  if (!err)
    {
      u32 seqno = ctx->recv_seqno - 1;
      pkt->datalen = ctx->pkt.payload_len;
      pkt->data = ctx->pkt.payload;
      pkt->seqno = seqno;
    }
  return err;
}


/* Write a packet and return it's sequence number in pkt->seqno.  If
   pkt is NULL a flush operation is performed. This is needed if the
   protocol which is used on top of this transport protocol must
   assure that a packet has really been sent to the peer.  */
gsti_error_t
gsti_put_packet (gsti_ctx_t ctx, gsti_pktdesc_t pkt)
{
  gsti_error_t err;
  const byte *data;
  size_t datalen;

  /* We do an extra loop to initialize the key exchange.  */
  if (!ctx->send_seqno)
    {
      ctx->pkt.type = 0xff;
      ctx->pkt.payload_len = 5;
      ctx->pkt.payload[0] = 0xff;
      memset (ctx->pkt.payload + 1, 0xff, 4);

      err = fsm_loop (ctx, 0);
      if (err)
	return err;
    }

  if (!pkt)
    return _gsti_packet_flush (ctx);

  data = pkt->data;
  datalen = pkt->datalen;
  if (!datalen)
    return gsti_error (GPG_ERR_TOO_SHORT);	/* need the packet type */

  if (datalen > ctx->pkt.size)
    return gsti_error (GPG_ERR_TOO_LARGE);

  /* The caller is not allowed to supply any of the tranport protocol
     numbers nor one of the reserved numbers.  0 is not defined.  */
  if (!*data || *data <= 49 || (*data >= 128 && *data <= 191))
    return gsti_error (GPG_ERR_INV_ARG);

  ctx->pkt.type = *data;
  ctx->pkt.payload_len = datalen;
  memcpy (ctx->pkt.payload, data, datalen);

  err = fsm_loop (ctx, 0);
  if (!err)
    {
      u32 seqno = ctx->send_seqno - 1;
      pkt->seqno = seqno;
    }

  return err;
}


gsti_error_t
fsm_user_read (gsti_ctx_t ctx)
{
  gsti_error_t err;
  struct gsti_pktdesc_s pkt;

  err = gsti_get_packet (ctx, &pkt);
  if (err)
    return err;

  ctx->user_read_nbytes = pkt.datalen;
  if (ctx->user_read_nbytes < ctx->user_read_bufsize)
    memcpy (ctx->user_read_buffer, pkt.data, pkt.datalen);

  return 0;
}


gsti_error_t
fsm_user_write (gsti_ctx_t ctx)
{
  struct gsti_pktdesc_s pkt;

  pkt.data = ctx->user_write_buffer;
  pkt.datalen = ctx->user_write_bufsize;

  return gsti_put_packet (ctx, &pkt);
}
