/* fsm.c - GSTI state management.
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

#include <errno.h>
#include <stdlib.h>

#include <gsti.h>

#include "utils.h"
#include "buffer.h"
#include "api.h"
#include "ssh.h"
#include "kex.h"
#include "packet.h"


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
  FSM_kex_wait_gex = 8,
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
  FSM_auth_send_success = 20,
  FSM_auth_wait_success = 21,
  FSM_auth_done = 22,
  FSM_idle = 23,
  FSM_kex_failed = 24,
  FSM_auth_failed = 25,
  FSM_not_implemented = 26,
  FSM_quit = 27,
};


static const char *
state_to_string (enum fsm_states state)
{
  const char *s;

  switch (state)
    {
#define X(a) case FSM_ ## a: s = STR(a); break
      X(init);
      X(read);
      X(write);
      X(wait_on_version);
      X(send_version);
      X(kex_start);
      X(kex_wait);
      X(kex_wait_newkeys);
      X(kex_wait_gex);
      X(wait_service_request);
      X(send_service_request);
      X(wait_service_accept);
      X(send_service_accept);
      X(service_start);
      X(auth_start);
      X(auth_wait);
      X(auth_send_pkok);
      X(auth_wait_pkok);
      X(auth_send_request);
      X(auth_wait_request);
      X(auth_send_success);
      X(auth_wait_success);
      X(auth_done);
      X(idle);
      X(kex_failed);
      X(auth_failed);
      X(not_implemented);
      X(quit);
#undef X
      default: s = "unknown"; break;
    }

  return s;
}

static void
log_error (gsti_ctx_t ctx)
{
  _gsti_log_err (ctx, "FSM: at new_state: state=%d, packet=%d\n",
                 ctx->state, ctx->pkt.type);
}


static void
log_state_error (gsti_ctx_t ctx)
{
  _gsti_log_err (ctx, "FSM: at fsm_loop: invalid state %d (pkt %d)\n",
                 ctx->state, ctx->pkt.type);
}


/* This is the handler for incoming data before we have gotten an
   identification string.  */
static gsti_error_t
handle_ident_data (gsti_ctx_t ctx, char *data, size_t data_len,
		   size_t *amount)
{
  gsti_error_t err;
  size_t pos;

  /* Waiting for and parsing the identification string is implemented
     as described in Transport 4.2 Protocol Version Exchange.  */

  /* CTX->state_info is true if we are waiting for the next beginning
     of a new line.  */
  if (ctx->state_info)
    {
      /* We are the client, and the server sends us non-identification
	 strings.  */
      for (pos = 0; pos < data_len; pos++)
	if (data[pos] == '\n')
	  break;

      /* If we found a newline, reset the state.  */
      if (pos < data_len)
	{
	  ctx->state_info = 0;
	  pos++;
	}

      if (ctx->pre_ident_cb)
	{
	  err = (*ctx->pre_ident_cb) (ctx, data, pos);
	  if (err)
	    return err;
	}

      /* Request that the next line is resubmitted to us.  */
      *amount = pos;
      return 0;
    }

  /* First make sure we never accept any data other than an
     identification string at the server side.  */
  if (ctx->we_are_server)
    {
      size_t min_len = SSH_IDENT_PREFIX_LEN;

      if (data_len < min_len)
	min_len = data_len;

      if (memcmp (data, SSH_IDENT_PREFIX, min_len))
	return gsti_error (GPG_ERR_PROTOCOL_VIOLATION);
    }

  /* Now we can be a bit more relaxed.  */
  for (pos = 0; pos < data_len; pos++)
    if (data[pos] == '\n')
      break;

  if (pos == data_len)
    {
      /* No newline found.  */
      *amount = data_len;

      /* If there is still room, try harder.  */
      if (data_len < SSH_IDENT_MAX_LEN + 2)
	{
	  *amount = 0;
	  return 0;
	}

      /* There is no room either.  This string is too long to be an
	 ident string.  */

      /* If it looks like an ident string, bail out.  */
      if (!memcmp (data, SSH_IDENT_PREFIX, SSH_IDENT_PREFIX_LEN))
	return gsti_error (GPG_ERR_PROTOCOL_VIOLATION);

      /* We are the client, and so we deal with arbitrary data the
	 server may send before the ident string here.  */
      if (ctx->pre_ident_cb)
	{
	  err = (*ctx->pre_ident_cb) (ctx, data, pos);
	  if (err)
	    return err;
	}

      /* Find the newline that is missing so far.  */
      *amount = data_len;
      ctx->state_info = 1;
      return 0;
    }

  /* If we made it here, we found a newline.  Process the line.  */
  *amount = pos + 1;

  if (data_len >= SSH_IDENT_PREFIX_LEN
      && !memcmp (data, SSH_IDENT_PREFIX, SSH_IDENT_PREFIX_LEN))
    {
      /* The line appears to be an ident string.  */

      if (data[pos - 1] == '\r')
	pos--;
      data[pos] = '\0';

      /* Sanity check.  */
      if (!strchr (&ctx->state_data[SSH_IDENT_PREFIX_LEN], '-'))
	return gsti_error (GPG_ERR_PROTOCOL_VIOLATION);

      _gsti_free (ctx->peer_version_string);
      err = gsti_bstr_make (&ctx->peer_version_string, data, pos);
      if (err)
	return err;

      /* Transform to the next state, which is the KEX.  */
      err = _gsti_kex_send_init_packet (ctx);
      if (err)
	return err;
      ctx->state = FSM_kex_start;

      /* Now start to handle packet data.  */
      ctx->data_handler = _gsti_handle_packet_data;
      
      return 0;
    }

  /* As we are the client, we deal with arbitrary data the server may
     send before the ident string here.  */
  if (ctx->pre_ident_cb)
    {
      err = (*ctx->pre_ident_cb) (ctx, data, pos);
      if (err)
	return err;
    }

  return 0;
}



/* Handle an incoming packet for the context CTX on the server side.  */
static gsti_error_t
server_handle_packet (gsti_ctx_t ctx)
{
  gsti_error_t err = 0;

  _gsti_log_debug (ctx, "** FSM (server) state=%s\n",
		   state_to_string (ctx->state));

  switch (ctx->state)
    {
    case FSM_kex_start:
      switch (ctx->pkt.type)
	{
	case SSH_MSG_KEXINIT:
	  err = _gsti_kex_proc_init_packet (ctx);
	  if (!err)
	    ctx->state = FSM_kex_wait;
	  break;

	default:
	  log_error (ctx);
	  ctx->state = FSM_kex_failed;
	  err = gsti_error (GPG_ERR_INV_PACKET);
	}
      break;

    case FSM_kex_wait:
      switch (ctx->pkt.type)
	{
	case SSH_MSG_KEXDH_REPLY:
	  _gsti_log_err (ctx, "server got unexpected KEXDH_REPLY\n");
	  err = gsti_error (GPG_ERR_PROTOCOL_VIOLATION);
	  break;
                  
	case SSH_MSG_KEX_DH_GEX_REQUEST:
	  err = _gsti_kex_proc_gex_request (ctx);
	  if (!err)
	    err = _gsti_kex_send_gex_group (ctx);
	  if (!err)
	    {
	      _gsti_log_debug (ctx, "KEX: enable DH group exchange\n");
	      ctx->gex.used = 1;
	    }
	  break;

	case SSH_MSG_KEXDH_INIT:
	case SSH_MSG_KEX_DH_GEX_INIT:
	  err = kex_proc_kexdh_init (ctx);
	  if (!err)
	    err = kex_send_kexdh_reply (ctx);
	  if (!err)
	    err = kex_send_newkeys (ctx);
	  if (!err)
	    ctx->state = FSM_kex_wait_newkeys;
	  break;

	default:
	  log_error (ctx);
	  ctx->state = FSM_kex_failed;
	  err = gsti_error (GPG_ERR_INV_PACKET);
	}
      break;

    case FSM_kex_wait_newkeys:
      switch (ctx->pkt.type)
	{
	case SSH_MSG_NEWKEYS:
	  err = kex_proc_newkeys (ctx);
	  if (!err)
	    ctx->state = FSM_wait_service_request;
	  break;

	default:
	  log_error (ctx);
	  ctx->state = FSM_kex_failed;
	  err = gsti_error (GPG_ERR_INV_PACKET);
	}
      break;

    case FSM_wait_service_request:
      switch (ctx->pkt.type)
	{
	case SSH_MSG_SERVICE_REQUEST:
	  err = kex_proc_service_request (ctx);
	  if (!err)
	    err = kex_send_service_accept (ctx);
	  if (!err)
	    {
	      _gsti_log_info (ctx, "service `");
	      _gsti_print_string (ctx, gsti_bstr_data (ctx->service_name),
				  gsti_bstr_length (ctx->service_name));
	      _gsti_log_cont (ctx, "' has been started (server)\n");
	      ctx->state = FSM_auth_wait;
	    }
	  break;

	default:
	  log_error (ctx);
	  ctx->state = FSM_kex_failed;
	  err = gsti_error (GPG_ERR_INV_PACKET);
	}
      break;

    case FSM_auth_wait:
      switch (ctx->pkt.type)
	{
	case SSH_MSG_USERAUTH_REQUEST:
	  err = _gsti_auth_proc_request_packet (ctx);
	  if (!err)
            err = _gsti_auth_run_auth_cb (ctx);
          if (!err && ctx->banner)
            err = _gsti_auth_send_banner_packet (ctx);
	  if (!err)
            err = _gsti_auth_send_pkok_packet (ctx);

          if (!err)
            ctx->state = FSM_auth_wait_request;
          else
	    err = _gsti_auth_send_failure_packet (ctx, ctx->auth);
	  break;
	  
	default:
	  log_error (ctx);
	  ctx->state = FSM_auth_failed;
	  err = gsti_error (GPG_ERR_INV_PACKET);
	}
      break;

    case FSM_auth_wait_request:
      switch (ctx->pkt.type)
	{
	case SSH_MSG_USERAUTH_REQUEST:
	  err = _gsti_auth_proc_request_packet (ctx);
	  if (!err)
	    err = _gsti_auth_send_success_packet (ctx);
	  if (!err)
	    {
	      /* Signal to the user that the connection can be used now.  */
	      if (ctx->control_cb)
		(*ctx->control_cb) (ctx, ctx->control_cb_value,
				    GSTI_CONTROL_FLAG_KEX,
				    ~GSTI_CONTROL_FLAG_KEX);
	      ctx->state = FSM_read;
	    }
	  break;
	}
      break;

    case FSM_read:
      if (ctx->pkt.type >= SSH_MSG_CHANNEL_BEGIN
	  && ctx->pkt.type <= SSH_MSG_CHANNEL_END)
	err = _gsti_handle_channel_packet (ctx);
      else if (ctx->pkt.type < SSH_MSG_USER_BEGIN)
	err = gsti_error (GPG_ERR_INV_PACKET);
      else		  
	{
	  struct gsti_pktdesc_s pkt;
	  u32 seqno = ctx->recv_seqno - 1;

	  pkt.datalen = ctx->pkt.payload_len;
	  pkt.data = ctx->pkt.payload;
	  pkt.seqno = seqno;

	  if (ctx->user_pkt_handler_cb)
	    err = (*ctx->user_pkt_handler_cb) (ctx,
					       ctx->user_pkt_handler_cb_value,
					       &pkt);
	}
      break;

    default:
      log_state_error (ctx);
      err = gsti_error (GPG_ERR_BUG);
    }
  return err;
}


/* Handle an incoming packet for the context CTX on the client side.  */
static gsti_error_t
client_handle_packet (gsti_ctx_t ctx)
{
  gsti_error_t err = 0;

  _gsti_log_debug (ctx, "** FSM (client) state=%s\n",
		   state_to_string (ctx->state));

  switch (ctx->state)
    {
    case FSM_kex_start:
      err = _gsti_kex_proc_init_packet (ctx);
      if (!err && ctx->gex.used)
	{
	  err = _gsti_kex_send_gex_request (ctx);
	  if (!err)
	    ctx->state = FSM_kex_wait_gex;

	}
      else
	{
	  if (!err)
	    err = kex_send_kexdh_reply (ctx);
	  if (!err)
	    ctx->state = FSM_kex_wait;
	}
      break;

    case FSM_kex_wait_gex:
      switch (ctx->pkt.type)
	{
	case SSH_MSG_KEX_DH_GEX_GROUP:
	  err = _gsti_kex_proc_gex_group (ctx);
	  if (!err)
	    err = _gsti_kex_send_kexdh_init (ctx);
	  if (!err)
	    ctx->state = FSM_kex_wait;
	  break;

	default:
	  _gsti_log_err (ctx,  "client got wrong packet "
			 "(pkttype=%d)\n",
			 ctx->pkt.type);
	  err = gsti_error (GPG_ERR_PROTOCOL_VIOLATION);
	  break; 
	}
      break;

    case FSM_kex_wait:
      switch (ctx->pkt.type)
	{
	case SSH_MSG_KEXDH_INIT:
	  _gsti_log_err (ctx, "client got unexpected KEXDH_INIT\n");
	  err = gsti_error (GPG_ERR_PROTOCOL_VIOLATION);
	  break;

	case SSH_MSG_KEXDH_REPLY:
	  err = kex_proc_kexdh_reply (ctx);
	  if (!err)
	    err = kex_send_newkeys (ctx);
	  if (!err)
	    ctx->state = FSM_kex_wait_newkeys;
	  break;
	}
      break;

    case FSM_kex_wait_newkeys:
      switch (ctx->pkt.type)
	{
	case SSH_MSG_NEWKEYS:
	  err = kex_proc_newkeys (ctx);
	  if (!err)
	    {
	      _gsti_log_info (ctx, "is local service? (%d)\n",
			      ctx->local_services ? 1 : 0);
	      err = kex_send_service_request (ctx, ctx->local_services ?
					      ctx->local_services->d
					      : "ssh-userauth");
	      _gsti_log_cont (ctx, "\n");
	      if (!err)
		ctx->state = FSM_wait_service_accept;
	    }
	  break;
	  
	default:
	  log_error (ctx);
	  ctx->state = FSM_kex_failed;
	  err = gsti_error (GPG_ERR_INV_PACKET);
	}
      break;

    case FSM_wait_service_accept:
      switch (ctx->pkt.type)
	{
	case SSH_MSG_SERVICE_ACCEPT:
	  err = kex_proc_service_accept (ctx);
	  if (!err)
	    {
	      _gsti_log_info (ctx, "service `");
	      _gsti_print_string (ctx, gsti_bstr_data (ctx->service_name),
				  gsti_bstr_length (ctx->service_name));
	      _gsti_log_cont (ctx, "' has been started (client)\n");

	      err = _gsti_auth_send_request_packet (ctx);
	      if (!err)
		ctx->state = FSM_auth_wait_pkok;
	    }
	  break;

	default:
	  log_error (ctx);
	  ctx->state = FSM_kex_failed;
	  err = gsti_error (GPG_ERR_INV_PACKET);
	}
      break;

    case FSM_auth_wait_pkok:
      switch (ctx->pkt.type)
	{
	case SSH_MSG_USERAUTH_BANNER:
	  err = _gsti_auth_proc_banner_packet (ctx);
	  if (!err)
            err = _gsti_banner_run_auth_cb (ctx);
	  break;
                  
	case SSH_MSG_USERAUTH_PK_OK:
	  err = _gsti_auth_proc_pkok_packet (ctx);
	  if (!err)
	    {
	      err = _gsti_auth_send_request_packet (ctx);
	      if (!err)
		ctx->state = FSM_auth_wait_success;
	    }
	  break;

	case SSH_MSG_USERAUTH_FAILURE:
	  _gsti_log_err (ctx, "user authentication failure\n");
	  ctx->state = FSM_auth_failed;
	  err = gsti_error (GPG_ERR_INV_NAME);
	  break;

	default:
	  log_error (ctx);
	  ctx->state = FSM_auth_failed;
	  err = gsti_error (GPG_ERR_INV_PACKET);
	}
      break;

    case FSM_auth_wait_success:
      switch (ctx->pkt.type)
	{
	case SSH_MSG_USERAUTH_SUCCESS:
	  err = _gsti_auth_proc_success_packet (ctx);
	  if (!err)
	    {
	      /* Signal to the user that the connection can be used now.  */
	      if (ctx->control_cb)
		(*ctx->control_cb) (ctx, ctx->control_cb_value,
				    GSTI_CONTROL_FLAG_KEX,
				    ~GSTI_CONTROL_FLAG_KEX);

	      ctx->state = FSM_read;
	    }
	  break;

	default:
	  log_error (ctx);
	  ctx->state = FSM_auth_failed;
	  err = gsti_error (GPG_ERR_INV_PACKET);
	}
      break;

    case FSM_read:
      if (ctx->pkt.type >= SSH_MSG_CHANNEL_BEGIN
	  && ctx->pkt.type <= SSH_MSG_CHANNEL_END)
	err = _gsti_handle_channel_packet (ctx);
      else if (ctx->pkt.type < SSH_MSG_USER_BEGIN)
	err = gsti_error (GPG_ERR_INV_PACKET);
      else		  
	{
	  struct gsti_pktdesc_s pkt;
	  u32 seqno = ctx->recv_seqno - 1;

	  pkt.datalen = ctx->pkt.payload_len;
	  pkt.data = ctx->pkt.payload;
	  pkt.seqno = seqno;

	  if (ctx->user_pkt_handler_cb)
	    err = (*ctx->user_pkt_handler_cb) (ctx,
					       ctx->user_pkt_handler_cb_value,
					       &pkt);
	}
      break;

    default:
      log_state_error (ctx);
      err = gsti_error (GPG_ERR_BUG);
    }
  return err;
}


/* Set the control callback handler for the context CTX to CONTROL_CB.
   CONTROL_CB_VALUE is passed to each invocation of this control
   callback handler.  */
gsti_error_t
gsti_set_control_cb (gsti_ctx_t ctx,
		     gsti_control_cb_t control_cb, void *control_cb_value)
{
  ctx->control_cb = control_cb;
  ctx->control_cb_value = control_cb_value;

  return 0;
}


/* Set the packet handler callback handler for the context CTX to
   PACKET_HANDLER_CB.  PACKET_HANDLER_CB_VALUE is passed to each
   invocation of this packet handler callback handler.  */
gsti_error_t
gsti_set_packet_handler_cb (gsti_ctx_t ctx,
			    gsti_packet_handler_cb_t packet_handler_cb,
			    void *packet_handler_cb_value)
{
  ctx->user_pkt_handler_cb = packet_handler_cb;
  ctx->user_pkt_handler_cb_value = packet_handler_cb_value;

  return 0;
}


/* Set the pre-identification-string callback handler for the context
   CTX to PRE_IDENT_CB.  PRE_IDENT_CB_VALUE is passed to each
   invocation of this callback handler.  */
gsti_error_t
gsti_set_pre_ident_cb (gsti_ctx_t ctx,
		       gsti_pre_ident_cb_t pre_ident_cb,
		       void *pre_ident_cb_value)
{
  ctx->pre_ident_cb = pre_ident_cb;
  ctx->pre_ident_cb_value = pre_ident_cb_value;

  return 0;
}


/* Initiate a connection to the other side over the context CTX.  */
gsti_error_t
gsti_start (gsti_ctx_t ctx)
{
  gsti_error_t err;

  if (!ctx->writefnc)
    return gsti_error (GPG_ERR_INV_ARG);

  err = _gsti_write_stream_new (&ctx->write_stream,
                                ctx->writefnc, ctx->writectx);
  if (err)
      return err;

  ctx->state = FSM_wait_on_version;
  ctx->data_handler = handle_ident_data;
  if (ctx->we_are_server)
    ctx->packet_handler = server_handle_packet;
  else
    ctx->packet_handler = client_handle_packet;

  /* Signal to the user that the connection is blocked for internal
     use for now.  */
  if (ctx->control_cb)
    (*ctx->control_cb) (ctx, ctx->control_cb_value, GSTI_CONTROL_FLAG_KEX,
			GSTI_CONTROL_FLAG_KEX);

  /* Initiate the connection by sending the version string.  */
  return _gsti_kex_send_version (ctx);
}


/* Push the incoming data, which consists of DATA_LEN bytes starting
   at the address DATA, into the context CTX and process it.  */
gsti_error_t
gsti_push_data (gsti_ctx_t ctx, void *data, size_t data_len)
{
  gsti_error_t err;
  size_t amount;

  if (!data_len)
    {
      /* FIXME: This is our close signal.  Clean up some stuff, like
	 channels.  */
      return 0;
    }

  if (ctx->state_data_alloc < ctx->state_data_len + data_len)
    {
      size_t new_data_len = ctx->state_data_len + data_len;
      void *new_data = realloc (ctx->state_data, new_data_len);

      if (!new_data)
	return gsti_error_from_errno (errno);

      ctx->state_data = new_data;
      ctx->state_data_alloc = new_data_len;
    }

  memcpy (&ctx->state_data[ctx->state_data_len], data, data_len);
  ctx->state_data_len += data_len;

  do
    {
      err = (*ctx->data_handler) (ctx, ctx->state_data, ctx->state_data_len,
				  &amount);
      if (!err && amount != 0)
	{
	  ctx->state_data_len -= amount;
	  memmove (ctx->state_data, ctx->state_data + amount,
		   ctx->state_data_len);
	}
    }
  while (!err && ctx->state_data_len && amount);

  return err;
}
