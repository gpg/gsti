/* channel.c - Channel API.
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
#include <errno.h>
#include <assert.h>

#include "gsti.h"

#include "packet.h"
#include "buffer.h"
#include "api.h"



typedef enum
  {
    /* The channel ID is unused and free for allocation.  */
    GSTI_CHANNEL_STATE_FREE,

    /* The channel ID is allocated and will soon be used.  */
    GSTI_CHANNEL_STATE_ALLOCATED,

    /* The channel is currently in the process of being opened by us.  */
    GSTI_CHANNEL_STATE_PENDING_REQUEST,

    /* The channel is currently in the process of being opened by the
       other end.  */
    GSTI_CHANNEL_STATE_IN_REPLY,

    /* The channel is open.  */
    GSTI_CHANNEL_STATE_OPEN,

    /* The channel was closed by us, and we are waiting for the close
       by the other end. */
    GSTI_CHANNEL_STATE_CLOSED
  }
gsti_channel_state_t;


/* A structure that holds the information for a single active
   channel.  */
struct gsti_channel
{
  /* The channel state.  */
  gsti_channel_state_t state;

  /* True if we have seen an EOF by the other end.  */
  unsigned int rec_eof;

  /* True if we have sent an EOF.  */
  unsigned int eof;
  
  /* Our channel number.  */
  unsigned int sender_channel;

  /* Our window size.  */
  unsigned int window_size;

  /* Our maximum packet size.  */
  unsigned int max_packet_size;

  /* The channel number of the other end.  */
  unsigned int recipient_channel;

  /* The window size of the other end.  */
  unsigned int rec_window_size;

  /* The maximum packet size of the other end.  */
  unsigned int rec_max_packet_size;

  /* The channel type.  */
  gsti_channel_type_t chan_type;

  /* The read callback for this channel.  */
  gsti_channel_read_cb_t read_cb;
  void *read_cb_value;

  /* The request callback for this channel.  */
  gsti_channel_request_cb_t request_cb;
  void *request_cb_value;

  /* The window adjustment callback for this channel.  */
  gsti_channel_win_adj_cb_t win_adj_cb;
  void *win_adj_cb_value;

  /* The EOF callback for this channel.  */
  gsti_channel_eof_cb_t eof_cb;
  void *eof_cb_value;

  /* The close callback for this channel.  */
  gsti_channel_close_cb_t close_cb;
  void *close_cb_value;

  /* The open result handler.  Only valid for channels opened by us.  */
  gsti_channel_open_result_cb_t open_result_cb;
  void *open_result_cb_value;
};



/* The number of new channels in each allocation round.  */
#define CHANNEL_INC 16

static gsti_error_t
channel_alloc (gsti_ctx_t ctx, gsti_channel_t *r_channel)
{
  unsigned int nr;
  gsti_channel_t channel;

  if (ctx->nr_channels < ctx->max_channels)
    {
      /* There is a free channel somewhere.  Search for it.  */
      for (nr = 0; nr < ctx->max_channels; nr++)
	if (ctx->channels[nr].state == GSTI_CHANNEL_STATE_FREE)
	  break;
      assert (nr < ctx->max_channels);
    }
  else
    {
      size_t new_number = ctx->max_channels + CHANNEL_INC;
      gsti_channel_t new_channels;

      if (ctx->channels)
	new_channels = realloc (ctx->channels,
				new_number * sizeof (struct gsti_channel));
      else
	new_channels = malloc (new_number * sizeof (struct gsti_channel));

      if (!new_channels)
	return gsti_error_from_errno (errno);

      for (nr = ctx->max_channels; nr < new_number; nr++)
	new_channels[nr].state = GSTI_CHANNEL_STATE_FREE;

      /* The first free one is the first new one.  */
      nr = ctx->max_channels;

      ctx->max_channels = new_number;
      ctx->channels = new_channels;
    }

  /* NR contains the free channel number now.  */
  ctx->nr_channels++;

  channel = &ctx->channels[nr];
  memset (channel, 0, sizeof (*channel));

  channel->state = GSTI_CHANNEL_STATE_ALLOCATED;
  channel->sender_channel = nr;

  *r_channel = channel;
  return 0;
}


static void
channel_dealloc (gsti_ctx_t ctx, gsti_channel_t channel)
{
  channel->state = GSTI_CHANNEL_STATE_FREE;
  ctx->nr_channels--;
}


static gsti_channel_t
channel_lookup (gsti_ctx_t ctx, gsti_uint32_t channel_id)
{
  gsti_channel_t channel;

  if (channel_id >= ctx->max_channels)
    return NULL;

  channel = &ctx->channels[channel_id]; 
  if (channel->state == GSTI_CHANNEL_STATE_FREE)
    return NULL;

  return channel;
}


/* A structure that holds the information for a single channel
   type.  */
struct gsti_channel_type
{
  /* The next pointer for the linked list of channel types.  */
  gsti_channel_type_t next;

  /* A string identifying the channel type.  */
  char *name;

  /* The open callback and its hook.  */
  gsti_channel_open_cb_t open_cb;
  void *open_cb_value;
};



/* Register a new channel type with the type name NAME for the context
   CTX.  The channel uses the specified open callback with the given
   hook value.  This allows the other end of a connection to attempt
   to open a channel with this type.  */
gsti_error_t
gsti_channel_add_type (gsti_ctx_t ctx, const char *name,
		       gsti_channel_open_cb_t open_cb, void *open_cb_value)
{
  gsti_channel_type_t chan_type;

  chan_type = calloc (1, sizeof (*chan_type));
  if (!chan_type)
    return gsti_error_from_errno (errno);

  chan_type->name = strdup (name);
  if (!chan_type->name)
    {
      gsti_error_t err = gsti_error_from_errno (errno);

      free (chan_type);
      return err;
    }
  chan_type->open_cb = open_cb;
  chan_type->open_cb_value = open_cb_value;

  chan_type->next = ctx->channel_types;
  ctx->channel_types = chan_type;

  return 0;
}


/* Return our current window size for the channel CHANNEL_ID in CTX.  */
size_t
gsti_channel_get_window_size (gsti_ctx_t ctx, gsti_uint32_t channel_id)
{
  gsti_channel_t channel = channel_lookup (ctx, channel_id);

  if (!channel)
    return 0;
  else
    return channel->window_size;
}


/* Return our maximum packet size for the channel CHANNEL_ID in CTX.  */
size_t
gsti_channel_get_max_packet_size (gsti_ctx_t ctx, gsti_uint32_t channel_id)
{
  gsti_channel_t channel = channel_lookup (ctx, channel_id);

  if (!channel)
    return 0;
  else
    return channel->max_packet_size;
}


/* Return the current window size of the other end for the channel
   CHANNEL_ID in CTX.  */
size_t
gsti_channel_get_rec_window_size (gsti_ctx_t ctx, gsti_uint32_t channel_id)
{
  gsti_channel_t channel = channel_lookup (ctx, channel_id);

  if (!channel)
    return 0;
  else
    return channel->rec_window_size;
}


/* Return the maximum packet size of the other end for the channel
   CHANNEL_ID in CTX.  */
size_t
gsti_channel_get_rec_max_packet_size (gsti_ctx_t ctx, gsti_uint32_t channel_id)
{
  gsti_channel_t channel = channel_lookup (ctx, channel_id);

  if (!channel)
    return 0;
  else
    return channel->rec_max_packet_size;
}


/* The SSH_MSG_CHANNEL_OPEN_CONFIRMATION message, client side.  */
static gsti_error_t
ssh_msg_channel_open_confirmation (gsti_ctx_t ctx,
				   gsti_uint32_t recipient_channel,
				   gsti_uint32_t sender_channel,
				   gsti_uint32_t initial_window_size,
				   gsti_uint32_t maximum_packet_size,
				   gsti_byte_t *data, size_t data_len)
{
  gsti_error_t err;
  gsti_buffer_t buf;
  size_t buflen;

  /* Build message.  */
  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putbyte (buf, SSH_MSG_CHANNEL_OPEN_CONFIRMATION);
  if (!err)
    err = gsti_buf_putuint32 (buf, recipient_channel);
  if (!err)
    err = gsti_buf_putuint32 (buf, sender_channel);
  if (!err)
    err = gsti_buf_putuint32 (buf, initial_window_size);
  if (!err)
    err = gsti_buf_putuint32 (buf, maximum_packet_size);
  if (!err)
    err = gsti_buf_putraw (buf, data, data_len);
  if (err)
    {
      gsti_buf_free (buf);
      return err;
    }

  /* Protect against buffer overflow.  */
  buflen = gsti_buf_readable (buf);
  if (buflen > ctx->pkt.size)
    {
      gsti_buf_free (buf);
      return gsti_error (GPG_ERR_TOO_LARGE);
    }

  /* Set up the packet.  */
  ctx->pkt.type = SSH_MSG_CHANNEL_OPEN_CONFIRMATION;
  ctx->pkt.payload_len = buflen;
  err = gsti_buf_getraw (buf, ctx->pkt.payload, buflen);
  assert (!err);
  gsti_buf_free (buf);

  /* Send the packet.  */
  err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);

  return err;
}


typedef struct
{
  unsigned int recipient_channel;
  unsigned int sender_channel;
  unsigned int initial_window_size;
  unsigned int maximum_packet_size;
} ssh_msg_channel_open_confirmation_t;


/* The SSH_MSG_CHANNEL_OPEN_CONFIRMATION message, receiver side.  */
static gsti_error_t
ssh_msg_channel_open_confirmation_S (gsti_ctx_t ctx)
{
  gsti_error_t err;
  ssh_msg_channel_open_confirmation_t chan_open_confirm;
  gsti_channel_t channel;

  err = gsti_buf_getuint32 (ctx->pktbuf, &chan_open_confirm.recipient_channel);
  if (!err)
    err = gsti_buf_getuint32 (ctx->pktbuf, &chan_open_confirm.sender_channel);
  if (!err)
    err = gsti_buf_getuint32 (ctx->pktbuf,
			      &chan_open_confirm.initial_window_size);
  if (!err)
    err = gsti_buf_getuint32 (ctx->pktbuf,
			      &chan_open_confirm.maximum_packet_size);
  if (err)
    return err;

  channel = channel_lookup (ctx, chan_open_confirm.recipient_channel);
  if (!channel || channel->state != GSTI_CHANNEL_STATE_PENDING_REQUEST)
    {
      /* FIXME: Ignore invalid confirmation?  */
      return 0;
    }

  channel->recipient_channel = chan_open_confirm.sender_channel;
  channel->rec_window_size = chan_open_confirm.initial_window_size;
  channel->rec_max_packet_size = chan_open_confirm.maximum_packet_size;
  channel->state = GSTI_CHANNEL_STATE_OPEN;

  /* Inform the user about it.  */
  (*channel->open_result_cb) (ctx, channel->sender_channel,
			      channel->open_result_cb_value, 0,
			      gsti_buf_getptr (ctx->pktbuf),
			      gsti_buf_readable (ctx->pktbuf));

  if (channel->rec_window_size)
    {
      /* Inform the user about the initial window size.  */

      if (channel->win_adj_cb)
	(*channel->win_adj_cb) (ctx, channel->sender_channel,
				channel->win_adj_cb_value,
				channel->rec_window_size);
    }

  return 0;
}


/* The SSH_MSG_CHANNEL_OPEN_FAILURE message, client side.  */
static gsti_error_t
ssh_msg_channel_open_failure (gsti_ctx_t ctx,
			      gsti_uint32_t recipient_channel,
			      gsti_uint32_t reason_code,
			      const char *additional_text,
			      const char *language_tag)
{
  gsti_error_t err;
  gsti_buffer_t buf;
  size_t buflen;

  /* Build message.  */
  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putbyte (buf, SSH_MSG_CHANNEL_OPEN_FAILURE);
  if (!err)
    err = gsti_buf_putuint32 (buf, recipient_channel);
  if (!err)
    err = gsti_buf_putuint32 (buf, reason_code);
  if (!err)
    err = gsti_buf_putstr (buf, additional_text, strlen (additional_text));
  if (!err)
    err = gsti_buf_putraw (buf, language_tag, strlen (language_tag));
  if (err)
    {
      gsti_buf_free (buf);
      return err;
    }

  /* Protect against buffer overflow.  */
  buflen = gsti_buf_readable (buf);
  if (buflen > ctx->pkt.size)
    {
      gsti_buf_free (buf);
      return gsti_error (GPG_ERR_TOO_LARGE);
    }

  /* Set up the packet.  */
  ctx->pkt.type = SSH_MSG_CHANNEL_OPEN_FAILURE;
  ctx->pkt.payload_len = buflen;
  err = gsti_buf_getraw (buf, ctx->pkt.payload, buflen);
  assert (!err);
  gsti_buf_free (buf);

  /* Send the packet.  */
  err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);

  return err;
}


/* The SSH_MSG_CHANNEL_OPEN_FAILURE message format.  */
typedef struct
{
  unsigned int recipient_channel;
  unsigned int reason_code;
} ssh_msg_channel_open_failure_t;


/* The SSH_MSG_CHANNEL_OPEN_FAILURE message, receiver side.  */
static gsti_error_t
ssh_msg_channel_open_failure_S (gsti_ctx_t ctx)
{
  gsti_error_t err;
  ssh_msg_channel_open_failure_t chan_open_fail;
  gsti_channel_t channel;

  err = gsti_buf_getuint32 (ctx->pktbuf, &chan_open_fail.recipient_channel);
  if (!err)
    err = gsti_buf_getuint32 (ctx->pktbuf, &chan_open_fail.reason_code);
  /* FIXME: Handle additional text and language tag.  */
  if (err)
    return err;

  channel = channel_lookup (ctx, chan_open_fail.recipient_channel);
  if (!channel || channel->state != GSTI_CHANNEL_STATE_PENDING_REQUEST)
    {
      /* FIXME: Ignore invalid failure message?  */
      return 0;
    }

  /* Inform the user about it.  FIXME: Support diagnostic message.  */
  (*channel->open_result_cb) (ctx, channel->sender_channel,
			      channel->open_result_cb_value,
			      chan_open_fail.reason_code,
			      NULL, 0);

  /* Deallocate the channel.  */
  channel_dealloc (ctx, channel);

  return 0;
}


/* The SSH_MSG_CHANNEL_OPEN message, client side.  */
static gsti_error_t
ssh_msg_channel_open (gsti_ctx_t ctx, const char *channel_type,
		      unsigned int sender_channel,
		      unsigned int initial_window_size,
		      unsigned int maximum_packet_size)
{
  gsti_error_t err;
  gsti_buffer_t buf;
  size_t buflen;

  /* Build message.  */
  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putbyte (buf, SSH_MSG_CHANNEL_OPEN);
  if (!err)
    err = gsti_buf_putstr (buf, channel_type, strlen (channel_type));
  if (!err)
    err = gsti_buf_putuint32 (buf, sender_channel);
  if (!err)
    err = gsti_buf_putuint32 (buf, initial_window_size);
  if (!err)
    err = gsti_buf_putuint32 (buf, maximum_packet_size);
  if (err)
    {
      gsti_buf_free (buf);
      return err;
    }

  /* Protect against buffer overflow.  */
  buflen = gsti_buf_readable (buf);
  if (buflen > ctx->pkt.size)
    {
      gsti_buf_free (buf);
      return gsti_error (GPG_ERR_TOO_LARGE);
    }

  /* Set up the packet.  */
  ctx->pkt.type = SSH_MSG_CHANNEL_OPEN;
  ctx->pkt.payload_len = buflen;
  err = gsti_buf_getraw (buf, ctx->pkt.payload, buflen);
  assert (!err);
  gsti_buf_free (buf);

  /* Send the packet.  */
  err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);

  return err;
}


/* The SSH_MSG_CHANNEL_OPEN message format.  */
typedef struct
{
  char *channel_type;
  unsigned int sender_channel;
  unsigned int initial_window_size;
  unsigned int maximum_packet_size;
} ssh_msg_channel_open_t;


/* The SSH_MSG_CHANNEL_OPEN message, receiver side.  */
static gsti_error_t
ssh_msg_channel_open_S (gsti_ctx_t ctx)
{
  gsti_error_t err;
  ssh_msg_channel_open_t chan_open;
  gsti_channel_type_t chan_type = ctx->channel_types;
  gsti_channel_t channel;
  size_t len;

  /* FIXME: Defaults?  */
  unsigned char *reply_buffer;
  size_t reply_buffer_len = 32768;

  err = gsti_buf_getstr (ctx->pktbuf, &chan_open.channel_type, &len);
  if (!err)
    err = gsti_buf_getuint32 (ctx->pktbuf, &chan_open.sender_channel);
  if (!err)
    err = gsti_buf_getuint32 (ctx->pktbuf, &chan_open.initial_window_size);
  if (!err)
    err = gsti_buf_getuint32 (ctx->pktbuf, &chan_open.maximum_packet_size);

  while (chan_type && strcmp (chan_type->name, chan_open.channel_type))
    chan_type = chan_type->next;

  if (!chan_type)
    return ssh_msg_channel_open_failure (ctx, chan_open.sender_channel,
					 SSH_OPEN_UNKNOWN_CHANNEL_TYPE,
					 "Unknown channel type", "en");

  reply_buffer = malloc (reply_buffer_len);
  if (!reply_buffer)
    return ssh_msg_channel_open_failure (ctx, chan_open.sender_channel,
					 SSH_OPEN_RESOURCE_SHORTAGE,
					 "Resource shortage", "en");
    
  err = channel_alloc (ctx, &channel);
  if (err)
    {
      free (reply_buffer);

      return ssh_msg_channel_open_failure (ctx, chan_open.sender_channel,
					   SSH_OPEN_RESOURCE_SHORTAGE,
					   "Resource shortage", "en");
    }

  channel->state = GSTI_CHANNEL_STATE_IN_REPLY;
  channel->chan_type = chan_type;
  /* FIXME: Good default?  */
  channel->window_size = 32768;
  /* FIXME: Good default?  */
  channel->max_packet_size = 65536;

  channel->recipient_channel = chan_open.sender_channel;
  channel->rec_window_size = chan_open.initial_window_size;
  channel->rec_max_packet_size = chan_open.maximum_packet_size;

  err = (*chan_type->open_cb) (ctx, channel->sender_channel,
			       chan_type->open_cb_value,
			       gsti_buf_getptr (ctx->pktbuf),
			       gsti_buf_readable (ctx->pktbuf),
			       &channel->window_size,
			       &channel->max_packet_size,
			       reply_buffer, &reply_buffer_len,
			       &channel->read_cb,
			       &channel->read_cb_value,
			       &channel->request_cb,
			       &channel->request_cb_value,
			       &channel->win_adj_cb,
			       &channel->win_adj_cb_value,
			       &channel->eof_cb,
			       &channel->eof_cb_value,
			       &channel->close_cb,
			       &channel->close_cb_value);

  if (err)
    {
      free (reply_buffer);
      channel_dealloc (ctx, channel);

      /* FIXME: Make reason code depdendend on ERR.  */
      return
	ssh_msg_channel_open_failure (ctx, chan_open.sender_channel,
				      SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
				      "Administratively prohibited", "en");
    }

  err = ssh_msg_channel_open_confirmation (ctx, channel->recipient_channel,
					   channel->sender_channel,
					   channel->window_size,
					   channel->max_packet_size,
					   reply_buffer, reply_buffer_len);
  free (reply_buffer);
  if (err)
    channel_dealloc (ctx, channel);
  else
    channel->state = GSTI_CHANNEL_STATE_OPEN;

  return err;
}


/* The SSH_MSG_CHANNEL_WINDOW_ADJUST message, client side.  */
static gsti_error_t
ssh_msg_channel_window_adjust (gsti_ctx_t ctx,
			       gsti_uint32_t sender_channel,
			       gsti_uint32_t bytes_to_add)
{
  gsti_error_t err;
  gsti_buffer_t buf;
  size_t buflen;

  /* Build message.  */
  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putbyte (buf, SSH_MSG_CHANNEL_WINDOW_ADJUST);
  if (!err)
    err = gsti_buf_putuint32 (buf, sender_channel);
  if (!err)
    err = gsti_buf_putuint32 (buf, bytes_to_add);
  if (err)
    {
      gsti_buf_free (buf);
      return err;
    }

  /* Protect against buffer overflow.  */
  buflen = gsti_buf_readable (buf);
  if (buflen > ctx->pkt.size)
    {
      gsti_buf_free (buf);
      return gsti_error (GPG_ERR_TOO_LARGE);
    }

  /* Set up the packet.  */
  ctx->pkt.type = SSH_MSG_CHANNEL_WINDOW_ADJUST;
  ctx->pkt.payload_len = buflen;
  err = gsti_buf_getraw (buf, ctx->pkt.payload, buflen);
  assert (!err);
  gsti_buf_free (buf);

  /* Send the packet.  */
  err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);

  return err;
}


typedef struct
{
  unsigned int recipient_channel;
  unsigned int bytes_to_add;
} ssh_msg_channel_window_adjust_t;


static gsti_error_t
ssh_msg_channel_window_adjust_S (gsti_ctx_t ctx)
{
  gsti_error_t err;
  ssh_msg_channel_window_adjust_t chan_win_adjust;
  gsti_channel_t channel;

  err = gsti_buf_getuint32 (ctx->pktbuf, &chan_win_adjust.recipient_channel);
  if (!err)
    err = gsti_buf_getuint32 (ctx->pktbuf, &chan_win_adjust.bytes_to_add);

  channel = channel_lookup (ctx, chan_win_adjust.recipient_channel);
  if (!channel || (channel->state != GSTI_CHANNEL_STATE_OPEN
		   && channel->state != GSTI_CHANNEL_STATE_CLOSED))
    {
      /* Do not ignore this error?  */
      return 0;
    }

  channel->rec_window_size += chan_win_adjust.bytes_to_add;

  /* Inform the user about it.  */
  if (channel->win_adj_cb)
    (*channel->win_adj_cb) (ctx, channel->sender_channel,
			    channel->win_adj_cb_value,
			    channel->rec_window_size);
  
  return 0;
}


/* The SSH_MSG_CHANNEL_DATA message, sender side.  */
static gsti_error_t
ssh_msg_channel_data (gsti_ctx_t ctx, gsti_uint32_t recipient_channel,
		      char *data, size_t amount)
{
  gsti_error_t err;
  gsti_buffer_t buf;
  size_t buflen;

  /* Build message.  */
  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putbyte (buf, SSH_MSG_CHANNEL_DATA);
  if (!err)
    err = gsti_buf_putuint32 (buf, recipient_channel);
  if (!err)
    err = gsti_buf_putraw (buf, data, amount);
  if (err)
    {
      gsti_buf_free (buf);
      return err;
    }

  /* Protect against buffer overflow.  */
  buflen = gsti_buf_readable (buf);
  if (buflen > ctx->pkt.size)
    {
      gsti_buf_free (buf);
      return gsti_error (GPG_ERR_TOO_LARGE);
    }

  /* Set up the packet.  */
  ctx->pkt.type = SSH_MSG_CHANNEL_DATA;
  ctx->pkt.payload_len = buflen;
  err = gsti_buf_getraw (buf, ctx->pkt.payload, buflen);
  assert (!err);
  gsti_buf_free (buf);

  /* Send the packet.  */
  err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);

  return err;
}


typedef struct
{
  unsigned int recipient_channel;
} ssh_msg_channel_data_t;


static gsti_error_t
ssh_msg_channel_data_S (gsti_ctx_t ctx)
{
  gsti_error_t err;
  ssh_msg_channel_data_t chan_data;
  gsti_channel_t channel;

  err = gsti_buf_getuint32 (ctx->pktbuf, &chan_data.recipient_channel);

  channel = channel_lookup (ctx, chan_data.recipient_channel);
  if (!channel || (channel->state != GSTI_CHANNEL_STATE_OPEN
		   && channel->state != GSTI_CHANNEL_STATE_CLOSED)
      || channel->rec_eof
      || channel->window_size < gsti_buf_readable (ctx->pktbuf)
      || channel->max_packet_size < gsti_buf_readable (ctx->pktbuf) + 5)
    {
      /* Note that we do NOT ignore data sent to us after we closed
	 the channel.  The SSH specification encourages us to deliver
	 as much data as possible (Connection 5.3).  */

      /* FIXME: Maybe the check for the maximum packet size is off by
	 5 bytes, if you do not count the msg id and recipient channel
	 bytes in the packet.  See comment in gsti_channel_write.  */

      /* FIXME: Should we ignore the problem?  */
      return 0;
    }

  channel->window_size -= gsti_buf_readable (ctx->pktbuf);
  
  /* Inform the user about it.  */
  (*channel->read_cb) (ctx, channel->sender_channel,
		       channel->read_cb_value, gsti_buf_getptr (ctx->pktbuf),
		       gsti_buf_readable (ctx->pktbuf));
  
  return 0;
}


/* The SSH_MSG_CHANNEL_EOF message, sender side.  */
static gsti_error_t
ssh_msg_channel_eof (gsti_ctx_t ctx, gsti_uint32_t recipient_channel)
{
  gsti_error_t err;
  gsti_buffer_t buf;
  size_t buflen;

  /* Build message.  */
  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putbyte (buf, SSH_MSG_CHANNEL_EOF);
  if (!err)
    err = gsti_buf_putuint32 (buf, recipient_channel);
  if (err)
    {
      gsti_buf_free (buf);
      return err;
    }

  /* Protect against buffer overflow.  */
  buflen = gsti_buf_readable (buf);
  if (buflen > ctx->pkt.size)
    {
      gsti_buf_free (buf);
      return gsti_error (GPG_ERR_TOO_LARGE);
    }

  /* Set up the packet.  */
  ctx->pkt.type = SSH_MSG_CHANNEL_EOF;
  ctx->pkt.payload_len = buflen;
  err = gsti_buf_getraw (buf, ctx->pkt.payload, buflen);
  assert (!err);
  gsti_buf_free (buf);

  /* Send the packet.  */
  err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);

  return err;
}


typedef struct
{
  unsigned int recipient_channel;
} ssh_msg_channel_eof_t;


static gsti_error_t
ssh_msg_channel_eof_S (gsti_ctx_t ctx)
{
  gsti_error_t err;
  ssh_msg_channel_data_t chan_data;
  gsti_channel_t channel;

  err = gsti_buf_getuint32 (ctx->pktbuf, &chan_data.recipient_channel);

  channel = channel_lookup (ctx, chan_data.recipient_channel);
  if (!channel || (channel->state != GSTI_CHANNEL_STATE_OPEN
		   && channel->state != GSTI_CHANNEL_STATE_CLOSED)
      || channel->rec_eof)

    {
      /* FIXME: Should we ignore the problem?  */
      return 0;
    }

  /* Set the recipient EOF flag for this channel.  */
  channel->rec_eof = 1;

  /* Inform the user about it.  */
  (*channel->eof_cb) (ctx, channel->sender_channel, channel->eof_cb_value);
  
  return 0;
}


/* The SSH_MSG_CHANNEL_CLOSE message, sender side.  */
static gsti_error_t
ssh_msg_channel_close (gsti_ctx_t ctx, gsti_uint32_t recipient_channel)
{
  gsti_error_t err;
  gsti_buffer_t buf;
  size_t buflen;

  /* Build message.  */
  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putbyte (buf, SSH_MSG_CHANNEL_CLOSE);
  if (!err)
    err = gsti_buf_putuint32 (buf, recipient_channel);
  if (err)
    {
      gsti_buf_free (buf);
      return err;
    }

  /* Protect against buffer overflow.  */
  buflen = gsti_buf_readable (buf);
  if (buflen > ctx->pkt.size)
    {
      gsti_buf_free (buf);
      return gsti_error (GPG_ERR_TOO_LARGE);
    }

  /* Set up the packet.  */
  ctx->pkt.type = SSH_MSG_CHANNEL_CLOSE;
  ctx->pkt.payload_len = buflen;
  err = gsti_buf_getraw (buf, ctx->pkt.payload, buflen);
  assert (!err);
  gsti_buf_free (buf);

  /* Send the packet.  */
  err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);

  return err;
}


typedef struct
{
  unsigned int recipient_channel;
} ssh_msg_channel_close_t;


static gsti_error_t
ssh_msg_channel_close_S (gsti_ctx_t ctx)
{
  gsti_error_t err;
  ssh_msg_channel_data_t chan_data;
  gsti_channel_t channel;

  err = gsti_buf_getuint32 (ctx->pktbuf, &chan_data.recipient_channel);

  channel = channel_lookup (ctx, chan_data.recipient_channel);
  if (!channel)
    {
      /* FIXME: Should we ignore the problem?  */
      return 0;
    }

  /* The channel was closed by the other side.  If it is not yet closed by us,
     we must do so.  */
  if (channel->state != GSTI_CHANNEL_STATE_CLOSED)
    {
      err = ssh_msg_channel_close (ctx, channel->recipient_channel);
      if (err)
	return err;

      channel->state = GSTI_CHANNEL_STATE_CLOSED;
    }

  /* Inform the user about it.  */
  if (channel->close_cb)
    (*channel->close_cb) (ctx, channel->sender_channel,
			  channel->close_cb_value);

  /* Now we are free to destroy the channel object.  */
  channel_dealloc (ctx, channel);

  return 0;
}


gsti_error_t
_gsti_handle_channel_packet (gsti_ctx_t ctx)
{
  gsti_error_t err;
  int val;

  /* Reap the packet type byte.  */
  err = gsti_buf_getc (ctx->pktbuf, &val);
  if (err)
    return err;

  switch (ctx->pkt.type)
    {
    case SSH_MSG_CHANNEL_OPEN:
      return ssh_msg_channel_open_S (ctx);

    case SSH_MSG_CHANNEL_OPEN_CONFIRMATION:
      return ssh_msg_channel_open_confirmation_S (ctx);

    case SSH_MSG_CHANNEL_OPEN_FAILURE:
      return ssh_msg_channel_open_failure_S (ctx);

    case SSH_MSG_CHANNEL_WINDOW_ADJUST:
      return ssh_msg_channel_window_adjust_S (ctx);

    case SSH_MSG_CHANNEL_DATA:
      return ssh_msg_channel_data_S (ctx);

    case SSH_MSG_CHANNEL_EOF:
      return ssh_msg_channel_eof_S (ctx);

    case SSH_MSG_CHANNEL_CLOSE:
      return ssh_msg_channel_close_S (ctx);

    default:
      ;	/* Ignore.  */
    }

  return 0;
}


/* Attempt to open a new channel in the context CTX.  Returns the
   channel number in CHANNEL_ID or an error if the operation does not
   succeed.  */
gsti_error_t
gsti_channel_open (gsti_ctx_t ctx, gsti_uint32_t *channel_id,
		   const char *channel_type, unsigned int initial_window_size,
		   unsigned int maximum_packet_size,
		   gsti_channel_open_result_cb_t open_result_cb,
		   void *open_result_cb_value,
		   gsti_channel_read_cb_t read_cb,
		   void *read_cb_value,
		   gsti_channel_request_cb_t request_cb,
		   void *request_cb_value,
		   gsti_channel_win_adj_cb_t win_adj_cb,
		   void *win_adj_cb_value,
		   gsti_channel_eof_cb_t eof_cb,
		   void *eof_cb_value,
		   gsti_channel_close_cb_t close_cb,
		   void *close_cb_value)
{
  gsti_error_t err;
  gsti_channel_t channel;

  err = channel_alloc (ctx, &channel);
  if (err)
    return err;

  channel->state = GSTI_CHANNEL_STATE_PENDING_REQUEST;
  channel->window_size = initial_window_size;
  channel->max_packet_size = maximum_packet_size;
  channel->open_result_cb = open_result_cb;
  channel->open_result_cb_value = open_result_cb_value;
  channel->read_cb = read_cb;
  channel->read_cb_value = read_cb_value;
  channel->request_cb = request_cb;
  channel->request_cb_value = request_cb_value;
  channel->win_adj_cb = win_adj_cb;
  channel->win_adj_cb_value = win_adj_cb_value;
  channel->eof_cb = eof_cb;
  channel->eof_cb_value = eof_cb_value;
  channel->close_cb = close_cb;
  channel->close_cb_value = close_cb_value;

  err = ssh_msg_channel_open (ctx, channel_type, channel->sender_channel,
			      channel->window_size, channel->max_packet_size);

  if (err)
    {
      channel_dealloc (ctx, channel);
      return err;
    }

  *channel_id = channel->sender_channel;
  return 0;
}


/* Write AMOUNT bytes of data starting from DATA to the channel
   CHANNEL_ID in the context CTX.  */
gsti_error_t
gsti_channel_write (gsti_ctx_t ctx, gsti_uint32_t channel_id,
		    char *data, size_t amount)
{
  gsti_error_t err;
  gsti_channel_t channel = channel_lookup (ctx, channel_id);

  if (!channel || channel->state != GSTI_CHANNEL_STATE_OPEN
      || channel->eof)
    return gsti_error (GPG_ERR_INV_ARG);

  /* FIXME: The check for the maximum packet size includes the five
     bytes used for the msg id and the recipient channel.  Is this
     correct?  In any case, the user does not know about this magic
     constant, so maybe subtract five from
     channel->rec_max_packet_size at setup time (and resp., add five
     bytes to channel->max_packet_size).  */
  if (channel->rec_window_size < amount
      || channel->rec_max_packet_size < amount + 5)
    return gsti_error (GPG_ERR_TOO_LARGE);

  err = ssh_msg_channel_data (ctx, channel->recipient_channel,
			      data, amount);
  if (!err)
    channel->rec_window_size -= amount;

  return err;
}


/* Increase the window size of the channel CHANNEL_ID in the context
   CTX by BYTES_TO_ADD bytes.  */
gsti_error_t
gsti_channel_window_adjust (gsti_ctx_t ctx, gsti_uint32_t channel_id,
			    gsti_uint32_t bytes_to_add)
{
  gsti_error_t err;
  gsti_channel_t channel = channel_lookup (ctx, channel_id);

  if (!channel || (channel->state != GSTI_CHANNEL_STATE_OPEN
		   && channel->state != GSTI_CHANNEL_STATE_CLOSED))
    return gsti_error (GPG_ERR_INV_ARG);

  err = ssh_msg_channel_window_adjust (ctx, channel->recipient_channel,
				       bytes_to_add);
  if (!err)
    channel->window_size += bytes_to_add;

  return err;
}


/* Send End-Of-File for this channel.  This should be done after
   sending the last byte (if the channel was not closed yet).  After
   this, no data may be sent over the channel anymore by us.  However,
   data from the other side may still be received.  */
gsti_error_t
gsti_channel_eof (gsti_ctx_t ctx, gsti_uint32_t channel_id)
{
  gsti_error_t err;
  gsti_channel_t channel = channel_lookup (ctx, channel_id);

  if (!channel || (channel->state != GSTI_CHANNEL_STATE_OPEN
		   && channel->state != GSTI_CHANNEL_STATE_CLOSED)
      || channel->eof)
    return gsti_error (GPG_ERR_INV_ARG);

  err = ssh_msg_channel_eof (ctx, channel->recipient_channel);
  if (!err)
    channel->eof = 1;

  return err;
}


/* Send request to close the channel.  */
gsti_error_t
gsti_channel_close (gsti_ctx_t ctx, gsti_uint32_t channel_id)
{
  gsti_error_t err;
  gsti_channel_t channel = channel_lookup (ctx, channel_id);

  if (!channel || channel->state != GSTI_CHANNEL_STATE_OPEN)
    return gsti_error (GPG_ERR_INV_ARG);

  err = ssh_msg_channel_close (ctx, channel->recipient_channel);

  if (!err)
    channel->state = GSTI_CHANNEL_STATE_CLOSED;

  return err;
}
