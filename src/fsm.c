/* fsm.c - state machine for the transport protocol
 *	Copyright (C) 1999 Werner Koch
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
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <config.h>
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

#define logrc _gsti_log_rc

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


/**************** 
 * Do some initialization 
 */
static int
handle_init (GSTIHD hd, int want_read)
{
  int rc = 0;

  if (!hd->readfnc || !hd->writefnc)
    return GSTI_INV_ARG;
  hd->read_stream = _gsti_read_stream_new (hd->readfnc);
  hd->write_stream = _gsti_write_stream_new (hd->writefnc);
  if (want_read)
    {				/* be the server side */
      hd->we_are_server = 1;
      hd->state = FSM_wait_on_version;
    }
  else
    {				/* be the client side  */
      hd->we_are_server = 0;
      hd->state = FSM_send_version;
    }
  return rc;
}



/**************** 
 * Cleanup the connection we are about to quit. 
 */
static int
handle_quit (GSTIHD hd)
{
  int rc = 0;

  return rc;
}


static void
log_error (GSTIHD hd)
{
  _gsti_log_info ("FSM: at new_state: state=%d, packet=%d\n",
		  hd->state, hd->pkt.type);
}


static int
request_packet (GSTIHD hd)
{
  int rc;
  int pkttype = 0;

  do
    {
      rc = _gsti_packet_read (hd);
      if (rc)
	_gsti_log_info ("FSM: read packet at state %d failed: %s\n",
			hd->state, gsti_strerror (rc));
      else
	pkttype = hd->pkt.type;
    }
  while (!rc && (pkttype == SSH_MSG_DEBUG || pkttype == SSH_MSG_IGNORE));
  return rc;
}


static int
fsm_server_loop (GSTIHD hd)
{
  int rc = 0;

  switch (hd->state)
    {
    case FSM_init:
      rc = handle_init (hd, 1);
      break;
    case FSM_idle:
      hd->state = FSM_read;
      break;
    default:
      _gsti_log_info ("FSM: start fsm_loop: invalid state %d\n", hd->state);
      rc = GSTI_BUG;
      break;
    }

  while (!rc && hd->state != FSM_quit && hd->state != FSM_idle)
    {
      _gsti_log_info ("** FSM (server) state=%d\n", hd->state);
      switch (hd->state)
	{
	case FSM_wait_on_version:
	  rc = kex_wait_on_version (hd);
	  if (!rc)
	    hd->state = FSM_send_version;
	  break;

	case FSM_send_version:
	  rc = kex_send_version (hd);
	  if (!rc)
	    hd->state = FSM_kex_start;
	  break;

	case FSM_kex_start:
	  rc = kex_send_init_packet (hd);
	  if (!rc)
	    rc = request_packet (hd);
	  if (!rc)
	    {
	      switch (hd->pkt.type)
		{
		case SSH_MSG_KEXINIT:
		  rc = kex_proc_init_packet (hd);
		  if (!rc)
		    hd->state = FSM_kex_wait;
		  break;

		default:
		  log_error (hd);
		  hd->state = FSM_kex_failed;
		}
	    }
	  break;

	case FSM_kex_wait:
	  rc = request_packet (hd);
	  if (!rc)
	    {
	      switch (hd->pkt.type)
		{
		case SSH_MSG_KEXDH_REPLY:
		  rc = logrc (GSTI_PROT_VIOL, "server got KEXDH_REPLY\n");
		  break;

		case SSH_MSG_KEXDH_INIT:
		  rc = kex_proc_kexdh_init (hd);
		  if (!rc)
		    rc = kex_send_kexdh_reply (hd);
		  if (!rc)
		    rc = kex_send_newkeys (hd);
		  if (!rc)
		    hd->state = FSM_kex_wait_newkeys;
		  break;
		}
	    }
	  break;

	case FSM_kex_wait_newkeys:
	  rc = request_packet (hd);
	  if (!rc)
	    {
	      switch (hd->pkt.type)
		{
		case SSH_MSG_NEWKEYS:
		  rc = kex_proc_newkeys (hd);
		  if (!rc)
		    hd->state = FSM_kex_done;
		  break;

		default:
		  log_error (hd);
		  hd->state = FSM_kex_failed;
		}
	    }
	  break;

	case FSM_kex_done:
	  hd->state = FSM_wait_service_request;
	  rc = request_packet (hd);
	  break;

	case FSM_wait_service_request:
	  switch (hd->pkt.type)
	    {
	    case SSH_MSG_SERVICE_REQUEST:
	      rc = kex_proc_service_request (hd);
	      if (!rc)
		hd->state = FSM_send_service_accept;
	      break;

	    default:
	      log_error (hd);
	      hd->state = FSM_kex_failed;
	    }
	  break;

	case FSM_send_service_accept:
	  rc = kex_send_service_accept (hd);
	  if (!rc)
	    hd->state = FSM_service_start;
	  break;

	case FSM_service_start:
	  _gsti_log_info ("service `");
	  _gsti_print_string (hd->service_name->d, hd->service_name->len);
	  _gsti_log_info ("' has been started (server)\n");
	  hd->state = FSM_auth_wait;
	  break;

	case FSM_auth_wait:
	  rc = request_packet (hd);
	  if (!rc)
	    {
	      switch (hd->pkt.type)
		{
		case SSH_MSG_USERAUTH_REQUEST:
		  rc = auth_proc_init_packet (hd);
		  if (!rc)
		    hd->state = FSM_auth_send_pkok;
		  break;

		default:
		  log_error (hd);
		  hd->state = FSM_auth_failed;
		}
	    }
	  break;

	case FSM_auth_send_pkok:
	  rc = auth_send_pkok_packet (hd);
	  if (!rc)
	    hd->state = FSM_auth_wait_request;
	  break;

	case FSM_auth_wait_request:
	  rc = request_packet (hd);
	  if (!rc)
	    {
	      switch (hd->pkt.type)
		{
		case SSH_MSG_USERAUTH_REQUEST:
		  rc = auth_proc_second_packet (hd);
		  if (!rc)
		    hd->state = FSM_auth_send_accept;
		  break;
		}
	    }
	  break;

	case FSM_auth_send_accept:
	  rc = auth_send_accept_packet (hd);
	  if (!rc)
	    hd->state = FSM_auth_done;
	  break;

	case FSM_auth_done:
	  hd->state = FSM_read;
	  break;

	case FSM_read:
	  rc = request_packet (hd);
	  if (!rc)
	    hd->state = FSM_idle;
	  break;

	case FSM_quit:
	  rc = handle_quit (hd);
	  _gsti_log_info ("FSM: returning from quit state: %s\n",
			  gsti_strerror (rc));
	  break;

	default:
	  _gsti_log_info ("FSM: at fsm_loop: invalid state %d\n", hd->state);
	  rc = GSTI_BUG;
	}
    }
  return rc;
}


int
fsm_client_loop (GSTIHD hd)
{
  int rc = 0;

  switch (hd->state)
    {
    case FSM_init:
      rc = handle_init (hd, 0);
      break;
    case FSM_idle:
      hd->state = FSM_write;
      break;
    default:
      _gsti_log_info ("FSM: start fsm_loop: invalid state %d\n", hd->state);
      rc = GSTI_BUG;
      break;
    }

  while (!rc && hd->state != FSM_quit && hd->state != FSM_idle)
    {
      _gsti_log_info ("** FSM (client) state=%d\n", hd->state);
      switch (hd->state)
	{
	case FSM_send_version:
	  rc = kex_send_version (hd);
	  if (!rc)
	    hd->state = FSM_wait_on_version;
	  break;

	case FSM_wait_on_version:
	  rc = kex_wait_on_version (hd);
	  if (!rc)
	    hd->state = FSM_kex_start;
	  break;

	case FSM_kex_start:
	  rc = kex_send_init_packet (hd);
	  if (!rc)
	    rc = request_packet (hd);
	  if (!rc)
	    rc = kex_proc_init_packet (hd);
	  if (!rc)
	    rc = kex_send_kexdh_init (hd);
	  if (!rc)
	    hd->state = FSM_kex_wait;
	  break;

	case FSM_kex_wait:
	  rc = request_packet (hd);
	  if (!rc)
	    {
	      switch (hd->pkt.type)
		{
		case SSH_MSG_KEXDH_INIT:
		  rc = logrc (GSTI_PROT_VIOL, "client got KEXDH_INIT\n");
		  break;

		case SSH_MSG_KEXDH_REPLY:
		  rc = kex_proc_kexdh_reply (hd);
		  if (!rc)
		    rc = kex_send_newkeys (hd);
		  if (!rc)
		    hd->state = FSM_kex_wait_newkeys;
		  break;
		}
	    }
	  break;

	case FSM_kex_wait_newkeys:
	  rc = request_packet (hd);
	  if (!rc)
	    {
	      switch (hd->pkt.type)
		{
		case SSH_MSG_NEWKEYS:
		  rc = kex_proc_newkeys (hd);
		  if (!rc)
		    hd->state = FSM_kex_done;
		  break;

		default:
		  log_error (hd);
		  hd->state = FSM_kex_failed;
		}
	    }
	  break;

	case FSM_kex_done:
	  hd->state = FSM_send_service_request;
	  break;

	case FSM_send_service_request:
	  _gsti_log_info ("is local service? (%d)\n",
			  hd->local_services ? 1 : 0);
	  rc = kex_send_service_request (hd, hd->local_services ?
					 hd->local_services->d
					 : "ssh-userauth");
	  _gsti_log_info ("\n");
	  if (!rc)
	    {
	      hd->state = FSM_wait_service_accept;
	      rc = request_packet (hd);
	    }
	  break;

	case FSM_wait_service_accept:
	  switch (hd->pkt.type)
	    {
	    case SSH_MSG_SERVICE_ACCEPT:
	      rc = kex_proc_service_accept (hd);
	      if (!rc)
		hd->state = FSM_service_start;
	      break;

	    default:
	      log_error (hd);
	      hd->state = FSM_kex_failed;
	    }
	  break;

	case FSM_service_start:
	  _gsti_log_info ("service `");
	  _gsti_print_string (hd->service_name->d, hd->service_name->len);
	  _gsti_log_info ("' has been started (client)\n");
	  hd->state = FSM_auth_start;
	  break;

	case FSM_auth_start:
	  rc = auth_send_init_packet (hd);
	  if (!rc)
	    hd->state = FSM_auth_wait_pkok;
	  break;

	case FSM_auth_wait_pkok:
	  rc = request_packet (hd);
	  if (!rc)
	    {
	      switch (hd->pkt.type)
		{
		case SSH_MSG_USERAUTH_PK_OK:
		  rc = auth_proc_pkok_packet (hd);
		  if (!rc)
		    hd->state = FSM_auth_send_request;
		  break;

		default:
		  log_error (hd);
		  hd->state = FSM_auth_failed;
		}
	    }
	  break;

	case FSM_auth_send_request:
	  rc = auth_send_second_packet (hd);
	  if (!rc)
	    hd->state = FSM_auth_wait_accept;
	  break;

	case FSM_auth_wait_accept:
	  rc = request_packet (hd);
	  if (!rc)
	    {
	      switch (hd->pkt.type)
		{
		case SSH_MSG_USERAUTH_SUCCESS:
		  rc = auth_proc_accept_packet (hd);
		  if (!rc)
		    hd->state = FSM_auth_done;
		  break;

		default:
		  log_error (hd);
		  hd->state = FSM_auth_failed;
		}
	    }
	  break;

	case FSM_auth_done:
	  hd->state = FSM_write;
	  break;

	case FSM_write:
	  rc = _gsti_packet_write (hd);
	  if (!rc)
	    hd->state = FSM_idle;
	  break;

	default:
	  _gsti_log_info ("FSM: at fsm_loop: invalid state %d\n", hd->state);
	  rc = GSTI_BUG;
	}
    }

  return rc;
}


/**************** 
 * This is the main processing loop 
 * 
 * For now we use a simple switch based fsm. 
 */
int
fsm_loop (GSTIHD hd, int want_read)
{
  int rc;

  if (want_read)
    rc = fsm_server_loop (hd);
  else
    rc = fsm_client_loop (hd);
  return rc;
}


/****************
 * Get a packet from the connection
 * NOTE:  the returned buffer is only valid until the next
 *	  gsti_{get,put}_packet and as long as the handle is valid!
 */
int
gsti_get_packet (GSTIHD hd, GSTI_PKTDESC * pkt)
{
  int rc;

  /* we do an extra loop to initialize the key exchange */
  if (!hd->recv_seqno)
    {
      rc = fsm_loop (hd, 1);
      if (rc)
	return rc;
    }

  rc = fsm_loop (hd, 1);
  if (!rc)
    {
      u32 seqno = hd->recv_seqno - 1;
      pkt->datalen = hd->pkt.payload_len;
      pkt->data = hd->pkt.payload;
      pkt->seqno = seqno;
    }
  return rc;
}


/****************
 * Write a packet and return it's sequence number in pkt->seqno.
 * If pkt is NULL a flush operation is performed. This is needed if
 * the protocol which is used on top of this transport protocol must
 * assure that a packet has really been sent to the peer.
 */
int
gsti_put_packet (GSTIHD hd, GSTI_PKTDESC * pkt)
{
  const byte *data;
  size_t datalen;
  int rc;

  /* we do an extra loop to initialize the key exchange */
  if (!hd->send_seqno)
    {
      hd->pkt.type = 0xff;
      hd->pkt.payload_len = 5;
      hd->pkt.payload[0] = 0xff;
      memset (hd->pkt.payload + 1, 0xff, 4);
      rc = fsm_loop (hd, 0);
      if (rc)
	return rc;
    }

  if (!pkt)
    return _gsti_packet_flush (hd);

  data = pkt->data;
  datalen = pkt->datalen;
  if (!datalen)
    return GSTI_TOO_SHORT;	/* need the packet type */
  if (datalen > hd->pkt.size)
    return GSTI_TOO_LARGE;

  /* The caller is not allowed to supply any of the
   * tranport protocol numbers nor one of the reserved
   * numbers. 0 is not defined
   */
  if (!*data || *data <= 49 || (*data >= 128 && *data <= 191))
    return GSTI_INV_ARG;

  hd->pkt.type = *data;
  hd->pkt.payload_len = datalen;
  memcpy (hd->pkt.payload, data, datalen);
  rc = fsm_loop (hd, 0);
  if (!rc)
    {
      u32 seqno = hd->send_seqno - 1;
      pkt->seqno = seqno;
    }
  return rc;
}


int
fsm_user_read (GSTIHD hd)
{
  GSTI_PKTDESC pkt;
  int rc;

  rc = gsti_get_packet (hd, &pkt);
  if (rc)
    return rc;
  hd->user_read_nbytes = pkt.datalen;
  if (hd->user_read_nbytes < hd->user_read_bufsize)
    memcpy (hd->user_read_buffer, pkt.data, pkt.datalen);
  return 0;
}


int
fsm_user_write (GSTIHD hd)
{
  GSTI_PKTDESC pkt;

  pkt.data = hd->user_write_buffer;
  pkt.datalen = hd->user_write_bufsize;
  return gsti_put_packet (hd, &pkt);
}
