/* fsm.c  -  state machine for the transport protocol
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
#include "fsm.h"


enum fsm_states {
    FSM_init = 0,
    FSM_read,
    FSM_write,
    FSM_wait_on_version,
    FSM_send_version,
    FSM_kex_start,
    FSM_kex_wait,
    FSM_kex_wait_newkeys,
    FSM_kex_done,
    FSM_wait_service_request,
    FSM_send_service_request,
    FSM_wait_service_accept,
    FSM_send_service_accept,
    FSM_service_start,
    FSM_idle,

    FSM_kex_failed,
    FSM_not_implemented,
    FSM_quit
};


/****************
 * Do some initialization
 */
static int
handle_init( GSTIHD hd, int want_read )
{
    int rc = 0;

    if( !hd->readfnc || !hd->writefnc )
	return GSTI_INV_ARG;
    hd->read_stream = new_read_stream( hd->readfnc );
    hd->write_stream = new_write_stream( hd->writefnc );
    if( want_read ) { /* be the server side */
	hd->we_are_server = 1;
	hd->state = FSM_wait_on_version;
    }
    else { /* be the client side */
	hd->we_are_server = 0;
	hd->state = FSM_send_version;
    }
    return rc;
}



/****************
 * Cleanup the connection we are about to quit.
 */
static int
handle_quit( GSTIHD hd )
{
    int rc = 0;

    return rc;
}



/****************
 * We are in state FSMwrite: write the user supplied data
 */
static int
handle_write( GSTIHD hd )
{
    int rc;

    rc = write_packet( hd );
    return rc;
}



/****************
 * Determine a new state depending on the current one
 * and the received packet
 */
static int
new_state( GSTIHD hd )
{
    int rc = 0;

    switch( hd->state ) {
      case FSM_kex_start:
	switch( hd->pkt.type ) {
	  case SSH_MSG_KEXINIT:
	    rc = kex_proc_init_packet( hd );
	    if( !rc ) {
		if( hd->we_are_server ) {
		    hd->state = FSM_kex_wait;
		}
		else {
		    rc = kex_send_kexdh_init( hd );
		    if( !rc )
			hd->state = FSM_kex_wait;
		}
	    }
	    break;

	  default:
	    fprintf(stderr,"FSM: at new_state: state=%d, packet=%d\n",
						hd->state, hd->pkt.type );
	    hd->state = FSM_kex_failed;
	}
	break;

      case FSM_kex_wait:
	switch( hd->pkt.type ) {
	  case SSH_MSG_KEXDH_REPLY:
	    if( hd->we_are_server ) {
		rc = debug_rc(GSTI_PROT_VIOL, "server got KEXDH_REPLY");
		break;
	    }
	    rc = kex_proc_kexdh_reply( hd );
	    if( !rc )
		rc = kex_send_newkeys( hd );
	    if( !rc )
		hd->state = FSM_kex_wait_newkeys;
	    break;

	  case SSH_MSG_KEXDH_INIT:
	    if( !hd->we_are_server ) {
		rc = debug_rc(GSTI_PROT_VIOL, "client got KEXDH_INIT");
		break;
	    }
	    rc = kex_proc_kexdh_init( hd );
	    if( !rc )
		rc = kex_send_kexdh_reply( hd );
	    if( !rc )
		rc = kex_send_newkeys( hd );
	    if( !rc )
		hd->state = FSM_kex_wait_newkeys;
	    break;

	  default:
	    fprintf(stderr,"FSM: at new_state: state=%d, packet=%d\n",
						hd->state, hd->pkt.type );
	    hd->state = FSM_kex_failed;
	}
	break;

      case FSM_kex_wait_newkeys:
	switch( hd->pkt.type ) {
	  case SSH_MSG_NEWKEYS:
	    rc = kex_proc_newkeys( hd );
	    if( !rc )
		hd->state = FSM_kex_done;
	    break;

	  default:
	    fprintf(stderr,"FSM: at new_state: state=%d, packet=%d\n",
						hd->state, hd->pkt.type );
	    hd->state = FSM_kex_failed;
	}
	break;

      case FSM_wait_service_accept:
	switch( hd->pkt.type ) {
	  case SSH_MSG_SERVICE_ACCEPT:
	    rc = kex_proc_service_accept( hd );
	    if( !rc )
		hd->state = FSM_service_start;
	    break;

	  default:
	    fprintf(stderr,"FSM: at new_state: state=%d, packet=%d\n",
						hd->state, hd->pkt.type );
	    hd->state = FSM_kex_failed;
	}
	break;

      case FSM_wait_service_request:
	switch( hd->pkt.type ) {
	  case SSH_MSG_SERVICE_REQUEST:
	    rc = kex_proc_service_request( hd );
	    if( !rc )
		hd->state = FSM_send_service_accept;
	    break;

	  default:
	    fprintf(stderr,"FSM: at new_state: state=%d, packet=%d\n",
						hd->state, hd->pkt.type );
	    hd->state = FSM_kex_failed;
	}
	break;


      case FSM_read:
	switch( hd->pkt.type ) {
	  case SSH_MSG_NEWKEYS: /* new key exchange requested */
	    hd->state = FSM_not_implemented;
	    break;

	  default:
	    hd->state = FSM_idle;
	    break;
	}
	break;

      default:
	fprintf(stderr,"FSM: at new_state: invalid state %d\n", hd->state );
	hd->state = GSTI_BUG;
    }

    return rc;
}




/****************
 * This is the main processing loop
 *
 * For now we use a simple switch based fsm.
 */
int
fsm_loop( GSTIHD hd, int want_read )
{
    int rc=0;

    switch( hd->state ) {
      case FSM_init: rc = handle_init( hd, want_read ); break;
      case FSM_idle: hd->state = want_read? FSM_read : FSM_write; break;
      default:
	fprintf(stderr,"FSM: start fsm_loop: invalid state %d\n", hd->state );
	rc = GSTI_BUG;
	break;
    }

    while( !rc && hd->state != FSM_idle && hd->state != FSM_quit ) {
	fprintf(stderr,"FSM: state is %d\n", hd->state );
	switch( hd->state ) {
	  case FSM_wait_on_version:
	    rc = kex_wait_on_version( hd );
	    if( rc )
		;
	    else if( hd->we_are_server ) {
		hd->state = FSM_send_version;
	    }
	    else {
		hd->state = FSM_kex_start;
	    }
	    break;

	  case FSM_send_version:
	    rc = kex_send_version( hd );
	    if( rc )
		;
	    else if( hd->we_are_server ) {
		hd->state = FSM_kex_start;
	    }
	    else {
		hd->state = FSM_wait_on_version;
	    }
	    break;

	  case FSM_kex_start:
	    /* in either case: send the version string out */
	    rc = kex_send_init_packet( hd );
	    if( !rc )
		hd->wait_packet = 1;
	    break;

	  case FSM_kex_wait:
	  case FSM_kex_wait_newkeys:
	    hd->wait_packet = 1;
	    break;

	  case FSM_kex_done:
	    if( hd->we_are_server ) {
		hd->state = FSM_wait_service_request;
		hd->wait_packet = 1;
	    }
	    else {
		hd->state = FSM_send_service_request;
	    }
	    break;

	  case FSM_send_service_request:
	    rc = kex_send_service_request( hd,
			    hd->local_services? hd->local_services->d
					      : "ssh-userauth" );
	    if( !rc ) {
		hd->state = FSM_wait_service_accept;
		hd->wait_packet = 1;
	    }
	    break;

	  case FSM_send_service_accept:
	    rc = kex_send_service_accept( hd );
	    if( !rc )
		hd->state = FSM_service_start;
	    break;

	  case FSM_service_start:
	    fprintf(stderr, "service `");
	    gsti_print_string( stderr, hd->service_name->d,
				       hd->service_name->len );
	    if( hd->we_are_server ) {
		fprintf(stderr, "' has been started (server)\n");
		hd->state = FSM_read;
	    }
	    else {
		fprintf(stderr, "' has been started (client)\n");
		hd->state = FSM_write;
	    }
	    break;

	  case FSM_read:
	    hd->wait_packet = 1;
	    break;

	  case FSM_write:
	    rc = handle_write( hd );
	    if( !rc )
		hd->state = FSM_idle;
	    break;

	  case FSM_quit:
	    rc = handle_quit( hd );
	    fprintf(stderr,"FSM: returning from quit state: %s\n",
						   gsti_strerror(rc) );
	    break;

	  default:
	    fprintf(stderr,"FSM: at fsm_loop: invalid state %d\n", hd->state );
	    rc = GSTI_BUG;
	}
	if( rc ) {
	    hd->wait_packet = 0;
	    fprintf(stderr,"FSM: error at state %d: %s\n",
						hd->state, gsti_strerror(rc) );
	}

	if( hd->wait_packet ) {
	    hd->wait_packet = 0;
	    do {
		rc = read_packet( hd );
		if( rc )
		    fprintf(stderr,"FSM: read packet at state %d failed: %s\n",
						hd->state, gsti_strerror(rc) );
	    } while( !rc && ( hd->pkt.type == SSH_MSG_DEBUG
			      || hd->pkt.type == SSH_MSG_IGNORE ) );

	    if( !rc ) {
		rc = new_state( hd );
		if( rc ) {
		    fprintf(stderr,"FSM: new_state at state %d failed: %s\n",
						hd->state, gsti_strerror(rc) );
		    return rc;
		}
	    }
	}
    }
    return rc;
}


/****************
 * Get a packet from the connection
 * NOTE:  the returned buffer is only valid until the next
 *	  gsti_{get,put}_packet and as long as the handle ist valid!
 */
int
gsti_get_packet( GSTIHD hd, GSTI_PKTDESC *pkt )
{
    int rc;

    rc = fsm_loop( hd, 1 );
    if( !rc ) {
	u32 seqno = hd->recv_seqno-1;
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
gsti_put_packet( GSTIHD hd, GSTI_PKTDESC *pkt )
{
    int rc;
    const byte *data;
    size_t   datalen;

    if( !pkt )
	return flush_packet( hd );


    data = pkt->data;
    datalen = pkt->datalen;
    if( !datalen )
	return GSTI_TOO_SHORT; /* need the packet type */
    if( datalen > hd->pkt.size )
	return GSTI_TOO_LARGE;

    /* The caller is not allowed to supply any of the
     * tranport protocol numbers nor one of the reserved
     * numbers. 0 is not defined */
    if( !*data || *data <= 49 || (*data >= 128 && *data <= 191) )
	return GSTI_INV_ARG;

    hd->pkt.type = *data;
    hd->pkt.payload_len = datalen;
    memcpy(hd->pkt.payload, data, datalen);
    rc = fsm_loop( hd, 0 );
    if( !rc ) {
	u32 seqno = hd->send_seqno-1;
	pkt->seqno = seqno;
    }
    return rc;
}


