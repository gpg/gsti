/* fsm.c - state machine for the transport protocol
 *	Copyright (C) 1999 Free Software Foundation, Inc.
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
 
#include "api.h" 
#include "memory.h" 
#include "stream.h" 
#include "packet.h" 
#include "utils.h" 
#include "kex.h" 

enum fsm_states { 
    FSM_init                 =  0, 
    FSM_read                 =  1, 
    FSM_write                =  2, 
    FSM_wait_on_version      =  3, 
    FSM_send_version         =  4, 
    FSM_kex_start            =  5,  
    FSM_kex_wait             =  6, 
    FSM_kex_wait_newkeys     =  7, 
    FSM_kex_done             =  8, 
    FSM_wait_service_request =  9, 
    FSM_send_service_request = 10, 
    FSM_wait_service_accept  = 11, 
    FSM_send_service_accept  = 12, 
    FSM_service_start        = 13, 
    FSM_idle                 = 14,
    FSM_kex_failed           = 15, 
    FSM_not_implemented      = 16, 
    FSM_quit                 = 17
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
    hd->read_stream = _gsti_read_stream_new( hd->readfnc ); 
    hd->write_stream = _gsti_write_stream_new( hd->writefnc ); 
    if( want_read ) { /* be the server side */
        hd->we_are_server = 1; 
        hd->state = FSM_wait_on_version; 
    } 
    else { /* be the client side  */
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

    rc = _gsti_packet_write( hd ); 
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
                if( hd->we_are_server )
                    hd->state = FSM_kex_wait;
                else {
                    rc = kex_send_kexdh_init( hd ); 
                    if( !rc ) 
                        hd->state = FSM_kex_wait; 
                } 
            } 
            break; 

        default:
            _gsti_log_info( "FSM: at new_state: state=%d, packet=%d\n", 
                            hd->state, hd->pkt.type );
            hd->state = FSM_kex_failed; 
        } 
        break; 

    case FSM_kex_wait: 
        switch( hd->pkt.type ) { 
        case SSH_MSG_KEXDH_REPLY: 
            if( hd->we_are_server ) { 
                rc = _gsti_log_rc( GSTI_PROT_VIOL, "server got KEXDH_REPLY" );
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
                rc = _gsti_log_rc( GSTI_PROT_VIOL, "client got KEXDH_INIT\n" );
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
            _gsti_log_info( "FSM: at new_state: state=%d, packet=%d\n",
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
            _gsti_log_info( "FSM: at new_state: state=%d, packet=%d\n", 
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
            _gsti_log_info( "FSM: at new_state: state=%d, packet=%d\n", 
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
            _gsti_log_info( "FSM: at new_state: state=%d, packet=%d\n", 
                            hd->state, hd->pkt.type ); 
            hd->state = FSM_kex_failed; 
        }
        break;

    case FSM_read:
        switch( hd->pkt.type ) {
        case SSH_MSG_NEWKEYS: /* new key exchange requested  */
            hd->state = FSM_not_implemented;
            break;

        default:
            hd->state = FSM_idle;
            break;
        }
        break;

    default:
        _gsti_log_info( "FSM: at new_state: invalid state %d\n", hd->state ); 
        hd->state = GSTI_BUG; 
    }

    return rc; 
}


#define skip_packet( type ) ( (type) == SSH_MSG_DEBUG \
                              || (type) == SSH_MSG_IGNORE )

 /**************** 
  * This is the main processing loop 
  * 
  * For now we use a simple switch based fsm. 
  */ 
int 
fsm_loop( GSTIHD hd, int want_read ) 
{ 
    int rc = 0;

    switch( hd->state ) { 
    case FSM_init: rc = handle_init( hd, want_read ); break;
    case FSM_idle: hd->state = want_read? FSM_read : FSM_write; break;
    default:
        _gsti_log_info( "FSM: start fsm_loop: invalid state %d\n", hd->state); 
        rc = GSTI_BUG;
        break;
    }

    while( !rc && hd->state != FSM_idle && hd->state != FSM_quit ) {
        _gsti_log_info( "FSM: state is %d\n", hd->state );
        switch( hd->state ) { 
        case FSM_wait_on_version:
            rc = kex_wait_on_version( hd ); 
            if( rc ) 
                ; 
            else if( hd->we_are_server )
                hd->state = FSM_send_version; 
            else
                hd->state = FSM_kex_start;
            break; 

        case FSM_send_version:
            rc = kex_send_version( hd );
            if( rc )
                ;
            else if( hd->we_are_server )
                hd->state = FSM_kex_start;
            else
                hd->state = FSM_wait_on_version;
            break; 

        case FSM_kex_start:
            /* in either case: send the version string out  */
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
            else
                hd->state = FSM_send_service_request;
            break;

        case FSM_send_service_request:
            _gsti_log_info( "is local service? (%d)\n",
                            hd->local_services? 1 : 0 );
            rc = kex_send_service_request( hd, hd->local_services?
                                           hd->local_services->d
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
            _gsti_log_info( "service `" );
            _gsti_print_string( stderr, hd->service_name->d,
                                hd->service_name->len );
            if( hd->we_are_server ) {
                _gsti_log_info( "' has been started (server)\n" );
                hd->state = FSM_read;
            }
            else {
                _gsti_log_info( "' has been started (client)\n" );
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
            _gsti_log_info( "FSM: returning from quit state: %s\n",
                            gsti_strerror( rc ) );
            break;

        default:
            _gsti_log_info( "FSM: at fsm_loop: invalid state %d\n",hd->state );
            rc = GSTI_BUG;
        }
        if( rc ) {
            hd->wait_packet = 0;
            _gsti_log_info( "FSM: error at state %d: %s\n",
                            hd->state, gsti_strerror( rc ) );
        }

        if( hd->wait_packet ) {
            hd->wait_packet = 0;
            do {
                rc = _gsti_packet_read( hd );
                if( rc )
                    _gsti_log_info("FSM: read packet at state %d failed: %s\n",
                                   hd->state, gsti_strerror( rc ) );
            } while( !rc && skip_packet( hd->pkt.type ) );
            if( !rc ) {
                rc = new_state( hd );
                if( rc ) {
                    _gsti_log_info( "FSM: new_state at state %d failed: %s\n",
                                    hd->state, gsti_strerror( rc ) );
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
 *	  gsti_{get,put}_packet and as long as the handle is valid!
 */
int
gsti_get_packet( GSTIHD hd, GSTI_PKTDESC *pkt )
{
    int rc;

    /* we do an extra loop to initialize the key exchange */
    if( !hd->recv_seqno ) {
        rc = fsm_loop( hd, 1 );
        if( rc )
            return rc;
    }
    
    rc = fsm_loop( hd, 1 );
    if( !rc ) {
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
gsti_put_packet( GSTIHD hd, GSTI_PKTDESC *pkt )
{
    const byte *data;
    size_t datalen;
    int rc;

    /* we do an extra loop to initialize the key exchange */
    if( !hd->send_seqno ) {
        hd->pkt.type = 0xff;
        hd->pkt.payload_len = 5;
        hd->pkt.payload[0] = 0xff;
        memset( hd->pkt.payload + 1, 0xff, 4 );
        rc = fsm_loop( hd, 0 );
        if( rc )
            return rc;
    }
        
    if( !pkt )
        return _gsti_packet_flush( hd );
    
    data = pkt->data;
    datalen = pkt->datalen;
    if( !datalen )
        return GSTI_TOO_SHORT; /* need the packet type */
    if( datalen > hd->pkt.size )
        return GSTI_TOO_LARGE;

    /* The caller is not allowed to supply any of the
     * tranport protocol numbers nor one of the reserved
     * numbers. 0 is not defined
     */
    if( !*data || *data <= 49 || (*data >= 128 && *data <= 191) )
        return GSTI_INV_ARG;

    hd->pkt.type = *data;
    hd->pkt.payload_len = datalen;
    memcpy( hd->pkt.payload, data, datalen );
    rc = fsm_loop( hd, 0 );
    if( !rc ) {
        u32 seqno = hd->send_seqno - 1;
        pkt->seqno = seqno;
    }
    return rc;
}


int
fsm_user_read( GSTIHD hd )
{
    GSTI_PKTDESC pkt;
    int rc;

    rc = gsti_get_packet( hd, &pkt );
    if( rc )
        return rc;
    hd->user_read_nbytes = pkt.datalen;
    if( hd->user_read_nbytes < hd->user_read_bufsize )
        memcpy( hd->user_read_buffer, pkt.data, pkt.datalen );
    return 0;
}


int
fsm_user_write( GSTIHD hd )
{
    GSTI_PKTDESC pkt;

    pkt.data = hd->user_write_buffer;
    pkt.datalen = hd->user_write_bufsize;
    return gsti_put_packet( hd, &pkt );
}
