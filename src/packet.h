/* packet.h
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

#ifndef GSTI_PACKET_H
#define GSTI_PACKET_H

#include <gcrypt.h>

enum {
    SSH_MSG_DISCONNECT	    = 1,
    SSH_MSG_IGNORE	    = 2,
    SSH_MSG_UNIMPLEMENTED   = 3,
    SSH_MSG_DEBUG	    = 4,
    SSH_MSG_SERVICE_REQUEST = 5,
    SSH_MSG_SERVICE_ACCEPT  = 6,

    SSH_MSG_KEXINIT	    = 20,
    SSH_MSG_NEWKEYS	    = 21,

    SSH_MSG_KEXDH_INIT	    = 30,
    SSH_MSG_KEXDH_REPLY     = 31,
};


typedef struct {
    byte cookie[16];
    STRLIST kex_algorithm;
    STRLIST server_host_key_algorithms;
    STRLIST encryption_algorithms_client_to_server;
    STRLIST encryption_algorithms_server_to_client;
    STRLIST mac_algorithms_client_to_server;
    STRLIST mac_algorithms_server_to_client;
    STRLIST compression_algorithms_client_to_server;
    STRLIST compression_algorithms_server_to_client;
    int first_kex_packet_follows;
} MSG_kexinit;


typedef struct {
    MPI e;
} MSG_kexdh_init;


typedef struct {
    BSTRING k_s;    /* servers public host key */
    MPI     f;
    BSTRING sig_h;  /* signature of the hash */
} MSG_kexdh_reply;


void init_packet( GSTIHD hd );
int read_packet( GSTIHD hd );
int write_packet( GSTIHD hd );
int flush_packet( GSTIHD hd );


#endif /* GSTI_PACKET_H */
