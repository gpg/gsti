/* api.h
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
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#ifndef GSTI_API_H
#define GSTI_API_H

#include "types.h"
#include "stream.h"
#include "utils.h"


struct packet_buffer_s {
    int packet_len;
    int padding_len;
    byte *packet_buffer; /* malloced of length SIZE+5 */
    size_t payload_len;
    size_t size;
    byte *payload;       /* = packet_buffer+5 */
    int type;
};

struct gsti_context {
    GSTI_READ_FNC  readfnc;
    GSTI_WRITE_FNC writefnc;
    READ_STREAM   read_stream;
    WRITE_STREAM  write_stream;
    STRLIST local_services;

    int    state;	  /* current state */
    int    wait_packet;   /* wait for a new packet */

    int  we_are_server;
    BSTRING peer_version_string;  /* received from other end */
    BSTRING host_kexinit_data;	  /* the KEX data we have send to the peer */
    BSTRING peer_kexinit_data;	  /* the KEX data we have got from the peer */

    BSTRING service_name;

    struct packet_buffer_s pkt;

    BSTRING session_id;     /* the exchange hash from the first KEX */
    u32  send_seqno;
    u32  recv_seqno;
    struct {
        BSTRING h;	    /* current exchange hash */
        GCRY_MPI k;	    /* the shared secret */
        BSTRING iv_a;	    /* IV client to server */
        BSTRING iv_b;	    /* IV server to client */
        BSTRING key_c;	    /* Enc client to server */
        BSTRING key_d;	    /* Enc server to client */
        BSTRING mac_e;	    /* Mac client to server */
        BSTRING mac_f;	    /* Mac server to client */
    } kex;
    int sent_newkeys;

    GCRY_MPI secret_x;  /* temporary use only */
    GCRY_MPI kexdh_e;   /* ditto */

    GCRY_MPI secret_y;  /* fixme: we could reuse secret_x kexdh_e */
    GCRY_MPI kexdh_f;   /* ditto */

    int ciph_blksize;
    int ciph_algo;
    int ciph_mode;
    GCRY_CIPHER_HD encrypt_hd;
    GCRY_CIPHER_HD decrypt_hd;

    int mac_algo;
    int mac_len;
    GCRY_MD_HD send_mac;
    GCRY_MD_HD recv_mac;

    byte *user_read_buffer;
    size_t user_read_bufsize;
    size_t user_read_nbytes;

    const byte *user_write_buffer;
    size_t user_write_bufsize;

    char *hostkey_file;
    GSTI_KEY hostkey;

    unsigned long id;
};


/*-- main.c --*/
int map_gcry_rc( int rc );

/*-- fsm.c --*/
int fsm_user_read( GSTIHD hd );
int fsm_user_write( GSTIHD hd );


#endif /* GSTI_API_H */
