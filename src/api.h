/* api.h
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

#ifndef GSTI_API_H
#define GSTI_API_H

#include "types.h"
#include "stream.h"
#include "utils.h"


struct packet_buffer_s
{
  int packet_len;
  int padding_len;
  byte *packet_buffer;		/* malloced of length SIZE+5 */
  size_t payload_len;
  size_t size;
  byte *payload;		/* = packet_buffer+5 */
  int type;
};
typedef struct packet_buffer_s * packet_buffer_t;

struct gsti_context
{
  GSTI_READ_FNC readfnc;
  GSTI_WRITE_FNC writefnc;
  READ_STREAM read_stream;
  WRITE_STREAM write_stream;
  STRLIST local_services;

  /* Logging.  */
  gio_stream_t log_stream;
  gsti_log_level_t log_level;

  int state;			/* current state */

  int we_are_server;
  BSTRING peer_version_string;	/* received from other end */
  BSTRING host_kexinit_data;	/* the KEX data we have send to the peer */
  BSTRING peer_kexinit_data;	/* the KEX data we have got from the peer */

  BSTRING service_name;

  struct packet_buffer_s pkt;
  BUFFER pktbuf;

  BSTRING session_id;		/* the exchange hash from the first KEX */
  u32 send_seqno;
  u32 recv_seqno;
  struct
  {
    BSTRING h;			/* current exchange hash */
    gcry_mpi_t k;		/* the shared secret */
    BSTRING iv_a;		/* IV client to server */
    BSTRING iv_b;		/* IV server to client */
    BSTRING key_c;		/* Enc client to server */
    BSTRING key_d;		/* Enc server to client */
    BSTRING mac_e;		/* Mac client to server */
    BSTRING mac_f;		/* Mac server to client */
  } kex;

  int kex_type;

  struct
  {
    unsigned int min;
    unsigned int max;
    unsigned int n;
  } gex;

  byte cookie[16];
  int sent_newkeys;

  gcry_mpi_t secret_x;		/* temporary use only */
  gcry_mpi_t kexdh_e;		/* ditto */
  gcry_mpi_t secret_y;		/* fixme: we could reuse secret_x kexdh_e */
  gcry_mpi_t kexdh_f;		/* ditto */

  int ciph_blksize;
  int ciph_algo;
  int ciph_mode;
  gcry_cipher_hd_t encrypt_hd;
  gcry_cipher_hd_t decrypt_hd;

  int mac_algo;
  int mac_len;
  gcry_md_hd_t send_mac;
  gcry_md_hd_t recv_mac;

  byte *user_read_buffer;
  size_t user_read_bufsize;
  size_t user_read_nbytes;

  const byte *user_write_buffer;
  size_t user_write_bufsize;

  gsti_key_t hostkey;

  struct
  {
    int method;
    gsti_key_t key;
    char *user;
  } auth;

  struct
  {
    unsigned int use:1;
    unsigned int init:1;
  } zlib;

  unsigned long id;
};


/*-- fsm.c --*/
gsti_error_t fsm_user_read (gsti_ctx_t ctx);
gsti_error_t fsm_user_write (gsti_ctx_t ctx);

/*-- auth.c --*/
gsti_error_t auth_send_accept_packet (gsti_ctx_t ctx);
gsti_error_t auth_proc_accept_packet (gsti_ctx_t ctx);

gsti_error_t auth_send_pkok_packet (gsti_ctx_t ctx);
gsti_error_t auth_proc_pkok_packet (gsti_ctx_t ctx);

gsti_error_t auth_send_init_packet (gsti_ctx_t ctx);
gsti_error_t auth_proc_init_packet (gsti_ctx_t ctx);

gsti_error_t auth_send_second_packet (gsti_ctx_t ctx);
gsti_error_t auth_proc_second_packet (gsti_ctx_t ctx);

#endif	/* GSTI_API_H */
