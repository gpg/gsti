/* packet.h
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

#ifndef GSTI_PACKET_H
#define GSTI_PACKET_H

#include <gcrypt.h>

#include "ssh.h"

#define MAX_PKTLEN 40000	/* sanity limit */
#define PKTBUFSIZE 50000	/* somewhat large size of a packet buffer */


enum
{
  SSH_HMAC_SHA1 = GCRY_MD_SHA1,
  SSH_HMAC_MD5 = GCRY_MD_MD5,
  SSH_HMAC_RMD160 = GCRY_MD_RMD160
};

enum
{
  SSH_CIPHER_3DES = GCRY_CIPHER_3DES,
  SSH_CIPHER_BLOWFISH = GCRY_CIPHER_BLOWFISH,
  SSH_CIPHER_TWOFISH256 = GCRY_CIPHER_TWOFISH,
  SSH_CIPHER_AES128 = GCRY_CIPHER_AES128,
  SSH_CIPHER_CAST128 = GCRY_CIPHER_CAST5
};


enum
{
  SSH_KEX_NONE = 0,
  SSH_KEX_GROUP1 = 1,
  SSH_KEX_GROUP_EXCHANGE = 2
};


typedef struct
{
  const char *name;
  int algid;
  int blksize;			/* for ciphers only */
  int mode;			/* for ciphers only */
  int len;
} algorithm_list;


typedef struct
{
  byte cookie[16];
  STRLIST kex_algo;
  STRLIST server_host_key_algos;
  STRLIST encr_algos_c2s;
  STRLIST encr_algos_s2c;
  STRLIST mac_algos_c2s;
  STRLIST mac_algos_s2c;
  STRLIST compr_algos_c2s;
  STRLIST compr_algos_s2c;
  int first_kex_packet_follows;
} MSG_kexinit;


typedef struct
{
  unsigned int min;
  unsigned int n;
  unsigned int max;
} MSG_gexdh_request;


typedef struct
{
  gcry_mpi_t p;
  gcry_mpi_t g;
} MSG_gexdh_group;


typedef struct
{
  gcry_mpi_t e;
} MSG_kexdh_init;


typedef struct
{
  BSTRING k_s;			/* servers public host key */
  gcry_mpi_t f;
  BSTRING sig_h;		/* signature of the hash */
} MSG_kexdh_reply;


typedef struct
{
  BSTRING user;
  BSTRING svcname;
  BSTRING method;
  unsigned false:1;
  BSTRING pkalgo;
  BSTRING key;
  BSTRING sig;
} MSG_auth_request;


typedef struct
{
  BSTRING pkalgo;
  BSTRING key;
} MSG_auth_pkok;


void _gsti_packet_init (gsti_ctx_t ctx);
void _gsti_packet_free (gsti_ctx_t ctx);
gsti_error_t _gsti_packet_read (gsti_ctx_t ctx);
gsti_error_t _gsti_packet_write (gsti_ctx_t ctx);
gsti_error_t _gsti_packet_flush (gsti_ctx_t ctx);


#endif	/* GSTI_PACKET_H */
