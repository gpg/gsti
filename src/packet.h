/* packet.h
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

#ifndef GSTI_PACKET_H
#define GSTI_PACKET_H

#include <gcrypt.h>

#define MAX_PKTLEN 40000  /* sanity limit */
#define PKTBUFSIZE 50000  /* somewhat large size of a packet buffer */

enum {
    /* transport */
    SSH_MSG_DISCONNECT	      =  1,
    SSH_MSG_IGNORE	      =  2,
    SSH_MSG_UNIMPLEMENTED     =  3,
    SSH_MSG_DEBUG	      =  4,
    SSH_MSG_SERVICE_REQUEST   =  5,
    SSH_MSG_SERVICE_ACCEPT    =  6,
    SSH_MSG_KEXINIT	      = 20,
    SSH_MSG_NEWKEYS	      = 21,
    
    SSH_MSG_KEXDH_INIT	      = 30,
    SSH_MSG_KEXDH_REPLY       = 31,
    SSH_MSG_KEX_DH_GEX_INIT   = 32,
    SSH_MSG_KEX_DH_GEX_REPLY  = 33,

    SSH_MSG_KEX_DH_GEX_REQUEST= 34,
    SSH_MSG_KEX_DH_GEX_GROUP  = 31,
    
    /* user auth */
    SSH_MSG_USERAUTH_REQUEST  = 50,
    SSH_MSG_USERAUTH_FAILURE  = 51,
    SSH_MSG_USERAUTH_SUCCESS  = 52,
    SSH_MSG_USERAUTH_BANNER   = 53,
    /* key based */
    SSH_MSG_USERAUTH_PK_OK    = 60,
};

enum {
    SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT      =  1,
    SSH_DISCONNECT_PROTOCOL_ERROR                   =  2,
    SSH_DISCONNECT_KEY_EXCHANGE_FAILED              =  3,
    SSH_DISCONNECT_RESERVED                         =  4,
    SSH_DISCONNECT_MAC_ERROR                        =  5,
    SSH_DISCONNECT_COMPRESSION_ERROR                =  6,
    SSH_DISCONNECT_SERVICE_NOT_AVAILABLE            =  7,
    SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED   =  8,
    SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE          =  9,
    SSH_DISCONNECT_CONNECTION_LOST                  = 10,
    SSH_DISCONNECT_BY_APPLICATION                   = 11,
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS             = 12,
    SSH_DISCONNECT_AUTH_CANCELLED_BY_USER           = 13,
    SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE   = 14,
    SSH_DISCONNECT_ILLEGAL_USER_NAME                = 15
};  

enum {
    SSH_HMAC_SHA1   = GCRY_MD_SHA1,
    SSH_HMAC_MD5    = GCRY_MD_MD5,
    SSH_HMAC_RMD160 = GCRY_MD_RMD160
};

enum {
    SSH_CIPHER_3DES = GCRY_CIPHER_3DES,
    SSH_CIPHER_BLOWFISH = GCRY_CIPHER_BLOWFISH,
    SSH_CIPHER_TWOFISH256 = GCRY_CIPHER_TWOFISH,
    SSH_CIPHER_AES128 = GCRY_CIPHER_AES128,
    SSH_CIPHER_CAST128 = GCRY_CIPHER_CAST5
};


enum {
    SSH_KEX_NONE           = 0,
    SSH_KEX_GROUP1         = 1,
    SSH_KEX_GROUP_EXCHANGE = 2
};


typedef struct {
    const char *name;
    int algid;
    int blksize; /* for ciphers only */
    int mode;   /* for ciphers only */
    int len;
} algorithm_list;


typedef struct {
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


typedef struct {
    unsigned int min;
    unsigned int n;
    unsigned int max;
} MSG_gexdh_request;


typedef struct {
    GCRY_MPI p;
    GCRY_MPI g;
} MSG_gexdh_group;


typedef struct {
    GCRY_MPI e;
} MSG_kexdh_init;


typedef struct {
    BSTRING k_s;    /* servers public host key */
    GCRY_MPI f;
    BSTRING sig_h;  /* signature of the hash */
} MSG_kexdh_reply;


typedef struct {
    BSTRING user;
    BSTRING svcname;
    BSTRING method;
    unsigned false:1;
    BSTRING pkalgo;
    BSTRING key;
    BSTRING sig;
} MSG_auth_request;


typedef struct {
    BSTRING pkalgo;
    BSTRING key;
} MSG_auth_pkok;


void _gsti_packet_init( GSTIHD hd );
void _gsti_packet_free( GSTIHD hd );
int  _gsti_packet_read( GSTIHD hd );
int  _gsti_packet_write( GSTIHD hd );
int  _gsti_packet_flush( GSTIHD hd );


#endif /* GSTI_PACKET_H */
