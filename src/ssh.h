/* ssh.h - Important SSH constants.
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
   along with GSTI; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  */

#ifndef _GSTI_SSH_H
#define _GSTI_SSH_H	1

/* Values for a boolean.  */
#define SSH_FALSE	0
#define SSH_TRUE	1

/* List separator.  */
#define SSH_SEPARATOR	','


/* Protocol versions.  */
#define SSH_IDENT_PREFIX	"SSH-"
#define SSH_IDENT_PREFIX_LEN	(sizeof (SSH_IDENT_PREFIX) - 1)
#define SSH_VERSION_COMPAT	"1.99"
#define SSH_VERSION_2		"2.0"


/* Transport Layer 5.2 Compression.  */
/* Required.  */
#define SSH_COMPRESSION_NONE	"none"
/* Optional.  */
#define SSH_COMPRESSION_ZLIB	"zlib"


/* Transport Layer 5.3 Encryption.  */
/* Required.  */
#define SSH_CIPHER_3DES_CBC		"3des-cbc"
/* Recommended.  */
#define SSH_CIPHER_AES128_CBC		"aes128-cbc"
/* Optional.  */
#define SSH_CIPHER_NONE			"none"
#define SSH_CIPHER_BLOWFISH_CBC		"blowfish-cbc"
#define SSH_CIPHER_TWOFISH256_CBC	"twofish256-cbc"
#define SSH_CIPHER_TWOFISH_CBC		"twofish-cbc"
#define SSH_CIPHER_TWOFISH192_CBC	"twofish192-cbc"
#define SSH_CIPHER_TWOFISH128_CBC	"twofish128-cbc"
#define SSH_CIPHER_AES256_CBC		"aes256-cbc"
#define SSH_CIPHER_AES192_CBC		"aes192-cbc"
#define SSH_CIPHER_SERPENT256_CBC	"serpent256-cbc"
#define SSH_CIPHER_SERPENT192_CBC	"serpent192-cbc"
#define SSH_CIPHER_SERPENT128_CBC	"serpent128-cbc"
#define SSH_CIPHER_ARCFOUR		"arcfour"
#define SSH_CIPHER_IDEA_CBC		"idea-cbc"
#define SSH_CIPHER_CAST128_CBC		"cast128-cbc"


/* Transport Layer 5.4 Data Integrity.  */
/* Required.  */
#define SSH_MAC_HMAC_SHA1	"hmac-sha1"
/* Recommended.  */
#define SSH_MAC_HMAC_SHA1_96	"hmac-sha1-96"
/* Optional.  */
#define SSH_MAC_NONE		"none"
#define SSH_MAC_HMAC_MD5	"hmac-md5"
#define SSH_MAC_HMAC_MD5_96	"hmac-md5-96"


/* Transport Layer 5.5 Key Exchange Methods.  */
/* Required.  */
#define SSH_KEX_DHG1_SHA1	"diffie-hellman-group1-sha1"


/* Transport Layer 5.6 Public Key Algorithms.  */
/* Required.  */
#define SSH_PKA_SSH_DSS		"ssh-dss"
/* Recommended.  */
#define SSH_PKA_SSH_RSA		"ssh-rsa"
/* Optional.  */
#define SSH_PKA_X509V3_SIGN_RSA	"x509v3-sign-rsa"
#define SSH_PKA_X509V3_SIGN_DSS	"x509v3-sign-dss"
#define SSH_PKA_SPKI_SIGN_RSA	"spki-sign-rsa"
#define SSH_PKA_SPKI_SIGN_DSS	"spki-sign-dss"
#define SSH_PKA_PGP_SIGN_RSA	"pgp-sign-rsa"
#define SSH_PKA_PGP_SIGN_DSS	"pgp-sign-dss"


/* Transport Layer 10.1 Disconnection Message.  */
typedef enum
  {
    SSH_DISCONNECT_HOST_NOT_ALLOWED_TO_CONNECT = 1,
    SSH_DISCONNECT_PROTOCOL_ERROR = 2,
    SSH_DISCONNECT_KEY_EXCHANGE_FAILED = 3,
    SSH_DISCONNECT_RESERVED = 4,
    SSH_DISCONNECT_MAC_ERROR = 5,
    SSH_DISCONNECT_COMPRESSION_ERROR = 6,
    SSH_DISCONNECT_SERVICE_NOT_AVAILABLE = 7,
    SSH_DISCONNECT_PROTOCOL_VERSION_NOT_SUPPORTED = 8,
    SSH_DISCONNECT_HOST_KEY_NOT_VERIFIABLE = 9,
    SSH_DISCONNECT_CONNECTION_LOST = 10,
    SSH_DISCONNECT_BY_APPLICATION = 11,
    SSH_DISCONNECT_TOO_MANY_CONNECTIONS = 12,
    SSH_DISCONNECT_AUTH_CANCELLED_BY_USER = 13,
    SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE = 14,
    SSH_DISCONNECT_ILLEGAL_USER_NAME = 15
  }
ssh_disconnect_code_t;


/* Authentication.  */
#define SSH_AUTH_NONE		"none"
#define SSH_AUTH_PUBLICKEY	"publickey"
#define SSH_AUTH_PASSWORD	"password"
#define SSH_AUTH_HOSTBASED	"hostbased"


/* Message Numbers.  */
typedef enum
  {
    /* Transport Layer 11 Summary of Message Numbers.  */
    SSH_MSG_DISCONNECT = 1,
    SSH_MSG_IGNORE = 2,
    SSH_MSG_UNIMPLEMENTED = 3,
    SSH_MSG_DEBUG = 4,
    SSH_MSG_SERVICE_REQUEST = 5,
    SSH_MSG_SERVICE_ACCEPT = 6,

    SSH_MSG_KEXINIT = 20,
    SSH_MSG_NEWKEYS = 21,

    SSH_MSG_KEXDH_INIT = 30,
    SSH_MSG_KEXDH_REPLY = 31,

    /* FIXME: Where is this defined?  */
    SSH_MSG_KEX_DH_GEX_GROUP = 31,
    SSH_MSG_KEX_DH_GEX_INIT = 32,
    SSH_MSG_KEX_DH_GEX_REPLY = 33,
    SSH_MSG_KEX_DH_GEX_REQUEST = 34,

    /* Authentication 3.2 Authentication Protocol Message Numbers.  */
    SSH_MSG_USERAUTH_REQUEST = 50,
    SSH_MSG_USERAUTH_FAILURE = 51,
    SSH_MSG_USERAUTH_SUCCESS = 52,
    SSH_MSG_USERAUTH_BANNER = 53,

    /* Authentication 3.3 "publickey".  */
    SSH_MSG_USERAUTH_PK_OK = 60,

    /* Authentication 3.4 "password".  */
    SSH_MSG_USERAUTH_PASSWORD_CHANGEREQ = 60,

    /* Connection 9 Summary of Message Numbers.  */
    SSH_MSG_GLOBAL_REQUEST = 80,
    SSH_MSG_REQUEST_SUCCESS = 81,
    SSH_MSG_REQUEST_FAILURE = 82,
    SSH_MSG_CHANNEL_OPEN = 90,
    SSH_MSG_CHANNEL_OPEN_CONFIRMATION = 91,
    SSH_MSG_CHANNEL_OPEN_FAILURE = 92,
    SSH_MSG_CHANNEL_WINDOW_ADJUST = 93,
    SSH_MSG_CHANNEL_DATA = 94,
    SSH_MSG_CHANNEL_EXTENDED_DATA = 95,
    SSH_MSG_CHANNEL_EOF = 96,
    SSH_MSG_CHANNEL_CLOSE = 97,
    SSH_MSG_CHANNEL_REQUEST = 98,
    SSH_MSG_CHANNEL_SUCCESS = 99,
    SSH_MSG_CHANNEL_FAILURE = 100
  }
ssh_msg_id_t;


/* Connection 5.1 Opening a Channel.  */
typedef enum
  {
    SSH_OPEN_ADMINISTRATIVELY_PROHIBITED = 1,
    SSH_OPEN_CONNECT_FAILED = 2,
    SSH_OPEN_UNKNOWN_CHANNEL_TYPE = 3,
    SSH_OPEN_RESOURCE_SHORTAGE = 4
  }
ssh_open_code_t;


#endif	/* _GSTI_SSH_H */
