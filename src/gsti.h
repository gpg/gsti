/* gsti.h -  GNU Secure Transport Initiative (gsti)
   Copyright (C) 1999, 2000 Werner Koch
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

#ifndef _GSTI_H
#define _GSTI_H

#include <stdarg.h>

#include <gpg-error.h>


#ifdef __GNUC__
#define _GSTI_INLINE __inline__
#elif __STDC_VERSION__ >= 199901L
#define _GSTI_INLINE inline
#else
#define _GSTI_INLINE
#endif

#ifdef __cplusplus
extern "C"
{
#if 0
}				/*(keep Emacs' auto-indent happy) */
#endif
#endif


/* The version of this header should match the one of the library It
   should not be used by a program because gcry_check_version() should
   reurn the same version.  The purpose of this macro is to let
   autoconf (using the AM_PATH_GSTI macro) check that this header
   matches the installed library.

   NOTE: Please do not chnange the formatting of this line; configure
   may set it to the correct version.  */
#define GSTI_VERSION "0.3.0-cvs"


/* I/O subsystem.  For now just a wrapper around the system I/O.  */
#include <stdio.h>

typedef FILE *gio_stream_t;


/* Error management.  */
typedef gpg_error_t gsti_error_t;
typedef gpg_err_code_t gsti_err_code_t;
typedef gpg_err_source_t gsti_err_source_t;


static _GSTI_INLINE gsti_error_t
gsti_err_make (gsti_err_source_t source, gsti_err_code_t code)
{
  return gpg_err_make (source, code);
}


/* The user can define GSTI_ERR_SOURCE_DEFAULT before including this
   file to specify a default source for gsti_error.  */
#ifndef GSTI_ERR_SOURCE_DEFAULT
#define GSTI_ERR_SOURCE_DEFAULT  GPG_ERR_SOURCE_USER_1
#endif


static _GSTI_INLINE gsti_error_t
gsti_error (gsti_err_code_t code)
{
  return gsti_err_make (GSTI_ERR_SOURCE_DEFAULT, code);
}


static _GSTI_INLINE gsti_err_code_t
gsti_err_code (gsti_error_t err)
{
  return gpg_err_code (err);
}


static _GSTI_INLINE gsti_err_source_t
gsti_err_source (gsti_error_t err)
{
  return gpg_err_source (err);
}


/* Return a pointer to a string containing a description of the error
   code in the error value ERR.  This function is not thread safe.  */
const char *gsti_strerror (gsti_error_t err);

/* Return the error string for ERR in the user-supplied buffer BUF of
   size BUFLEN.  This function is, in contrast to gpg_strerror,
   thread-safe if a thread-safe strerror_r() function is provided by
   the system.  If the function succeeds, 0 is returned and BUF
   contains the string describing the error.  If the buffer was not
   large enough, ERANGE is returned and BUF contains as much of the
   beginning of the error string as fits into the buffer.  */
int gsti_strerror_r (gpg_error_t err, char *buf, size_t buflen);


/* Return a pointer to a string containing a description of the error
   source in the error value ERR.  */
const char *gsti_strsource (gsti_error_t err);


/* Retrieve the error code for the system error ERR.  This returns
   GPG_ERR_UNKNOWN_ERRNO if the system error is not mapped (report
   this).  */
gsti_err_code_t gsti_err_code_from_errno (int err);


/* Retrieve the system error for the error code CODE.  This returns 0
   if CODE is not a system error code.  */
int gsti_err_code_to_errno (gsti_err_code_t code);

  
/* Return an error value with the error source SOURCE and the system
   error ERR.  */
gsti_error_t gsti_err_make_from_errno (gsti_err_source_t source, int err);


/* Return an error value with the system error ERR.  */
gsti_err_code_t gsti_error_from_errno (int err);


enum gsti_ctl_cmds
{
  GSTI_DISABLE_LOCKING = 1,
  GSTI_SECMEM_INIT = 2,
  GSTI_SECMEM_RELEASE = 3,
};


enum gsti_hmac_algos
{
  GSTI_HMAC_SHA1 = 0,
  GSTI_HMAC_SHA1_96 = 1,
  GSTI_HMAC_MD5 = 2,
  GSTI_HMAC_MD5_96 = 3,
  GSTI_HMAC_RMD160 = 4,
};

enum gsti_cipher_algos
{
  GSTI_CIPHER_3DES = 0,
  GSTI_CIPHER_BLOWFISH = 1,
  GSTI_CIPHER_CAST128 = 2,
  GSTI_CIPHER_TWOFISH = 3,
  GSTI_CIPHER_AES128 = 4,
};

enum gsti_digest_algos
{
  GSTI_DIGEST_MD5 = 1,
  GSTI_DIGEST_SHA1 = 2,
};

enum gsti_pk_algos
{
  GSTI_PK_DSS = 1,
  GSTI_PK_RSA = 2,  
};

enum gsti_auth_methods
{
  GSTI_AUTH_PUBLICKEY = 1
};


/* The context type.  */
struct gsti_context;
typedef struct gsti_context *gsti_ctx_t;


/* Some handy types.  */
typedef int (*GSTI_READ_FNC) (gsti_ctx_t ctx, void *, size_t *);
typedef int (*GSTI_WRITE_FNC) (gsti_ctx_t ctx, const void *, size_t);

typedef struct
{
  size_t datalen;
  const unsigned char *data;
  unsigned long seqno;
} GSTI_PKTDESC;

struct gsti_key_s;
typedef struct gsti_key_s *gsti_key_t;
typedef struct gsti_key_s *GSTI_KEY;


/*-- main.c --*/
/* general */
const char *gsti_check_version (const char *req_version);
void gsti_control (enum gsti_ctl_cmds ctl);

/* api */
gsti_ctx_t gsti_init (void);
void gsti_deinit (gsti_ctx_t ctx);
gsti_error_t gsti_set_readfnc (gsti_ctx_t ctx, GSTI_READ_FNC readfnc);
gsti_error_t gsti_set_writefnc (gsti_ctx_t ctx, GSTI_WRITE_FNC writefnc);
gsti_error_t gsti_set_service (gsti_ctx_t ctx, const char *svcname);
gsti_error_t gsti_read (gsti_ctx_t ctx, void *buffer, size_t * length);
gsti_error_t gsti_write (gsti_ctx_t ctx, const void *buffer, size_t length);
gsti_error_t gsti_set_hostkey (gsti_ctx_t ctx, const char *file);
gsti_error_t gsti_set_client_key (gsti_ctx_t ctx, const char *file);
gsti_error_t gsti_set_client_user (gsti_ctx_t ctx, const char *user);
gsti_error_t gsti_set_auth_method (gsti_ctx_t ctx, int methd);
gsti_error_t gsti_set_compression (gsti_ctx_t ctx, int val);
gsti_error_t gsti_set_dhgex (gsti_ctx_t ctx, unsigned int min, unsigned int n,
			     unsigned int max);


/* Logging interface.  */

typedef enum
  {
    GSTI_LOG_NONE = 0,
    GSTI_LOG_INFO = 128,
    GSTI_LOG_DEBUG = 256,

    /* This also enforces a minimum width for the used integer type.  */
    GSTI_LOG_MAX = (1 << 30)
  }
gsti_log_level_t;

/* Set the log stream for the context CTX to STREAM.  */
gsti_error_t gsti_set_log_stream (gsti_ctx_t ctx, gio_stream_t stream);

/* Set the maximum level up to which messages are passed to the log
   handler for the context CTX.  */
void gsti_set_log_level (gsti_ctx_t ctx, gsti_log_level_t level);


/*-- fsm.c --*/
gsti_error_t gsti_get_packet (gsti_ctx_t ctx, GSTI_PKTDESC * pkt);
gsti_error_t gsti_put_packet (gsti_ctx_t ctx, GSTI_PKTDESC * pkt);


/*-- pubkey.c --*/
gsti_error_t gsti_key_load (const char *file, int keytype, gsti_key_t * r_ctx);
unsigned char *gsti_key_fingerprint (gsti_key_t ctx, int mdalgo);
void gsti_key_free (gsti_key_t ctx);


#ifdef __cplusplus
#if 0
{				/*(keep Emacs' auto-indent happy) */
#endif
}
#endif

#endif	/* _GSTI_H */
