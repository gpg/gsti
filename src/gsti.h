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
   should not be used by a program because gsti_check_version() should
   reurn the same version.  The purpose of this macro is to let
   autoconf (using the AM_PATH_GSTI macro) check that this header
   matches the installed library.

   NOTE: Please do not chnange the formatting of this line; configure
   may set it to the correct version.  */
#define GSTI_VERSION "0.3.0-cvs"


/* I/O subsystem.  For now just a wrapper around the system I/O.  */
#include <stdio.h>

typedef FILE *gio_stream_t;


/* Basic types.  */
typedef unsigned char gsti_byte_t;
typedef unsigned int gsti_uint32_t;


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


/* FIXME: there is no gcrypt mapping possible if we have two hmac
   modes for the same algorithm */
enum gsti_hmac_algos
{
  GSTI_HMAC_SHA1 = 2,
  /*GSTI_HMAC_SHA1_96 = 1,*/
  GSTI_HMAC_MD5 = 1,
  /*GSTI_HMAC_MD5_96 = 3,*/
  GSTI_HMAC_RMD160 = 3,
};

enum gsti_cipher_algos
{
  GSTI_CIPHER_3DES = 2,
  GSTI_CIPHER_BLOWFISH = 4,
  GSTI_CIPHER_CAST128 = 3,
  GSTI_CIPHER_TWOFISH = 10,
  GSTI_CIPHER_AES128 = 7,
  GSTI_CIPHER_SERPENT128 = 304,
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

enum gsti_prefs
{
  GSTI_PREFS_ENCR  = 1,
  GSTI_PREFS_HMAC  = 2,
  GSTI_PREFS_COMPR = 3
};

enum gsti_auth_ids
{
  GSTI_AUTHID_USER   = 1,
  GSTI_AUTHID_PUBKEY = 2
};

/* The context type.  */
struct gsti_context;
typedef struct gsti_context *gsti_ctx_t;

struct gsti_auth_s;
typedef struct gsti_auth_s *gsti_auth_t;

/* Some handy types.  */
typedef gsti_error_t (*gsti_read_fnc_t)(void *, void *, size_t, size_t *);
typedef gsti_error_t (*gsti_write_fnc_t)(void *, const void *, size_t, size_t *);


struct gsti_pktdesc_s
{
  size_t datalen;
  const unsigned char *data;
  unsigned long seqno;
};
typedef struct gsti_pktdesc_s * gsti_pktdesc_t;

struct gsti_key_s;
typedef struct gsti_key_s *gsti_key_t;


/* Hmmm, we depend on Libgcrypt here.  Should we really do this or
   better change the callback typedef to take canonical encoded
   S-expressions? */
#include <gcrypt.h>
typedef gsti_error_t (*gsti_sign_fnc_t) (void *, gcry_sexp_t *result,
                                         gcry_sexp_t data, gcry_sexp_t skey);


typedef gsti_error_t (*gsti_auth_cb_t) (void *, int statcode,
                                        const void * buf, size_t buflen);

/*-- main.c --*/
/* general */
const char *gsti_check_version (const char *req_version);
void gsti_control (enum gsti_ctl_cmds ctl);

gsti_key_t gsti_get_auth_key (gsti_ctx_t ctx);

/* api */
gsti_error_t gsti_init (gsti_ctx_t * r_ctx);
void gsti_deinit (gsti_ctx_t ctx);
gsti_error_t gsti_set_readfnc (gsti_ctx_t ctx, gsti_read_fnc_t readfnc,
                               void * opaque);
gsti_error_t gsti_set_writefnc (gsti_ctx_t ctx, gsti_write_fnc_t writefnc,
                                void * opaque);
gsti_error_t gsti_set_service (gsti_ctx_t ctx, const char *svcname);
gsti_error_t gsti_read (gsti_ctx_t ctx, void *buffer, size_t * length);
gsti_error_t gsti_write (gsti_ctx_t ctx, const void *buffer, size_t length);
gsti_error_t gsti_set_hostkey (gsti_ctx_t ctx, const char *file);
gsti_key_t   gsti_get_hostkey (gsti_ctx_t ctx);
gsti_error_t gsti_set_client_key (gsti_ctx_t ctx, const char *file);
gsti_error_t gsti_set_client_key_blob (gsti_ctx_t ctx,
                                       const unsigned char *key, size_t keylen,
                                       gsti_sign_fnc_t sign_fnc,
                                       void *sign_fnc_value);
gsti_error_t gsti_set_client_user (gsti_ctx_t ctx, const char *user);
gsti_error_t gsti_set_auth_method (gsti_ctx_t ctx, int methd);
gsti_error_t gsti_set_auth_callback (gsti_ctx_t ctx, gsti_auth_cb_t fnc,
                                     void * fnc_value);
gsti_error_t gsti_set_compression (gsti_ctx_t ctx, int val);
gsti_error_t gsti_set_dhgex (gsti_ctx_t ctx, unsigned int min, unsigned int n,
			     unsigned int max);
gsti_error_t gsti_set_kex_prefs (gsti_ctx_t ctx, enum gsti_prefs type,
                                 const unsigned short * prefs, size_t n);


/* Logging interface.  */

typedef enum
  {
    GSTI_LOG_NONE = 0,
    GSTI_LOG_INFO = 128,
    GSTI_LOG_DEBUG = 256,

    GSTI_LOG_CONT = (1<<16),

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
gsti_error_t gsti_get_packet (gsti_ctx_t ctx, gsti_pktdesc_t pkt);
gsti_error_t gsti_put_packet (gsti_ctx_t ctx, gsti_pktdesc_t pkt);


/*-- pubkey.c --*/
gsti_error_t gsti_key_load (const char *file, int keytype, gsti_key_t * r_ctx);
gsti_error_t gsti_key_save (const char *file, int secpart, gsti_key_t ctx);
gsti_error_t gsti_key_fingerprint (gsti_key_t ctx, int mdalgo,
                                   unsigned char ** r_fprbuf);
gsti_error_t gsti_key_from_sexp (void * ctx_key, gsti_key_t * r_key);
void gsti_key_free (gsti_key_t ctx);

/*-- auth.c --*/
gsti_error_t gsti_auth_new (gsti_auth_t * r_ath);
void gsti_auth_free (gsti_auth_t ath);


/*-- channel.c --*/

/* This callback is invoked when data arrives on the channel.  */
typedef void (*gsti_channel_read_cb_t)
     (gsti_ctx_t ctx, gsti_uint32_t channel_id, void *read_cb_value,
      char *data, size_t amount);

/* This callback is invoked when a request is made.  */
typedef int (*gsti_channel_request_cb_t)
     (gsti_ctx_t ctx, gsti_uint32_t channel_id, void *request_cb_value,
      gsti_uint32_t request_type, char *data, size_t amount);

/* This callback is invoked when the window for sending data increases
   in size.  */
typedef void (*gsti_channel_win_adj_cb_t)
     (gsti_ctx_t ctx, gsti_uint32_t channel_id, void *win_adj_cb_value,
      gsti_uint32_t new_window_size);

/* This callback is invoked when EOF for this channel is received.  */
typedef void (*gsti_channel_eof_cb_t)
     (gsti_ctx_t ctx, gsti_uint32_t channel_id, void *eof_cb_value);

/* This callback is invoked when the channel is closed.  After this
   callback returns, the channel ID becomes invalid.  */
typedef void (*gsti_channel_close_cb_t)
     (gsti_ctx_t ctx, gsti_uint32_t channel_id, void *close_cb_value);


/* Channel sender side.  */

/* This callback is invoked when a channel opened by us was confirmed
   or failed.  It is followed up by an invocation of the window adjust
   callback as soon as window space is available (immediately if the
   initial window size is not 0).  If ERR is 0, then opening the
   channel was confirmed, and DATA points to AMOUNT bytes with the
   channel type specific data sent by the server.  Otherwise opening
   the channel failed.  ERR will contain the error code returned by
   the server (one of SSH_OPEN_ADMINISTRATIVELY_PROHIBITED,
   SSH_OPEN_CONNECT_FAILED, SSH_OPEN_UNKNOWN_CHANNEL_TYPE, and
   SSH_OPEN_RESOURCE_SHORTAGE, FIXME), and DATA will point to AMOUNT
   bytes with additional textual information (UTF-8).  If an error is
   returned, then the channel number becomes invalid as soon as the
   callback returns.  */
typedef void (*gsti_channel_open_result_cb_t)
     (gsti_ctx_t ctx, gsti_uint32_t channel_id, void *open_result_cb_value,
      unsigned int err, char *data, size_t amount);


/* Attempt to open a new channel in the context CTX.  Returns the
   channel number in CHANNEL_ID or an error if the operation does not
   succeed.  */
gsti_error_t gsti_channel_open (gsti_ctx_t ctx, gsti_uint32_t *channel_id,
				const char *channel_type,
				unsigned int initial_window_size,
				unsigned int maximum_packet_size,
				gsti_channel_open_result_cb_t open_result_cb,
				void *open_result_cb_value,
				gsti_channel_read_cb_t read_cb,
				void *read_cb_value,
				gsti_channel_request_cb_t request_cb,
				void *request_cb_value,
				gsti_channel_win_adj_cb_t win_adj_cb,
				void *win_adj_cb_value,
				gsti_channel_eof_cb_t eof_cb,
				void *eof_cb_value,
				gsti_channel_close_cb_t close_cb,
				void *close_cb_value);


/* Return our current window size for the channel CHANNEL_ID in CTX.  */
size_t gsti_channel_get_window_size (gsti_ctx_t ctx, gsti_uint32_t channel_id);

/* Return our maximum packet size for the channel CHANNEL_ID in CTX.  */
size_t gsti_channel_get_max_packet_size (gsti_ctx_t ctx,
					 gsti_uint32_t channel_id);

/* Return the maximum packet size of the other end for the channel
   CHANNEL_ID in CTX.  */
size_t gsti_channel_get_rec_max_packet_size (gsti_ctx_t ctx,
					     gsti_uint32_t channel_id);

/* Return the current window size of the other end for the channel
   CHANNEL_ID in CTX.  */
size_t gsti_channel_get_rec_window_size (gsti_ctx_t ctx,
					 gsti_uint32_t channel_id);


/* Write AMOUNT bytes of data starting from DATA to the channel
   CHANNEL_ID in the context CTX.  */
gsti_error_t gsti_channel_write (gsti_ctx_t ctx, gsti_uint32_t channel_id,
				 char *data, size_t amount);

/* Increase the window size of the channel CHANNEL_ID in the context
   CTX by BYTES_TO_ADD bytes.  */
gsti_error_t gsti_channel_window_adjust (gsti_ctx_t ctx,
					 gsti_uint32_t channel_id,
					 gsti_uint32_t bytes_to_add);

/* Send End-Of-File for this channel.  This should be done after
   sending the last byte (if the channel was not closed yet).  After
   this, no data may be sent over the channel anymore by us.  However,
   data from the other side may still be received.  */
gsti_error_t gsti_channel_eof (gsti_ctx_t ctx, gsti_uint32_t channel_id);

/* Send request to close the channel.  */
gsti_error_t gsti_channel_close (gsti_ctx_t ctx, gsti_uint32_t channel_id);


/* Channel receiver side.  */

typedef gsti_error_t (*gsti_channel_open_cb_t)
     (gsti_ctx_t ctx, gsti_uint32_t channel_id,
      void *open_cb_value, unsigned char *request, size_t request_len,
      gsti_uint32_t *init_window_size, gsti_uint32_t *max_packet_size,
      unsigned char *reply, size_t *reply_len,
      gsti_channel_read_cb_t *read_cb, void **read_cb_value,
      gsti_channel_request_cb_t *request_cb, void **request_cb_value,
      gsti_channel_win_adj_cb_t *win_adj_cb, void **win_adj_cb_value,
      gsti_channel_eof_cb_t *eof_cb, void **eof_cb_value,
      gsti_channel_close_cb_t *close_cb, void **close_cb_value);


/* Register a new channel type with the type name NAME for the context
   CTX.  The channel uses the specified open callback with the given
   hook value.  This allows the other end of a connection to attempt
   to open a channel with this type.  */
gsti_error_t
gsti_channel_add_type (gsti_ctx_t ctx, const char *name,
		       gsti_channel_open_cb_t open_cb, void *open_cb_value);


#ifdef __cplusplus
#if 0
{				/*(keep Emacs' auto-indent happy) */
#endif
}
#endif

#endif	/* _GSTI_H */
