/* main.c - Main APIs
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <gcrypt.h>

#include "types.h"
#include "buffer.h"
#include "memory.h"
#include "packet.h"
#include "api.h"
#include "kex.h"
#include "pubkey.h"

static const char *
parse_version_number (const char *s, int *number)
{
  int val = 0;

  if (*s == '0' && isdigit (s[1]))
    return NULL;		/* leading zeros are not allowed */
  for (; isdigit (*s); s++)
    {
      val *= 10;
      val += *s - '0';
    }
  *number = val;
  return val < 0 ? NULL : s;
}


static const char *
parse_version_string (const char *s, int *major, int *minor, int *micro)
{
  s = parse_version_number (s, major);
  if (!s || *s != '.')
    return NULL;
  s++;
  s = parse_version_number (s, minor);
  if (!s || *s != '.')
    return NULL;
  s++;
  s = parse_version_number (s, micro);
  if (!s)
    return NULL;
  return s;			/* patchlevel */
}


/****************
 * Check that the the version of the library is at minimum the requested one
 * and return the version string; return NULL if the condition is not
 * satisfied.  If a NULL is passed to thsi function, no check is done,
 * but the version string is simpley returned.
 */
const char *
gsti_check_version (const char *req_version)
{
  const char *ver = VERSION;
  int my_major, my_minor, my_micro;
  int rq_major, rq_minor, rq_micro;
  const char *my_plvl, *rq_plvl;

  if (!req_version)
    return ver;

  my_plvl = parse_version_string (ver, &my_major, &my_minor, &my_micro);
  if (!my_plvl)
    return NULL;		/* very strange our own version is bogus */
  rq_plvl = parse_version_string (req_version, &rq_major, &rq_minor,
				  &rq_micro);
  if (!rq_plvl)
    return NULL;		/* req version string is invalid */

  if (my_major > rq_major
      || (my_major == rq_major && my_minor > rq_minor)
      || (my_major == rq_major && my_minor == rq_minor
	  && my_micro > rq_micro)
      || (my_major == rq_major && my_minor == rq_minor
	  && my_micro == rq_micro && strcmp (my_plvl, rq_plvl) >= 0))
    {
      return ver;
    }
  return NULL;
}


void
gsti_control (enum gsti_ctl_cmds ctl)
{
  switch (ctl)
    {
    case GSTI_DISABLE_LOCKING:
      gcry_control (GCRYCTL_DISABLE_INTERNAL_LOCKING);
      break;

    case GSTI_SECMEM_INIT:
      gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
      gcry_control (GCRYCTL_DISABLE_SECMEM_WARN);
      break;

    case GSTI_SECMEM_RELEASE:
      gcry_control (GCRYCTL_TERM_SECMEM);
      break;
    }
}


gsti_error_t
gsti_init (gsti_ctx_t * r_ctx)
{
  gsti_ctx_t ctx;
  gsti_error_t err;

  ctx = _gsti_xcalloc (1, sizeof *ctx);
  _gsti_packet_init (ctx);
  _gsti_kex_set_defaults (ctx);

  err = gsti_auth_new (&ctx->auth);
  /* FIXME: Handle error.  */

  *r_ctx = ctx;
  return 0;
}


static void
_gsti_kex_free (gsti_kex_t kex)
{
  if (!kex)
    return;
  gcry_mpi_release (kex->p);
  gcry_mpi_release (kex->g);
  gsti_bstr_free (kex->h);
  gsti_bstr_free (kex->iv_a);
  gsti_bstr_free (kex->iv_b);
  gsti_bstr_free (kex->key_c);
  gsti_bstr_free (kex->key_d);
  gsti_bstr_free (kex->mac_e);
  gsti_bstr_free (kex->mac_f);
}


void
gsti_deinit (gsti_ctx_t ctx)
{
  if (!ctx)
    return;

  gsti_auth_free (ctx->auth);
  _gsti_read_stream_free (ctx->read_stream);
  _gsti_write_stream_free (ctx->write_stream);
  _gsti_strlist_free (ctx->local_services);
  gsti_bstr_free (ctx->peer_version_string);
  gsti_bstr_free (ctx->host_kexinit_data);
  gsti_bstr_free (ctx->peer_kexinit_data);
  _gsti_free (ctx->service_name);
  gsti_bstr_free (ctx->session_id);
  _gsti_kex_free (&ctx->kex);
  gcry_cipher_close (ctx->encrypt_hd);
  gcry_cipher_close (ctx->decrypt_hd);
  gsti_key_free (ctx->hostkey);
  _gsti_packet_free (ctx);
  _gsti_free (ctx);
  if (ctx->state_data)
    free (ctx->state_data);
}


gsti_error_t
gsti_set_writefnc (gsti_ctx_t ctx, gsti_write_fnc_t writefnc, void * opaque)
{
  if (!ctx)
    return gsti_error (GPG_ERR_INV_ARG);

  ctx->writefnc = writefnc;
  ctx->writectx = opaque;

  return 0;
}


/* A client can request a special service using this function.  A
   servicename must have a @ in it, so that it does not conflict with
   any standard service.  Comma and colons should be avoided in a
   service name.  If this is not used, a standard SSH service is used.
   A server must use this function to set acceptable services.  A
   client uses the first service from the list.  */
gsti_error_t
gsti_set_service (gsti_ctx_t ctx, const char *svcname)
{
  gsti_strlist_t s;

  if (!ctx)
    return gsti_error (GPG_ERR_INV_ARG);  
  if (!svcname || !*svcname)
    return 0;
  ctx->local_services = _gsti_algolist_parse (svcname, strlen (svcname));
  for (s = ctx->local_services; s; s = s->next)
    {
      if (!strchr (s->d, '@'))
	;
      _gsti_log_info (ctx, "service `%s'\n", s->d);
    }
  return 0;
}


gsti_error_t
gsti_set_hostkey (gsti_ctx_t ctx, const char *file)
{
  struct stat statbuf;

  if (!ctx)
    return gsti_error (GPG_ERR_INV_ARG);
  if (stat (file, &statbuf))
    return gsti_error_from_errno (errno);

  ctx->we_are_server = 1;
  return gsti_key_load (file, 1, &ctx->hostkey);
}


gsti_key_t
gsti_get_hostkey (gsti_ctx_t ctx)
{
  if (!ctx)
    return NULL;
  return ctx->hostkey;
}


gsti_error_t
gsti_set_client_key (gsti_ctx_t ctx, const char *file)
{
  struct stat statbuf;

  if (!ctx)
    return gsti_error (GPG_ERR_INV_ARG);
  if (stat (file, &statbuf))
    return gsti_error_from_errno (errno);

  gsti_key_free (ctx->auth->key);
  ctx->auth->key = NULL;
  return gsti_key_load (file, 1, &ctx->auth->key);
}


/* Set the client authentication key from a ssh style keyblob in KEY
   and KEYLEN.  Optionally a sign function may be assigned to the
   key. */
gsti_error_t
gsti_set_client_key_blob (gsti_ctx_t ctx,
                          const unsigned char *key, size_t keylen,
                          gsti_sign_fnc_t sign_fnc, void *sign_fnc_value)
{
  gsti_error_t err;
  gsti_bstr_t bstr;

  if (!ctx)
    return gsti_error (GPG_ERR_INV_ARG);

  err = gsti_bstr_make (&bstr, key, keylen);
  if (err)
    return err;
    
  gsti_key_free (ctx->auth->key);
  ctx->auth->key = NULL;
  err = _gsti_key_fromblob (bstr, &ctx->auth->key);
  if (!err)
    {
      ctx->auth->key->sign_fnc = sign_fnc;
      ctx->auth->key->sign_fnc_value = sign_fnc_value;
    }
  gsti_bstr_free (bstr);
  return err;
}


gsti_error_t
gsti_set_client_user (gsti_ctx_t ctx, const char *user)
{
  if (!ctx)
    return gsti_error (GPG_ERR_INV_ARG);

  _gsti_free (ctx->auth->user);
  ctx->auth->user = _gsti_xstrdup (user);

  return 0;
}

gsti_error_t
gsti_set_auth_method (gsti_ctx_t ctx, int methd)
{
  if (!ctx)
    return gsti_error (GPG_ERR_INV_ARG);

  switch (methd)
    {
    case GSTI_AUTH_PUBLICKEY:
      ctx->auth->method = methd;
      break;
    default:
      return gsti_error (GPG_ERR_PROTOCOL_VIOLATION);
    }

  return 0;
}


gsti_error_t
gsti_set_compression (gsti_ctx_t ctx, int val)
{
#ifndef USE_ZLIB
  ctx->zlib.use = 0;
  return gsti_error (GPG_ERR_NOT_IMPLEMENTED);
#else
  if (!ctx)
    return gsti_error (GPG_ERR_INV_ARG);
  ctx->zlib.use = val;
  return 0;
#endif
}



gsti_error_t
gsti_set_kex_dhgex (gsti_ctx_t ctx, unsigned int min, unsigned int n,
                    unsigned int max)
{
  if (!ctx)
    return gsti_error (GPG_ERR_INV_ARG);

  if (n < min || n > max)
    return gsti_error (GPG_ERR_INV_ARG);
  if (!n || !min || !max)
    {
      _gsti_kex_set_defaults (ctx);
      return 0;
    }

  ctx->gex.min = min;
  ctx->gex.n = n;
  ctx->gex.max = max;
  ctx->gex.used = 1;

  return 0;
}


gsti_key_t
gsti_get_auth_key (gsti_ctx_t ctx)
{
  if (!ctx)
    return NULL;
  return ctx->auth->key;
}


gsti_error_t
gsti_set_auth_callback (gsti_ctx_t ctx, gsti_auth_cb_t fnc,
                        void * fnc_value)
{
  if (!ctx)
    return gsti_error (GPG_ERR_INV_ARG);
  ctx->auth_cb = fnc;
  ctx->auth_cb_val = fnc_value;
  
  return 0;
}


gsti_error_t
gsti_set_auth_banner (gsti_ctx_t ctx, const char * data, int isfile)
{
  gsti_error_t err = 0;
  
  if (!ctx)
    gsti_error (GPG_ERR_INV_ARG);
  
  if (!isfile)
    {
      gsti_bstr_free (ctx->auth->msg);
      err = gsti_bstr_make (&ctx->auth->msg, data, strlen (data));
    }
  else
    ; /* FIXME: todo */
  return err;
}


gsti_error_t
gsti_set_kex_prefs (gsti_ctx_t ctx, enum gsti_prefs type,
                    const unsigned short * prefs, size_t n)
{
  gsti_error_t err = 0;
  int i;

  if (!ctx)
    return gsti_error (GPG_ERR_INV_ARG);
  if (!n)
    return 0;
  
  switch (type)
    {
    case GSTI_PREFS_ENCR:
      if (n > DIM (ctx->prefs.encr))
        return gsti_error (GPG_ERR_TOO_LARGE);
      err = _gsti_kex_check_alglist (type, prefs, n);
      if (!err)
        for (i=0; i < n; i++)
          ctx->prefs.encr[i] = prefs[i];
      break;

    case GSTI_PREFS_COMPR:
      if (n > DIM (ctx->prefs.compr))
        return gsti_error (GPG_ERR_TOO_LARGE);
      break;

    case GSTI_PREFS_HMAC:
      if (n > DIM (ctx->prefs.hmac))
        return gsti_error (GPG_ERR_TOO_LARGE);
      err = _gsti_kex_check_alglist (type, prefs,n );
      if (!err)
        for (i=0; i < n; i++)
          ctx->prefs.hmac[i] = prefs[i];
      break;

    default:
      return gsti_error (GPG_ERR_INV_ATTR);
    }

  return err;
}

