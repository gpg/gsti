/* auth.c - Userauth stuff
   Copyright (C) 2002 Timo Schulz
   Copyright (C) 2004, 2010 g10 Code GmbH

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
   Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA  */

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "types.h"
#include "utils.h"
#include "buffer.h"
#include "api.h"
#include "packet.h"
#include "pubkey.h"

struct gsti_auth_none_s
{
  unsigned int dummy;
};
typedef struct gsti_auth_none_s *gsti_auth_none_t;

struct gsti_auth_publickey_s
{
  unsigned int act:1;  /* Perform the actual authentication.  */
  gsti_bstr_t  pkalgo;  
  gsti_bstr_t  keyblob;
  gsti_bstr_t  sigblob;
  /* int trypk; */
  /* gsti_key_t key; */
  /* gsti_bstr_t blob; */
  /* gsti_bstr_t msg; */
  /* char *user; */
};
typedef struct gsti_auth_publickey_s *gsti_auth_publickey_t;

struct gsti_auth_password_s
{
  unsigned int dummy;
};
typedef struct gsti_auth_password_s *gsti_auth_password_t;

struct gsti_auth_hostbased_s
{
  unsigned int dummy;
};
typedef struct gsti_auth_hostbased_s *gsti_auth_hostbased_t;

struct gsti_auth_s
{
  gsti_bstr_t  user;                 /* The user name.  */
  gsti_bstr_t  svcname;              /* The service name.  */
  gsti_bstr_t  method;               /* The method name.  */ 
  enum gsti_auth_methods method_id;  /* The id of the above method
                                        name or 0 if unknown.  */
  union {
    struct gsti_auth_none_s      none;
    struct gsti_auth_publickey_s publickey;
    struct gsti_auth_password_s  password;
    struct gsti_auth_hostbased_s hostbased;
  } m;
};




/* 

   Helper functions

 */

/* Read a bstring and return it as a BSTR object.  */
static gsti_error_t
read_bstring (gsti_buffer_t buf, gsti_bstr_t * r_dst)
{
  gsti_error_t err;
  char *p;
  size_t n;

  err = gsti_buf_getstr (buf, &p, &n);
  if (err)
    return err;

  err = gsti_bstr_make (r_dst, p, n);
  free (p);

  return err;
}




/* Create an userauth request in PKT from the AUTH object.  */
static gsti_error_t
build_auth_request (packet_buffer_t pkt, gsti_auth_t auth)
{
  gsti_error_t err;
  gsti_buffer_t buf;
  size_t len;

  assert (pkt->size > 100);

  if (auth->method_id != GSTI_AUTH_PUBLICKEY)
    return gsti_error (GPG_ERR_NOT_SUPPORTED);

  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putc (buf, 0);
  if (!err)
    err = gsti_buf_putbstr (buf, auth->user);
  if (!err)
    err = gsti_buf_putbstr (buf, auth->svcname);
  if (!err)
    err = gsti_buf_putbstr (buf, auth->method);
  if (!err)
    err = gsti_buf_putc (buf, auth->m.publickey.act);
  if (!err)
    err = gsti_buf_putbstr (buf, auth->m.publickey.pkalgo);
  if (!err)
    err = gsti_buf_putbstr (buf, auth->m.publickey.keyblob);

  if (!err && auth->m.publickey.sigblob)
    err = gsti_buf_putbstr (buf, auth->m.publickey.sigblob);

  if (!err)
    {
      len = gsti_buf_readable (buf);
      err = gsti_buf_getraw (buf, pkt->payload, len);
      if (!err)
        {
          pkt->type = SSH_MSG_USERAUTH_REQUEST;
          pkt->payload_len = len;
        }
    }
  gsti_buf_free (buf);
  return err;
}


/* Create new auth object and store it at R_AUTH.  */
static gsti_error_t
init_auth_request (gsti_auth_t *r_auth,
                   const char *user, int act, gsti_key_t pk)
{
  gsti_error_t err;
  const char svc[] = "ssh-userauth";
  const char mthd[] = "publickey";
  gsti_auth_t auth;
  unsigned char *p;
  size_t n;

  *r_auth = NULL;

  if (!user || !pk)
    return gsti_error (GPG_ERR_INV_ARG);

  err = gsti_auth_new (&auth);
  if (err)
    return err;

  err = gsti_bstr_make (&auth->user, user, strlen (user));
  if (err)
    goto leave;
  err = gsti_bstr_make (&auth->svcname, svc, strlen (svc));
  if (err)
    goto leave;
  err = gsti_bstr_make (&auth->method, mthd, strlen (mthd));
  if (err)
    goto leave;
  auth->method_id = GSTI_AUTH_PUBLICKEY;

  auth->m.publickey.act = act;
  err = _gsti_ssh_get_pkname (pk->type, 0, &p, &n);
  if (err)
    goto leave;
  err = gsti_bstr_make (&auth->m.publickey.pkalgo, p, n);
  free (p);
  if (err)
    goto leave;

  err = _gsti_key_getblob (pk, &auth->m.publickey.keyblob);

 leave:
  if (err)
    gsti_auth_free (auth);
  else
    *r_auth = auth;
  return err;
}


static void
dump_auth_request (gsti_ctx_t ctx, gsti_auth_t auth)
{
  _gsti_log_debug (ctx, "MSG userauth_request:\n");
  if (auth)
    {
      _gsti_dump_bstring (ctx, "  user: ", auth->user);
      _gsti_dump_bstring (ctx, "  service: ", auth->svcname);
      _gsti_dump_bstring (ctx, "  method: ", auth->method);
      _gsti_log_debug (ctx,    "  method_id: %d\n", auth->method_id);
      switch (auth->method_id)
        {
        case GSTI_AUTH_PUBLICKEY:
          _gsti_log_info (ctx,     "  act: %d\n", auth->m.publickey.act);
          _gsti_dump_bstring (ctx, "  algo: ", auth->m.publickey.pkalgo);
          _gsti_dump_bstring (ctx, "  key: ", auth->m.publickey.keyblob);
          _gsti_dump_bstring (ctx, "  sig: ", auth->m.publickey.sigblob);
          break;
        default:
          break;
        }
    }
  _gsti_log_debug (ctx, "[End userauth_request]\n");
}


gsti_error_t
_gsti_auth_send_failure_packet (gsti_ctx_t ctx, gsti_auth_t auth)
{
  packet_buffer_t pkt = &ctx->pkt;
  gsti_error_t err;
  unsigned char tmp[4] = {0};

  /* For now we only support public key auth so the list is empty
     because there are no authentications which could continue. */
  pkt->type = SSH_MSG_USERAUTH_FAILURE;
  pkt->payload_len = 5;
  memcpy (pkt->payload, tmp, 4);
  pkt->payload[5] = 0;

  err = _gsti_packet_write (ctx, &ctx->pkt);
  if (!err)
      err = _gsti_packet_flush (ctx);
  return err;
}

  
  
/* Send a success packet for the last current authentication request.  */
gsti_error_t
_gsti_auth_send_success_packet (gsti_ctx_t ctx)
{
  gsti_error_t err;
  packet_buffer_t pkt = &ctx->pkt;

  pkt->type = SSH_MSG_USERAUTH_SUCCESS;
  pkt->payload_len = 1;
  err = _gsti_packet_write (ctx, &ctx->pkt);
  if (!err)
    err = _gsti_packet_flush (ctx);
  return err;
}


gsti_error_t
_gsti_auth_proc_success_packet (gsti_ctx_t ctx)
{
  packet_buffer_t pkt = &ctx->pkt;

  if (pkt->type != SSH_MSG_USERAUTH_SUCCESS)
    return gsti_error (GPG_ERR_UNEXPECTED);

  if (pkt->payload_len != 1)
    return gsti_error (GPG_ERR_INV_PACKET);

  return 0;
}


/* Parse the USERAUTH_REQUEST message in BUF and on success return a
   new auth object at R_AUTH.  */
static gsti_error_t
parse_auth_request (gsti_auth_t *r_auth, const gsti_buffer_t buf)
{
  gsti_error_t err;
  gsti_auth_t auth;
  int val;

  err = gsti_auth_new (&auth);
  if (err)
    goto leave;

  err = gsti_buf_getc (buf, &val);
  if (err)
    goto leave;
  if (val != SSH_MSG_USERAUTH_REQUEST)
    {
      err = gsti_error (GPG_ERR_BUG);
      goto leave;
    }

  err = read_bstring (buf, &auth->user);
  if (err)
    goto leave;
  err = read_bstring (buf, &auth->svcname);
  if (err)
    goto leave;
  err = read_bstring (buf, &auth->method);
  if (err)
    goto leave;

  if (!gsti_bstr_match_str_p (auth->method, "publickey"))
    {
      auth->method_id = GSTI_AUTH_PUBLICKEY;
      err = gsti_buf_getbool (buf, &val);
      if (err)
        goto leave;
      auth->m.publickey.act = val;
      
      err = read_bstring (buf, &auth->m.publickey.pkalgo);
      if (err)
        goto leave;
      err = read_bstring (buf, &auth->m.publickey.keyblob);
      if (err)
        goto leave;
      err = read_bstring (buf, &auth->m.publickey.sigblob);
      if (err)
        goto leave;

      if (gsti_buf_readable (buf))
        {
          /* Extra bytes detected.  */
          err = gsti_error (GPG_ERR_INV_PACKET);
          goto leave;
        }
    }
  else
    err = gsti_error (GPG_ERR_NOT_IMPLEMENTED);

 leave:
  if (err)
    {
      gsti_auth_free (auth);
      auth = NULL;
    }
  *r_auth = auth;
  return err;
}


/* Compute the hash for the publickey authentication as specified by
   rfc-4252.7.  SESSID is the current session id and AUTH is an object
   with the authentication data.  On success the hash is stored as a
   bstring at R_DIGEST.  */
static gsti_error_t
calc_sig_hash (gsti_bstr_t sessid, gsti_auth_t auth, gsti_bstr_t *r_digest)
{
  gsti_error_t err;
  gcry_md_hd_t md;
  int dlen = gcry_md_get_algo_dlen (GCRY_MD_SHA1);

  err = gcry_md_open (&md, GCRY_MD_SHA1, 0);
  if (err)
    {
      r_digest = NULL;
      return err;
    }
  _gsti_bstring_hash (md, sessid);
  gcry_md_putc (md, SSH_MSG_USERAUTH_REQUEST);
  _gsti_bstring_hash (md, auth->user);
  _gsti_bstring_hash (md, auth->svcname);
  _gsti_bstring_hash (md, auth->method);
  gcry_md_putc (md, auth->m.publickey.act);
  _gsti_bstring_hash (md, auth->m.publickey.pkalgo);
  _gsti_bstring_hash (md, auth->m.publickey.keyblob);

  gcry_md_final (md);
  err = gsti_bstr_make (r_digest, gcry_md_read (md, 0), dlen);
  gcry_md_close (md);

  return err;
}


/* Process a received USERAUTH_REQUEST message.  [rfc-4252.5] */
gsti_error_t
_gsti_auth_proc_request_packet (gsti_ctx_t ctx)
{
  gsti_error_t err;
  gsti_auth_t auth;

  if (ctx->pkt.type != SSH_MSG_USERAUTH_REQUEST)
    return gsti_error (GPG_ERR_UNEXPECTED);

  err = parse_auth_request (&auth, ctx->pktbuf);
  if (err)
    return err;
  dump_auth_request (ctx, auth);
  
  /* if (auth->m.publickey.act) */
  /*   { */
  /*     gsti_bstr_t hash = NULL; */
  /*     err = calc_sig_hash (ctx->session_id, auth, &hash); */
  /*     if (!err) */
  /*       err = _gsti_sig_decode (auth->m.publickey.keyblob, */
  /*                               auth->m.publickey.sigblob, */
  /*                               gsti_bstr_data (hash), NULL); */
  /*     gsti_bstr_free (hash); */
  /*   } */

  if (err)
    gsti_auth_free (auth);
  else
    {
      gsti_auth_free (ctx->auth);
      ctx->auth = auth;
    }
  
  return err;
}


static gsti_error_t
build_pkok_packet (packet_buffer_t pkt, gsti_bstr_t pkalgo, gsti_bstr_t key)
{
  gsti_error_t err;
  gsti_buffer_t buf;
  size_t len;

  err = gsti_buf_alloc (&buf);
  if (!err)
    err = gsti_buf_putc (buf, 0);
  if (!err)
    err = gsti_buf_putbstr (buf, pkalgo);
  if (!err)
    err = gsti_buf_putbstr (buf, key);

  if (!err)
    {
      len = gsti_buf_readable (buf);
      err = gsti_buf_getraw (buf, pkt->payload, len);
      if (!err)
        {
          pkt->type = SSH_MSG_USERAUTH_PK_OK;
          pkt->payload_len = len;
        }
    }

  gsti_buf_free (buf);
  return 0;
}


gsti_error_t
_gsti_auth_send_pkok_packet (gsti_ctx_t ctx)
{
  gsti_error_t err;
  gsti_key_t pk;
  gsti_bstr_t pkalgo, key;
  byte *p;
  size_t n;

  /*FIXME */
  /* pk = auth->m.publickey.keyblob; */
  /* if (!pk) */
  /*   return gsti_error (GPG_ERR_INV_OBJ); */

  err = _gsti_ssh_get_pkname (pk->type, 0, &p, &n);
  if (err)
    return err;
  err = gsti_bstr_make (&pkalgo, p, n);
  free (p);
  if (err)
    return err;

  err = _gsti_key_getblob (pk, &key);
  if (err)
    {
      gsti_bstr_free (pkalgo);
      return err;
    }

  err = build_pkok_packet (&ctx->pkt, pkalgo, key);
  gsti_bstr_free (pkalgo);
  gsti_bstr_free (key);
  if (err)
    return err;

  err = _gsti_packet_write (ctx, &ctx->pkt);
  if (!err)
    err = _gsti_packet_flush (ctx);

  return err;
}


static gsti_error_t
parse_pkok_packet (gsti_bstr_t *r_pkalgo, gsti_bstr_t *r_key,
                   const gsti_buffer_t buf)
{
  gsti_error_t err;
  char *p;
  size_t n;
  int val;
  gsti_bstr_t pkalgo, key;

  *r_pkalgo = NULL;
  *r_key = NULL;

  if (gsti_buf_readable (buf) < (4 + 4))
    return gsti_error (GPG_ERR_TOO_SHORT);

  err = gsti_buf_getc (buf, &val);
  if (err)
    return err;

  if (val != SSH_MSG_USERAUTH_PK_OK)
    return gsti_error (GPG_ERR_INV_PACKET);

  err = gsti_buf_getstr (buf, &p, &n);
  if (err)
    return err;

  err = gsti_bstr_make (&pkalgo, p, n);
  free (p);
  if (err)
    return err;

  err = gsti_buf_getstr (buf, &p, &n);
  if (err)
    {
      gsti_bstr_free (pkalgo);
      return err;
    }

  err = gsti_bstr_make (&key, p, n);
  free (p);
  if (err)
    {
      gsti_bstr_free (pkalgo);
      return err;
    }

  *r_pkalgo = pkalgo;
  *r_key = key;
  return 0;
}



gsti_error_t
_gsti_auth_proc_pkok_packet (gsti_ctx_t ctx)
{
  gsti_error_t err;
  gsti_bstr_t pkalgo, key;
  gsti_key_t a;

  if (ctx->pkt.type != SSH_MSG_USERAUTH_PK_OK)
    return gsti_error (GPG_ERR_UNEXPECTED);

  err = parse_pkok_packet (&pkalgo, &key, ctx->pktbuf);
  if (err)
    return err;
  err = _gsti_ssh_cmp_pkname (auth->m.publickey.key->type,
                              gsti_bstr_data (pkalgo),
                              gsti_bstr_length (pkalgo));
  if (!err)
    {
      err = _gsti_key_fromblob (key, &a);
      if (!err)
	{
	  err = _gsti_ssh_cmp_keys (a, auth->key);
	  gsti_key_free (a);
	}
    }
  gsti_bstr_free (pkalgo);
  gsti_bstr_free (key);
  return err;
}


gsti_error_t
_gsti_auth_send_request_packet (gsti_ctx_t ctx)
{
  /* gsti_error_t err; */
  /* gsti_bstr_t hash = NULL; */

  /* err = init_auth_request (&ath, auth->user, auth->trypk, auth->key); */
  /* if (auth->trypk == 0) */
  /*   { */
  /*     if (!err) */
  /*       err = calc_sig_hash (ctx->session_id, &ath, &hash); */
  /*     if (!err) */
  /*       err = _gsti_sig_encode (auth->key, */
  /*                               gsti_bstr_data (hash), */
  /*                               gsti_bstr_length (hash), */
  /*                               &ath.sig); */
  /*   } */
  /* if (!err) */
  /*   err = build_auth_request (&ath, &ctx->pkt); */
  /* if (!err) */
  /*   err = _gsti_packet_write (ctx, &ctx->pkt); */
  /* if (!err) */
  /*   err = _gsti_packet_flush (ctx); */

  /* free_auth_request (&ath); */
  /* gsti_bstr_free (hash); */

  /* if (!err && auth->trypk == 1) */
  /*   auth->trypk = 0; */

  return err;
}



/* Create a new authentication object and return it in R_AUTH.  */
gsti_error_t
gsti_auth_new (gsti_auth_t *r_auth)
{
  gsti_auth_t auth;

  if (!r_auth)
    return gsti_error (GPG_ERR_INV_ARG);

  auth = calloc (1, sizeof *auth);
  if (!auth)
    return gsti_error_from_errno (errno);
  
  *r_auth = auth;
  return 0;
}


/* Destroy the authentication object AUTH.  */
void
gsti_auth_free (gsti_auth_t auth)
{
  if (!auth)
    return;

  gsti_bstr_free (auth->user);
  gsti_bstr_free (auth->svcname);
  gsti_bstr_free (auth->method);
  switch (auth->method_id)
    {
    case GSTI_AUTH_UNKNOWN:
      break;

    case GSTI_AUTH_NONE:
      break;

    case GSTI_AUTH_PUBLICKEY: 
      gsti_bstr_free (auth->m.publickey.pkalgo);
      gsti_bstr_free (auth->m.publickey.keyblob);
      gsti_bstr_free (auth->m.publickey.sigblob);
      break;

    case GSTI_AUTH_PASSWORD:
      break;

    case GSTI_AUTH_HOSTBASED:
      break;
    }
  free (auth);
}


/* Run the registerted authentication callbacks.  */
gsti_error_t
_gsti_auth_run_auth_cb (gsti_ctx_t ctx)
{
  gsti_error_t err;

  if (!ctx->auth_cb || !ctx->auth)
    return 0;

  err = ctx->auth_cb (ctx->auth_cb_val, GSTI_AUTHCB_USER,
                      gsti_bstr_data (ctx->auth->user),
                      gsti_bstr_length (ctx->auth->user));
  if (!err && ctx->auth.method_id == GSTI_AUTH_PUBLICKEY)
    err = ctx->auth_cb (ctx->auth_cb_val, GSTI_AUTHCB_PUBLICKEY,
                        gsti_bstr_data (ctx->auth->m.publickey.keyblob),
                        gsti_bstr_length (ctx->auth->m.publickey.keyblob));

  return err;
}
