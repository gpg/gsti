/* auth.c - Public key authentication
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

#include <assert.h>
#include <stdio.h>

#include "types.h"
#include "utils.h"
#include "buffer.h"
#include "api.h"
#include "packet.h"
#include "memory.h"
#include "pubkey.h"


static int
check_auth_id (const char *buf)
{
  if (!strncmp (buf, SSH_AUTH_PUBLICKEY, 9))
    return GSTI_AUTH_PUBLICKEY;
  return -1;			/* not supported */
}


static gsti_error_t
build_auth_request (MSG_auth_request * ath, struct packet_buffer_s *pkt)
{
  BUFFER buf;
  size_t len;

  assert (pkt->size > 100);

  _gsti_buf_init (&buf);
  _gsti_buf_putc (buf, 0);
  _gsti_buf_putbstr (buf, ath->user);
  _gsti_buf_putbstr (buf, ath->svcname);
  _gsti_buf_putbstr (buf, ath->method);
  _gsti_buf_putc (buf, ath->false);
  _gsti_buf_putbstr (buf, ath->pkalgo);
  _gsti_buf_putbstr (buf, ath->key);
  if (ath->sig)
    _gsti_buf_putbstr (buf, ath->sig);

  len = _gsti_buf_getlen (buf);
  pkt->type = SSH_MSG_USERAUTH_REQUEST;
  pkt->payload_len = len;
  memcpy (pkt->payload, _gsti_buf_getptr (buf), len);

  _gsti_buf_free (buf);

  return 0;
}


static void
free_auth_request (MSG_auth_request * ath)
{
  if (ath)
    {
      _gsti_bstring_free (ath->user);
      _gsti_bstring_free (ath->svcname);
      _gsti_bstring_free (ath->method);
      _gsti_bstring_free (ath->pkalgo);
      _gsti_bstring_free (ath->key);
      _gsti_bstring_free (ath->sig);
    }
}


static gsti_error_t
init_auth_request (MSG_auth_request * ath, const char *user, int false,
		   gsti_key_t pk)
{
  const char *svc = "ssh-userauth", *mthd = SSH_AUTH_PUBLICKEY;
  byte *p;
  size_t n;

  if (!user || !pk)
    return gsti_error (GPG_ERR_INV_ARG);

  ath->user = _gsti_bstring_make (user, strlen (user));
  ath->svcname = _gsti_bstring_make (svc, strlen (svc));
  ath->method = _gsti_bstring_make (mthd, strlen (mthd));
  ath->false = false;
  p = _gsti_ssh_get_pkname (pk->type, 0, &n);
  ath->pkalgo = _gsti_bstring_make (p, n);
  _gsti_free (p);
  ath->key = _gsti_key_getblob (pk);

  /* Due to the fact we need to hash the packet first before we
     can sign, we always add the signature later and not here. */

  return 0;
}


static void
dump_auth_request (gsti_ctx_t ctx, MSG_auth_request * ath)
{
  /* FIXME: What we really want here are format extensions for GIO, so
     that we can dump objects by using a special format spec, eg %B,
     for a binary string.  This will also preserve the log level etc.  */
#if WE_EVENTUALLY_HAVE_A_FEATURE_COMPLETE_GIO
  _gsti_log_debug (ctx, "\nMSG_auth_request:\n");
  _gsti_log_debug (ctx, "user: %B\n", ath->user);
  _gsti_log_debug (ctx, "service: %B\n", ath->svcname);
  _gsti_log_debug (ctx, "method: %B\n", ath->method);
  _gsti_log_debug (ctx, "false=%d\n", ath->false);
  _gsti_log_debug (ctx, "key: %B\n", ath->key);
  _gsti_log_debug (ctx, "signature: %B", ath->sig);
#else
  _gsti_log_debug (ctx, "\nMSG_auth_request:\n");
  _gsti_dump_bstring ("user: ", ath->user);
  _gsti_dump_bstring ("service: ", ath->svcname);
  _gsti_dump_bstring ("method: ", ath->method);
  _gsti_log_debug (ctx, "false=%d\n", ath->false);
  _gsti_dump_bstring ("key: ", ath->key);
  _gsti_dump_bstring ("signature: ", ath->sig);
  _gsti_log_debug (ctx, "\n");
#endif
}


gsti_error_t
auth_send_accept_packet (gsti_ctx_t ctx)
{
  gsti_error_t err;
  packet_buffer_t pkt = &ctx->pkt;

  pkt->type = SSH_MSG_USERAUTH_SUCCESS;
  pkt->payload_len = 1;
  err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);
  return err;
}


gsti_error_t
auth_proc_accept_packet (gsti_ctx_t ctx)
{
  packet_buffer_t pkt = &ctx->pkt;

  if (pkt->type != SSH_MSG_USERAUTH_SUCCESS)
    return gsti_error (GPG_ERR_BUG);

  if (pkt->payload_len != 1)
    return gsti_error (GPG_ERR_INV_PACKET);

  return 0;
}


gsti_error_t
auth_send_init_packet (gsti_ctx_t ctx, gsti_auth_t auth)
{
  gsti_error_t err;
  MSG_auth_request ath;

  memset (&ath, 0, sizeof ath);
  err = init_auth_request (&ath, auth->user, 0, auth->key);
  if (!err)
    err = build_auth_request (&ath, &ctx->pkt);
  if (!err)
    err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);

  free_auth_request (&ath);
  return err;
}


static BSTRING
read_bstring (BUFFER buf)
{
  BSTRING dst = NULL;
  size_t n;
  byte *p = _gsti_buf_getstr (buf, &n);
  if (p)
    dst = _gsti_bstring_make (p, n);
  _gsti_free (p);
  return dst;
}


static gsti_error_t
parse_auth_request (MSG_auth_request * ath, const BUFFER buf)
{
  gsti_error_t err = 0;

  memset (ath, 0, sizeof *ath);
  if (_gsti_buf_getlen (buf) < (4 + 4 + 4 + 1 + 4 + 4))
    return gsti_error (GPG_ERR_TOO_SHORT);
  if (_gsti_buf_getc (buf) != SSH_MSG_USERAUTH_REQUEST)
    return gsti_error (GPG_ERR_BUG);
  ath->user = read_bstring (buf);
  ath->svcname = read_bstring (buf);
  ath->method = read_bstring (buf);
  ath->false = _gsti_buf_getc (buf);
  ath->pkalgo = read_bstring (buf);
  ath->key = read_bstring (buf);
  if (_gsti_buf_getlen (buf))
    ath->sig = read_bstring (buf);
  if (_gsti_buf_getlen (buf))
    err = gsti_error (GPG_ERR_INV_PACKET);

  return err;
}


gsti_error_t
auth_proc_init_packet (gsti_ctx_t ctx, gsti_auth_t auth)
{
  gsti_error_t err;
  MSG_auth_request ath;

  if (ctx->pkt.type != SSH_MSG_USERAUTH_REQUEST)
    return gsti_error (GPG_ERR_BUG);

  err = parse_auth_request (&ath, ctx->pktbuf);
  if (err)
    return err;
  if (check_auth_id (ath.method->d) == -1)
    {
      free_auth_request (&ath);
      return gsti_error (GPG_ERR_NOT_IMPLEMENTED);
    }
  auth->user = _gsti_xstrdup (ath.user->d);
  auth->key = _gsti_key_fromblob (ath.key);

  dump_auth_request (ctx, &ath);
  free_auth_request (&ath);
  return err;
}


static gsti_error_t
calc_sig_hash (BSTRING sessid, MSG_auth_request * ath, BSTRING * r_digest)
{
  gsti_error_t err;
  gcry_md_hd_t md;
  int dlen = gcry_md_get_algo_dlen (GCRY_MD_SHA1);

  err = gcry_md_open (&md, GCRY_MD_SHA1, 0);
  if (err)
    return err;
  _gsti_bstring_hash (md, sessid);
  gcry_md_putc (md, SSH_MSG_USERAUTH_REQUEST);
  _gsti_bstring_hash (md, ath->user);
  _gsti_bstring_hash (md, ath->svcname);
  _gsti_bstring_hash (md, ath->method);
  gcry_md_putc (md, ath->false);
  _gsti_bstring_hash (md, ath->pkalgo);
  _gsti_bstring_hash (md, ath->key);

  gcry_md_final (md);
  *r_digest = _gsti_bstring_make (gcry_md_read (md, 0), dlen);
  gcry_md_close (md);

  return 0;
}


static void
free_auth_pkok (MSG_auth_pkok * ok)
{
  if (ok)
    {
      _gsti_bstring_free (ok->pkalgo);
      _gsti_bstring_free (ok->key);
    }
}


static gsti_error_t
build_pkok_packet (MSG_auth_pkok * ok, packet_buffer_t pkt)
{
  BUFFER buf;
  size_t len;

  _gsti_buf_init (&buf);
  _gsti_buf_putc (buf, 0);
  _gsti_buf_putbstr (buf, ok->pkalgo);
  _gsti_buf_putbstr (buf, ok->key);

  len = _gsti_buf_getlen (buf);
  pkt->type = SSH_MSG_USERAUTH_PK_OK;
  pkt->payload_len = len;
  memcpy (pkt->payload, _gsti_buf_getptr (buf), len);

  _gsti_buf_free (buf);
  return 0;
}


gsti_error_t
auth_send_pkok_packet (gsti_ctx_t ctx, gsti_auth_t auth)
{
  gsti_error_t err;
  gsti_key_t pk;
  MSG_auth_pkok ok;
  byte *p;
  size_t n;

  memset (&ok, 0, sizeof ok);
  pk = auth->key;
  if (!pk)
    return gsti_error (GPG_ERR_INV_OBJ);
  p = _gsti_ssh_get_pkname (pk->type, 0, &n);
  ok.pkalgo = _gsti_bstring_make (p, n);
  ok.key = _gsti_key_getblob (pk);
  err = build_pkok_packet (&ok, &ctx->pkt);
  if (!err)
    err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);

  _gsti_free (p);
  free_auth_pkok (&ok);
  return err;
}


static gsti_error_t
parse_pkok_packet (MSG_auth_pkok * ok, const BUFFER buf)
{
  byte *p;
  size_t n;

  memset (ok, 0, sizeof *ok);
  if (_gsti_buf_getlen (buf) < (4 + 4))
    return gsti_error (GPG_ERR_TOO_SHORT);
  if (_gsti_buf_getc (buf) != SSH_MSG_USERAUTH_PK_OK)
    return gsti_error (GPG_ERR_INV_PACKET);
  p = _gsti_buf_getstr (buf, &n);
  ok->pkalgo = _gsti_bstring_make (p, n);
  _gsti_free (p);

  p = _gsti_buf_getstr (buf, &n);
  ok->key = _gsti_bstring_make (p, n);
  _gsti_free (p);

  return 0;
}


gsti_error_t
auth_proc_pkok_packet (gsti_ctx_t ctx, gsti_auth_t auth)
{
  gsti_error_t err;
  MSG_auth_pkok ok;
  BSTRING alg;

  if (ctx->pkt.type != SSH_MSG_USERAUTH_PK_OK)
    return gsti_error (GPG_ERR_BUG);

  err = parse_pkok_packet (&ok, ctx->pktbuf);
  if (err)
    return err;
  alg = ok.pkalgo;
  err = _gsti_ssh_cmp_pkname (auth->key->type, alg->d, alg->len);
  if (!err)
    {
      gsti_key_t a = _gsti_key_fromblob (ok.key);
      if (a)
	{
	  err = _gsti_ssh_cmp_keys (a, auth->key);
	  gsti_key_free (a);
	}
    }
  free_auth_pkok (&ok);
  return err;
}


gsti_error_t
auth_send_second_packet (gsti_ctx_t ctx, gsti_auth_t auth)
{
  gsti_error_t err;
  MSG_auth_request ath;
  BSTRING sig = NULL, hash;

  memset (&ath, 0, sizeof ath);
  err = init_auth_request (&ath, auth->user, 1, auth->key);
  if (!err)
    err = calc_sig_hash (ctx->session_id, &ath, &hash);
  if (!err)
    sig = _gsti_sig_encode (auth->key, hash->d);
  if (sig)
    ath.sig = sig;
  else
    goto leave;
  if (!err)
    err = build_auth_request (&ath, &ctx->pkt);
  if (!err)
    err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);

leave:
  free_auth_request (&ath);
  _gsti_bstring_free (hash);

  return err;
}


gsti_error_t
auth_proc_second_packet (gsti_ctx_t ctx, gsti_auth_t auth)
{
  gsti_error_t err;
  MSG_auth_request ath;
  BSTRING hash;

  err = parse_auth_request (&ath, ctx->pktbuf);
  if (!err)
    err = calc_sig_hash (ctx->session_id, &ath, &hash);
  if (!err)
    err = _gsti_sig_decode (ath.key, ath.sig, hash->d, NULL);

  _gsti_bstring_free (hash);
  free_auth_request (&ath);

  return err;
}


gsti_error_t
gsti_auth_new (gsti_auth_t * r_ath)
{
  gsti_auth_t a;

  if (!r_ath)
    return gsti_error (GPG_ERR_INV_ARG);
  a = _gsti_xcalloc (1, sizeof * a);
  *r_ath = a;

  return 0;
}


void
gsti_auth_free (gsti_auth_t ath)
{
  if (ath == NULL)
    return;
  _gsti_free (ath->user);
  gsti_key_free (ath->key);
}

