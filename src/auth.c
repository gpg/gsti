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

struct valid_auth_method_s
{
  const char * name;
  int id;
}
valid_auth_methods[] =
{
  {SSH_AUTH_PUBLICKEY, GSTI_AUTH_PUBLICKEY},
  {NULL},
};


static gsti_error_t read_bstring (gsti_buffer_t buf, gsti_bstr_t * r_dst);


static int
check_auth_id (const char *buf)
{
  const char * s;
  int i;

  for (i=0; (s = valid_auth_methods[i].name); i++)
    {
      if (!strncmp (buf, s, strlen (s)))
        return valid_auth_methods[i].id;
    }
  return -1; /* not supported */
}


static gsti_error_t
build_auth_banner (MSG_auth_banner * ban, packet_buffer_t pkt)
{
  gsti_error_t err;
  gsti_buffer_t buf;
  size_t len;

  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putbstr (buf, ban->msg);
  if (!err)
    err = gsti_buf_putbstr (buf, ban->lang);
  if (!err)
    {
      len = gsti_buf_readable (buf);
      pkt->type = SSH_MSG_USERAUTH_BANNER;
      pkt->payload_len = len;
      err = gsti_buf_getraw (buf, pkt->payload, len);
      assert (!err);
    }

  gsti_buf_free (buf);
  return err;
}


static gsti_error_t
parse_auth_banner (MSG_auth_banner * ban, const gsti_buffer_t buf)
{
  gsti_error_t err;
  int val;
  
  memset (ban, 0, sizeof * ban);
  if (gsti_buf_readable (buf) < (4+4))
    return gsti_error (GPG_ERR_TOO_SHORT);

  err = gsti_buf_getc (buf, &val);
  if (err || val != SSH_MSG_USERAUTH_BANNER)
    return gsti_error (GPG_ERR_INV_PACKET);

  printf ("BUFFER LEN %d\n", gsti_buf_readable (buf));
  err = read_bstring (buf, &ban->msg);
  if (!err)
    err = read_bstring (buf, &ban->lang);
  printf ("BUFFER LEN %d rc=%s\n", gsti_buf_readable (buf), gsti_strerror (err));
  if (!err && gsti_buf_readable (buf))
    err = gsti_error (GPG_ERR_INV_PACKET);
  return err;
}


static gsti_error_t
init_auth_banner (MSG_auth_banner * ban, const char * msg, size_t msglen,
                  const char * lang, size_t llen)
{
  gsti_error_t err;
  
  err = gsti_bstr_make (&ban->msg, msg? msg : NULL, msglen);
  if (!err)
    err = gsti_bstr_make (&ban->lang, NULL, 0);
  return err;
}


static void
free_auth_banner (MSG_auth_banner * ban)
{
  if (ban)
    {
      gsti_bstr_free (ban->msg);
      gsti_bstr_free (ban->lang);
    }
}


gsti_error_t
_gsti_auth_proc_banner_packet (gsti_ctx_t ctx, gsti_auth_t auth)
{
  MSG_auth_banner ban;
  gsti_error_t err;
  
  if (ctx->pkt.type != SSH_MSG_USERAUTH_BANNER)
    return gsti_error (GPG_ERR_BUG);

  memset (&ban, 0, sizeof ban);
  err = parse_auth_banner (&ban, ctx->pktbuf);
  if (!err)
    {
      auth->msg = ban.msg;
      ban.msg = NULL;
    }
  
  free_auth_banner (&ban);
  return err;
}


gsti_error_t
_gsti_auth_send_banner_packet (gsti_ctx_t ctx, gsti_auth_t auth)
{
  MSG_auth_banner ban;
  gsti_error_t err;

  memset (&ban, 0, sizeof ban);
  err = init_auth_banner (&ban, gsti_bstr_data (auth->msg),
                          gsti_bstr_length (auth->msg), NULL, 0);
  if (!err)
      err = build_auth_banner (&ban, &ctx->pkt);
  if (!err)
    err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);

  free_auth_banner (&ban);
  return err;
}


static gsti_error_t
build_auth_request (MSG_auth_request * ath, packet_buffer_t pkt)
{
  gsti_error_t err;
  gsti_buffer_t buf;
  size_t len;

  assert (pkt->size > 100);

  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putc (buf, 0);
  if (!err)
    err = gsti_buf_putbstr (buf, ath->user);
  if (!err)
    err = gsti_buf_putbstr (buf, ath->svcname);
  if (!err)
    err = gsti_buf_putbstr (buf, ath->method);
  if (!err)
    err = gsti_buf_putc (buf, ath->chk_key);
  if (!err)
    err = gsti_buf_putbstr (buf, ath->pkalgo);
  if (!err)
    err = gsti_buf_putbstr (buf, ath->key);

  if (!err && ath->sig)
    err = gsti_buf_putbstr (buf, ath->sig);

  if (!err)
    {
      len = gsti_buf_readable (buf);
      pkt->type = SSH_MSG_USERAUTH_REQUEST;
      pkt->payload_len = len;
      err = gsti_buf_getraw (buf, pkt->payload, len);
      assert (!err);
    }
  gsti_buf_free (buf);
  return err;
}


static void
free_auth_request (MSG_auth_request * ath)
{
  if (!ath)
    return;

  gsti_bstr_free (ath->user);
  gsti_bstr_free (ath->svcname);
  gsti_bstr_free (ath->method);
  gsti_bstr_free (ath->pkalgo);
  gsti_bstr_free (ath->key);
  gsti_bstr_free (ath->sig);
}


static gsti_error_t
init_auth_request (MSG_auth_request * ath, const char *user, int false,
		   gsti_key_t pk)
{
  gsti_error_t err;
  const char *svc = "ssh-userauth", *mthd = SSH_AUTH_PUBLICKEY;
  byte *p;
  size_t n;

  if (!user || !pk)
    return gsti_error (GPG_ERR_INV_ARG);

  err = gsti_bstr_make (&ath->user, user, strlen (user));
  if (err)
    return err;
  err = gsti_bstr_make (&ath->svcname, svc, strlen (svc));
  if (err)
    {
      free_auth_request (ath);
      return err;
    }
  err = gsti_bstr_make (&ath->method, mthd, strlen (mthd));
  if (err)
    {
      free_auth_request (ath);
      return err;
    }

  ath->chk_key = false;
  err = _gsti_ssh_get_pkname (pk->type, 0, &p, &n);
  if (!err)
    err = gsti_bstr_make (&ath->pkalgo, p, n);
  _gsti_free (p);
  if (err)
    {
      free_auth_request (ath);
      return err;
    }
  err = _gsti_key_getblob (pk, &ath->key);

  /* Due to the fact we need to hash the packet first before we
     can sign, we always add the signature later and not here. */

  return err;
}


static void
dump_auth_request (gsti_ctx_t ctx, MSG_auth_request * ath)
{
  /* FIXME: What we really want here are format extensions for GIO, so
     that we can dump objects by using a special format spec, eg %B,
     for a binary string.  This will also preserve the log level etc.  */
#if WE_EVENTUALLY_HAVE_A_FEATURE_COMPLETE_GIO
  _gsti_log_debug (ctx, "MSG_auth_request:\n");
  _gsti_log_debug (ctx, "user: %B\n", ath->user);
  _gsti_log_debug (ctx, "service: %B\n", ath->svcname);
  _gsti_log_debug (ctx, "method: %B\n", ath->method);
  _gsti_log_debug (ctx, "false=%d\n", ath->chk_key);
  _gsti_log_debug (ctx, "key: %B\n", ath->key);
  _gsti_log_debug (ctx, "signature: %B", ath->sig);
#else
  _gsti_log_debug (ctx, "MSG_auth_request:\n");
  _gsti_dump_bstring ("user: ", ath->user);
  _gsti_dump_bstring ("service: ", ath->svcname);
  _gsti_dump_bstring ("method: ", ath->method);
  _gsti_log_info (ctx, "false=%d\n", ath->chk_key);
  _gsti_dump_bstring ("key: ", ath->key);
  _gsti_dump_bstring ("signature: ", ath->sig);
  _gsti_log_debug (ctx, "[end MSG_auth_request]\n");
#endif
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

  err = _gsti_packet_write (ctx);
  if (!err)
      err = _gsti_packet_flush (ctx);
  return err;
}

  
  
gsti_error_t
_gsti_auth_send_success_packet (gsti_ctx_t ctx, gsti_auth_t auth)
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
_gsti_auth_proc_success_packet (gsti_ctx_t ctx, gsti_auth_t auth)
{
  packet_buffer_t pkt = &ctx->pkt;

  if (pkt->type != SSH_MSG_USERAUTH_SUCCESS)
    return gsti_error (GPG_ERR_BUG);

  if (pkt->payload_len != 1)
    return gsti_error (GPG_ERR_INV_PACKET);

  return 0;
}


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
  _gsti_free (p);

  return err;
}


static gsti_error_t
parse_auth_request (MSG_auth_request * ath, const gsti_buffer_t buf)
{
  gsti_error_t err = 0;
  int val;

  memset (ath, 0, sizeof *ath);
  if (gsti_buf_readable (buf) < (4 + 4 + 4 + 1 + 4 + 4))
    return gsti_error (GPG_ERR_TOO_SHORT);

  err = gsti_buf_getc (buf, &val);
  if (err)
    return err;
  if (val != SSH_MSG_USERAUTH_REQUEST)
    return gsti_error (GPG_ERR_BUG);

  err = read_bstring (buf, &ath->user);
  if (!err)
    err = read_bstring (buf, &ath->svcname);
  if (!err)
    err = read_bstring (buf, &ath->method);
  if (!err)
    err = gsti_buf_getbool (buf, &val);
  if (err)
      return err;
  ath->chk_key = val;

  err = read_bstring (buf, &ath->pkalgo);
  if (!err)
    err = read_bstring (buf, &ath->key);
  if (err)
    return err;
  if (gsti_buf_readable (buf))
    err = read_bstring (buf, &ath->sig);
  if (gsti_buf_readable (buf))
    err = gsti_error (GPG_ERR_INV_PACKET);

  return err;
}


static gsti_error_t
calc_sig_hash (gsti_bstr_t sessid, MSG_auth_request *ath,
	       gsti_bstr_t *r_digest)
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
  gcry_md_putc (md, ath->chk_key);
  _gsti_bstring_hash (md, ath->pkalgo);
  _gsti_bstring_hash (md, ath->key);

  gcry_md_final (md);
  err = gsti_bstr_make (r_digest, gcry_md_read (md, 0), dlen);
  gcry_md_close (md);

  return err;
}


gsti_error_t
_gsti_auth_proc_request_packet (gsti_ctx_t ctx, gsti_auth_t auth)
{
  gsti_error_t err;
  gsti_bstr_t hash = NULL;
  MSG_auth_request ath;

  if (ctx->pkt.type != SSH_MSG_USERAUTH_REQUEST)
    return gsti_error (GPG_ERR_BUG);

  err = parse_auth_request (&ath, ctx->pktbuf);
  if (err)
    return err;
  
  if (check_auth_id (gsti_bstr_data (ath.method)) == -1)
    {
      free_auth_request (&ath);
      return gsti_error (GPG_ERR_NOT_IMPLEMENTED);
    }
  if (auth->trypk == 1)
    {
      auth->user = _gsti_xstrdup (gsti_bstr_data (ath.user));
      err = gsti_bstr_make (&auth->blob, gsti_bstr_data (ath.key),
                            gsti_bstr_length (ath.key));
      if (!err)
        err = _gsti_key_fromblob (ath.key, &auth->key);
    }
  else
    {
      err = calc_sig_hash (ctx->session_id, &ath, &hash);
      if (!err)
        err = _gsti_sig_decode (ath.key, ath.sig, gsti_bstr_data (hash), NULL);
    }

  dump_auth_request (ctx, &ath);
  gsti_bstr_free (hash);
  free_auth_request (&ath);

  if (!err && auth->trypk == 1)
    auth->trypk = 0;
  
  return err;
}


static void
free_auth_pkok (MSG_auth_pkok * ok)
{
  if (!ok)
    return;

  gsti_bstr_free (ok->pkalgo);
  gsti_bstr_free (ok->key);
}


static gsti_error_t
build_pkok_packet (MSG_auth_pkok * ok, packet_buffer_t pkt)
{
  gsti_error_t err;
  gsti_buffer_t buf;
  size_t len;

  err = gsti_buf_alloc (&buf);
  if (!err)
    err = gsti_buf_putc (buf, 0);
  if (!err)
    err = gsti_buf_putbstr (buf, ok->pkalgo);
  if (!err)
    err = gsti_buf_putbstr (buf, ok->key);

  if (!err)
    {
      len = gsti_buf_readable (buf);
      pkt->type = SSH_MSG_USERAUTH_PK_OK;
      pkt->payload_len = len;
      err = gsti_buf_getraw (buf, pkt->payload, len);
      assert (!err);
    }

  gsti_buf_free (buf);
  return 0;
}


gsti_error_t
_gsti_auth_send_pkok_packet (gsti_ctx_t ctx, gsti_auth_t auth)
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
  err = _gsti_ssh_get_pkname (pk->type, 0, &p, &n);
  if (!err)
    err = gsti_bstr_make (&ok.pkalgo, p, n);
  if (err)
    {
      _gsti_free (p);
      return err;
    }
  err = _gsti_key_getblob (pk, &ok.key);
  if (!err)
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
parse_pkok_packet (MSG_auth_pkok * ok, const gsti_buffer_t buf)
{
  gsti_error_t err;
  char *p;
  size_t n;
  int val;

  memset (ok, 0, sizeof *ok);
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

  err = gsti_bstr_make (&ok->pkalgo, p, n);
  _gsti_free (p);
  if (err)
    return err;

  err = gsti_buf_getstr (buf, &p, &n);
  if (err)
    return err;

  err = gsti_bstr_make (&ok->key, p, n);
  _gsti_free (p);

  return err;
}


gsti_error_t
_gsti_auth_proc_pkok_packet (gsti_ctx_t ctx, gsti_auth_t auth)
{
  MSG_auth_pkok ok;
  gsti_error_t err;
  gsti_bstr_t alg;
  gsti_key_t a;

  if (ctx->pkt.type != SSH_MSG_USERAUTH_PK_OK)
    return gsti_error (GPG_ERR_BUG);

  err = parse_pkok_packet (&ok, ctx->pktbuf);
  if (err)
    return err;
  alg = ok.pkalgo;
  err = _gsti_ssh_cmp_pkname (auth->key->type, gsti_bstr_data (alg),
			      gsti_bstr_length (alg));
  if (!err)
    {
      err = _gsti_key_fromblob (ok.key, &a);
      if (!err)
	{
	  err = _gsti_ssh_cmp_keys (a, auth->key);
	  gsti_key_free (a);
	}
    }
  free_auth_pkok (&ok);
  return err;
}


gsti_error_t
_gsti_auth_send_request_packet (gsti_ctx_t ctx, gsti_auth_t auth)
{
  gsti_error_t err;
  gsti_bstr_t hash = NULL;
  MSG_auth_request ath;

  memset (&ath, 0, sizeof ath);
  err = init_auth_request (&ath, auth->user, auth->trypk, auth->key);
  if (auth->trypk == 0)
    {
      if (!err)
        err = calc_sig_hash (ctx->session_id, &ath, &hash);
      if (!err)
        err = _gsti_sig_encode (auth->key, gsti_bstr_data (hash), &ath.sig);
    }
  if (!err)
    err = build_auth_request (&ath, &ctx->pkt);
  if (!err)
    err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);

  free_auth_request (&ath);
  gsti_bstr_free (hash);

  if (!err && auth->trypk == 1)
    auth->trypk = 0;

  return err;
}


gsti_error_t
gsti_auth_new (gsti_auth_t * r_ath)
{
  gsti_auth_t a;

  if (!r_ath)
    return gsti_error (GPG_ERR_INV_ARG);
  a = _gsti_xcalloc (1, sizeof * a);
  a->trypk = 1;
  *r_ath = a;

  return 0;
}


void
gsti_auth_free (gsti_auth_t ath)
{
  if (!ath)
    {
      _gsti_free (ath->user);
      gsti_key_free (ath->key);
      gsti_bstr_free (ath->blob);
      gsti_bstr_free (ath->msg);
    }
}

