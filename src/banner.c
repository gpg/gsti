/* auth.c - Public key authentication
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



typedef struct
{
  gsti_bstr_t msg;
  gsti_bstr_t lang;

} MSG_auth_banner;

/* 
    Helper functions.

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





/*
   Banner stuff

 */ 

static void
dump_auth_banner (gsti_ctx_t ctx, MSG_auth_banner * ban)
{
  _gsti_log_debug (ctx, "MSG_userauth_banner:\n");
  _gsti_dump_bstring (ctx, "  msg: ", ban->msg);
  _gsti_dump_bstring (ctx, "  lang: ", ban->lang);
}
  

static gsti_error_t
build_auth_banner (MSG_auth_banner * ban, packet_buffer_t pkt)
{
  gsti_error_t err;
  gsti_buffer_t buf;
  size_t len;

  assert (pkt->size > (gsti_bstr_length (ban->msg)+8));
  
  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putc (buf, 0);
  if (!err)
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
  if (err)
    return err;
  if (val != SSH_MSG_USERAUTH_BANNER)
    return gsti_error (GPG_ERR_UNEXPECTED);
  
  err = read_bstring (buf, &ban->msg);
  if (!err)
    err = read_bstring (buf, &ban->lang);

  if (!err && gsti_buf_readable (buf))
    err = gsti_error (GPG_ERR_INV_PACKET);
  return err;
}


static gsti_error_t
init_banner (MSG_auth_banner *ban, gsti_ctx_t ctx,
             const char * lang, size_t llen)
{
  gsti_error_t err;

  if (!ctx)
    return gsti_error (GPG_ERR_INV_ARG);
  if (!lang)
    {
      lang = "en_US";
      llen = 5;
    }
  if (!ctx->banner)
    err = gsti_bstr_make (&ban->msg, "", 0);
  else
    err = gsti_bstr_copy (&ban->msg, ctx->banner);
  if (!err)
    err = gsti_bstr_make (&ban->lang, lang, llen);
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
_gsti_auth_proc_banner_packet (gsti_ctx_t ctx)
{
  MSG_auth_banner ban;
  gsti_error_t err;
  
  if (ctx->pkt.type != SSH_MSG_USERAUTH_BANNER)
    return gsti_error (GPG_ERR_BUG);

  memset (&ban, 0, sizeof ban);
  err = parse_auth_banner (&ban, ctx->pktbuf);
  if (!err)
    {
      gsti_bstr_free (ctx->banner);
      ctx->banner = ban.msg;
      ban.msg = NULL;
    }

  dump_auth_banner (ctx, &ban);
  free_auth_banner (&ban);
  return err;
}


gsti_error_t
_gsti_auth_send_banner_packet (gsti_ctx_t ctx)
{
  MSG_auth_banner ban;
  gsti_error_t err;

  memset (&ban, 0, sizeof ban);
  err = init_banner (&ban, ctx, NULL, 0);
  if (!err)
    err = build_auth_banner (&ban, &ctx->pkt);
  if (!err)
    err = _gsti_packet_write (ctx, &ctx->pkt);
  if (!err)
    err = _gsti_packet_flush (ctx);

  dump_auth_banner (ctx, &ban);
  free_auth_banner (&ban);
  return err;
}


gsti_error_t
_gsti_banner_run_auth_cb (gsti_ctx_t ctx)
{
  if (!ctx->auth_cb)
    return 0;

  return ctx->auth_cb (ctx->auth_cb_val, GSTI_AUTHCB_BANNER,
                       gsti_bstr_data (ctx->banner),
                       gsti_bstr_length (ctx->banner));
}

