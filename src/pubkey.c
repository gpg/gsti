/* pubkey.c
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
#include <ctype.h>
#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>
#include <gcrypt.h>

#include "types.h"
#include "buffer.h"
#include "pubkey.h"
#include "api.h"
#include "memory.h"


static struct
{
  const char *algname;
  const char *key_elements;
  size_t nkey;
  const char *sig_elements;
  size_t nsig;
  const char *sec_elements;
  size_t nskey;
} pk_table[] =
{
  {"none",    "dummy", 0, "dummy", 0, "dummy", 0},
  {"ssh-dss", "pqgy",  4, "rs",    2, "x",     1},
  {"ssh-rsa", "ne",    2, "s",     1, "dpqu",  4},
  {0}
};


gcry_mpi_t
get_mpissh (gcry_mpi_t dat)
{
  gcry_mpi_t a = NULL;
  byte buf[512 + 4];
  size_t n;
  int rc;

  rc = gcry_mpi_print (GCRYMPI_FMT_SSH, buf, sizeof buf, &n, dat);
  if (!rc)
    rc = gcry_mpi_scan (&a, GCRYMPI_FMT_SSH, buf, n, NULL);
  if (!rc)
    gcry_mpi_release (dat);
  return a;
}


static gsti_error_t
sexp_get_sshmpi (gcry_sexp_t s_sig, int pktype, gcry_mpi_t sig[2])
{
  gcry_sexp_t list;
  gcry_mpi_t tmp;
  size_t n = 0;
  const char *s;
  char name[2];

  if (pktype > SSH_PK_LAST)
    return gsti_error (GPG_ERR_INV_OBJ);

  s = pk_table[pktype].sig_elements;
  while (s && n < pk_table[pktype].nsig)
    {
      name[0] = *s;
      name[1] = 0;
      list = gcry_sexp_find_token (s_sig, name, 0);
      if (!list)
	return gsti_error (GPG_ERR_INV_OBJ);

      tmp = gcry_sexp_nth_mpi (list, 1, 0);
      sig[n++] = get_mpissh (tmp);
      gcry_sexp_release (list);
      s++;
    }

  return 0;
}


static gsti_error_t
sexp_from_buffer (gcry_sexp_t * r_a, const byte * buf, size_t buflen,
                  int use_pkcs1)
{
  gsti_error_t err;
  gcry_sexp_t s_a;
  gcry_mpi_t a = NULL;
  const char * s;
  char tmp[16+1];
  int i;

  if (use_pkcs1 == 0)
    {
      err = gcry_mpi_scan (&a, GCRYMPI_FMT_USG, buf, buflen, NULL);
      if (!err)
        err = gcry_sexp_build (&s_a, NULL, "%m", a);
    }
  else
    {
      s = gcry_md_algo_name (GCRY_MD_SHA1);
      if (s == NULL || strlen (s) > 16)
        return gsti_error (GPG_ERR_BUG);
      for (i=0; i < strlen (s); i++)
        tmp[i] = tolower (s[i]);
      tmp[i] = '\0';
      err = gcry_sexp_build (&s_a, NULL,
                             "(data (flags pkcs1) (hash %s %b))",
                             tmp, buflen, buf);
    }
  
  gcry_mpi_release (a);
  *r_a = s_a;

  return err;
}


static void
free_mpi_array (gcry_mpi_t * a, size_t na)
{
  size_t i;

  if (!a)
    return;

  for (i = 0; i < na; i++)
    {
      gcry_mpi_release (a[i]);
      a[i] = NULL;
    }
}


gsti_error_t
_gsti_rsa_sign (gsti_key_t ctx, const byte * hash, gcry_mpi_t sig[2])
{
  gsti_error_t err;
  gcry_sexp_t s_hash = NULL, s_key = NULL, s_sig = NULL;
  int dlen = gcry_md_get_algo_dlen (GCRY_MD_SHA1);
  
  if (ctx->type != SSH_PK_RSA)
    return gsti_error (GPG_ERR_BUG);
  if (!ctx->secret)
    return gsti_error (GPG_ERR_INV_OBJ);
  
  err = sexp_from_buffer (&s_hash, hash, dlen, 1);
  if (!err)
    err = gcry_sexp_build (&s_key, NULL,
                           "(private-key(rsa(n%m)(e%m)(d%m)(p%m)(q%m)(u%m)))",
                           ctx->key[0],
                           ctx->key[1],
                           ctx->key[2],
                           ctx->key[3],
                           ctx->key[4],
                           ctx->key[5]);
  if (!err)
    err = gcry_pk_sign (&s_sig, s_hash, s_key);
  if (!err)
    err = sexp_get_sshmpi (s_sig, SSH_PK_RSA, sig);

  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_key);
  gcry_sexp_release (s_sig);

  sig[1] = NULL;
  return err;
}


gsti_error_t
_gsti_dss_sign (gsti_key_t ctx, const byte * hash, gcry_mpi_t sig[2])
{
  gsti_error_t err;
  gcry_sexp_t s_hash = NULL, s_key = NULL, s_sig = NULL;
  int dlen = gcry_md_get_algo_dlen (GCRY_MD_SHA1);

  if (ctx->type != SSH_PK_DSS)
    return gsti_error (GPG_ERR_BUG);
  if (!ctx->secret)
    return gsti_error (GPG_ERR_INV_OBJ);

  err = sexp_from_buffer (&s_hash, hash, dlen, 0);
  if (!err)
    err = gcry_sexp_build (&s_key, NULL,
                           "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
                           ctx->key[0],	/* p */
                           ctx->key[1],	/* q */
                           ctx->key[2],	/* g */
                           ctx->key[3],	/* y */
                           ctx->key[4] /* x */ );

  if (!err)
    err = gcry_pk_sign (&s_sig, s_hash, s_key);
  if (!err)
    err = sexp_get_sshmpi (s_sig, SSH_PK_DSS, sig);

  gcry_sexp_release (s_key);
  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_sig);

  return err;
}


gsti_error_t
_gsti_rsa_verify (gsti_key_t ctx, const byte * hash, gcry_mpi_t sig[2])
{
  gsti_error_t err;
  gcry_sexp_t s_key, s_md, s_sig;
  int dlen = gcry_md_get_algo_dlen (GCRY_MD_SHA1);

  if (ctx->type != SSH_PK_RSA)
    return gsti_error (GPG_ERR_BUG);
  
  err = sexp_from_buffer (&s_md, hash, dlen, 1);
  if (!err)
    err = gcry_sexp_build (&s_key, NULL,
                           "(public-key(rsa(n%m)(e%m)))",
                           ctx->key[0],
                           ctx->key[1]);
  if (!err)
    err = gcry_sexp_build (&s_sig, NULL,
                           "(sig-val (rsa(s%m)))", sig[0]);
  if (!err)
    err = gcry_pk_verify (s_sig, s_md, s_key);

  gcry_sexp_release (s_key);
  gcry_sexp_release (s_md);
  gcry_sexp_release (s_sig);
  sig[1] = NULL;
  
  return err;
}


gsti_error_t
_gsti_dss_verify (gsti_key_t ctx, const byte * hash, gcry_mpi_t sig[2])
{
  gsti_error_t err;
  gcry_sexp_t s_key, s_md, s_sig;
  int dlen = gcry_md_get_algo_dlen (GCRY_MD_SHA1);

  if (ctx->type != SSH_PK_DSS)
    return gsti_error (GPG_ERR_BUG);

  err = sexp_from_buffer (&s_md, hash, dlen, 0);
  if (!err)
    err = gcry_sexp_build (&s_key, NULL,
                           "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
                           ctx->key[0],	/* p */
                           ctx->key[1],	/* q */
                           ctx->key[2],	/* g */
                           ctx->key[3] /* y */ );
  if (!err)
    err = gcry_sexp_build (&s_sig, NULL,
                           "(sig-val(dsa(r%m)(s%m)))",
                           sig[0] /* r */,
                           sig[1] /* s */ );
  if (!err)
    err = gcry_pk_verify (s_sig, s_md, s_key);

  gcry_sexp_release (s_key);
  gcry_sexp_release (s_md);
  gcry_sexp_release (s_sig);

  return err;
}


gsti_error_t
_gsti_key_verify (gsti_key_t ctx, const byte * hash, gcry_mpi_t sig[2])
{
  if (!ctx)
    return gsti_error (GPG_ERR_BUG);
  switch (ctx->type)
    {
    case SSH_PK_DSS:
      return _gsti_dss_verify (ctx, hash, sig);
    case SSH_PK_RSA:
      return _gsti_rsa_verify (ctx, hash, sig);
    }
  return gsti_error (GPG_ERR_BUG);
}
    

gsti_error_t
_gsti_key_sign (gsti_key_t ctx, const byte * hash, gcry_mpi_t sig[2])
{
  if (!ctx)
    return gsti_error (GPG_ERR_BUG);
  
  switch (ctx->type)
    {
    case SSH_PK_DSS:
      return _gsti_dss_sign (ctx, hash, sig);
    case SSH_PK_RSA:
      return _gsti_rsa_sign (ctx, hash, sig);
    }
  return gsti_error (GPG_ERR_BUG);
}


static gsti_error_t
read_bstring (FILE * fp, int ismpi, BSTRING * r_a)
{
  struct stat statbuf;
  BSTRING a;
  byte buf[4];
  u32 len = 0, n;

  if (fstat (fileno (fp), &statbuf))
    return gsti_error_from_errno (errno);
  for (n = 0; n < 4; n++)
    buf[n] = fgetc (fp);
  len = buf[0] << 24 | buf[1] << 16 | buf[2] << 8 | buf[3];
  if (len > statbuf.st_size)
    {
      _gsti_log_info (0, "read_bstring: %d: string larger than file.\n", len);
      return gsti_error (GPG_ERR_INV_OBJ);
    }
  a = _gsti_bstring_make (NULL, ismpi ? len + 4 : len);
  if (ismpi)
    {
      a->d[0] = len >> 24;
      a->d[1] = len >> 16;
      a->d[2] = len >> 8;
      a->d[3] = len;
      n = 4;
    }
  else
    n = 0;
  _gsti_log_debug (0, "got string with a length of %d\n", len);
  while (len--)
    a->d[n++] = fgetc (fp);
  *r_a = a;
  return 0;
}


static gcry_mpi_t
bstring_to_sshmpi (BSTRING bstr)
{
  gcry_mpi_t a;

  if (bstr->len < 5)
    return NULL;
  if (gcry_mpi_scan (&a, GCRYMPI_FMT_SSH, bstr->d, bstr->len, NULL))
    return NULL;

  return a;
}


static gsti_error_t
read_key (FILE * fp, gsti_key_t ctx, int n, int algo, int keytype)
{
  gsti_error_t err;
  BSTRING a;
  int i;
  
  for (i = 0; i < n; i++)
    {
      err = read_bstring (fp, 1, &a);
      if (err)
	return err;
      ctx->key[i] = bstring_to_sshmpi (a);
      _gsti_bstring_free (a);
    }
  /* if the key also contains a secret key, set the secure flag for'x' */
  /* XXX do the same for RSA */
  if (keytype)
    gcry_mpi_set_flag (ctx->key[n - 1], GCRYMPI_FLAG_SECURE);
  ctx->type = algo;
  ctx->nkey = n;
  ctx->secret = keytype ? 1 : 0;
  return 0;
}


static gsti_error_t
read_rsa_key (FILE * fp, int keytype, gsti_key_t ctx)
{
  gsti_error_t err;
  BSTRING a;
  size_t n;
  
  n = pk_table[SSH_PK_RSA].nkey;
  if (keytype)
    n += pk_table[SSH_PK_RSA].nskey;
  err = read_bstring (fp, 0, &a);
  if (err)
    return err;
  if (a->len != 7 || strncmp (a->d, "ssh-rsa", 7))
    {
      _gsti_log_info (0, "read_rsa_key: %s: not a rsa key blob\n", a->d);
      _gsti_bstring_free (a);
      return gsti_error (GPG_ERR_INV_OBJ);
    }
  _gsti_bstring_free (a);
  err = read_key (fp, ctx, n, SSH_PK_RSA, keytype);
  return err;
}


static gsti_error_t
read_dss_key (FILE * fp, int keytype, gsti_key_t ctx)
{
  gsti_error_t err;
  BSTRING a;
  size_t n;

  n = pk_table[SSH_PK_DSS].nkey;
  if (keytype)
    n += pk_table[SSH_PK_DSS].nskey; /* secret key */
  err = read_bstring (fp, 0, &a);
  if (err)
    return err;
  if (a->len != 7 || strncmp (a->d, "ssh-dss", 7))
    {
      _gsti_log_info (0, "read_dss_key: %s: not a dss key blob\n", a->d);
      _gsti_bstring_free (a);
      return gsti_error (GPG_ERR_INV_OBJ);
    }
  _gsti_bstring_free (a);
  err = read_key (fp, ctx, n, SSH_PK_DSS, keytype);
  return err;
}


static gsti_error_t
parse_key_entry (FILE * fp, int pktype, int keytype, gsti_key_t * r_ctx)
{
  gsti_error_t err;
  gsti_key_t ctx;

  ctx = _gsti_xcalloc (1, sizeof *ctx);
  ctx->type = SSH_PK_NONE;
  switch (pktype)
    {
    case SSH_PK_DSS:
      err = read_dss_key (fp, keytype, ctx);
      break;

    case SSH_PK_RSA:
      err = read_rsa_key (fp, keytype, ctx);
      break;
      
    default:
      err = gsti_error (GPG_ERR_GENERAL);
      break;
    }
  *r_ctx = ctx;
  return err;
}


static int
pktype_from_file (FILE * fp)
{
  gsti_error_t err;
  BSTRING a;
  int type;

  err = read_bstring (fp, 0, &a);
  fseek (fp, 0, SEEK_SET);
  if (err)
    return 0;
  if (a->len == 7 && !strcmp (a->d, "ssh-dss"))
    type = SSH_PK_DSS;
  else if (a->len == 7 && !strcmp (a->d, "ssh-rsa"))
    type = SSH_PK_RSA;
  else
    type = 0;
  _gsti_bstring_free (a);
  return type;
}


/* Read a public key from the given file.  It is expected that the
   file contains one key and as a result, only the first record will
   be read!  */
gsti_error_t
gsti_key_load (const char *file, int keytype, gsti_key_t *r_ctx)
{
  gsti_error_t err;
  FILE *inp;
  int pktype;

  inp = fopen (file, "rb");
  if (!inp)
    return gsti_error_from_errno (errno);
  pktype = pktype_from_file (inp);
  err = parse_key_entry (inp, pktype, keytype, r_ctx);
  fclose (inp);
  return err;
}


gsti_error_t
gsti_key_save (const char * file, int secpart, gsti_key_t ctx)
{
  gsti_error_t err = 0;
  BSTRING dat = NULL;
  FILE * outp;
  int i, n;
  
  if (!file || !ctx)
    return gsti_error (GPG_ERR_INV_ARG);

  outp = fopen (file, "wb");
  if (!outp)
    return gsti_error_from_errno (errno);
  dat = _gsti_key_getblob (ctx);
  if (dat)
    fwrite (dat->d, 1, dat->len, outp);
  _gsti_bstring_free (dat);
  if (secpart)
    {
      byte buf[512];
      size_t nbuf=0;
      
      n = ctx->nkey + pk_table[ctx->type].nskey;
      for (i = ctx->nkey; i < n; i++)
        {
          if (gcry_mpi_print (GCRYMPI_FMT_SSH, buf, sizeof buf-1,
                              &nbuf, ctx->key[i]) == 0)
            fwrite (buf, 1, nbuf, outp);
        }
    }
  fclose (outp);
  return err;
}


gsti_error_t
_gsti_ssh_cmp_pkname (int pktype, const char *name, size_t len)
{
  const char *s;

  if (pktype > SSH_PK_LAST)
    return gsti_error (GPG_ERR_INV_OBJ);
  s = pk_table[pktype].algname;
  if (strlen (s) != len)
    return gsti_error (GPG_ERR_INV_OBJ);
  if (strncmp (pk_table[pktype].algname, name, strlen (s)))
    return gsti_error (GPG_ERR_INV_OBJ);

  return 0;
}


gsti_error_t
_gsti_ssh_cmp_keys (gsti_key_t a, gsti_key_t b)
{
  size_t n;

  if (a->type != b->type)
    return gsti_error (GPG_ERR_INV_OBJ);
  for (n = 0; n < a->nkey; n++)
    {
      if (gcry_mpi_cmp (a->key[n], b->key[n]))
	return gsti_error (GPG_ERR_INV_OBJ);
    }

  return 0;
}


byte *
_gsti_ssh_get_pkname (int pktype, int asbstr, size_t * r_n)
{
  const char *s;
  size_t len, n = 0;
  byte *p;

  if (pktype > SSH_PK_LAST)
    return NULL;
  s = pk_table[pktype].algname;
  len = strlen (s);
  if (asbstr)
    n = 4;
  p = _gsti_xmalloc (n + len + 1);
  if (asbstr)
    {
      p[0] = len >> 24;
      p[1] = len >> 16;
      p[2] = len >> 8;
      p[3] = len;
    }
  memcpy (p + n, s, len);
  p[n + len] = 0;
  *r_n = n + len;
  return p;
}


static int
pkalgo_get_nkey (int algid, const char *name)
{
  const char *s;
  int i;

  if (algid != 0 && algid < SSH_PK_LAST)
    return pk_table[algid].nkey;
  else if (name)
    {
      for (i = 0; (s = pk_table[i].algname); i++)
	{
	  if (!strncmp (s, name, strlen (s)))
	    return pk_table[i].nkey;
	}
    }
  return -1;
}


static int
check_pubalgo (const char * s)
{
  int n = strlen (s);
  if (n != 7 || strcmp (s, "ssh-dss"))
    if (n != 7 || strcmp (s, "ssh-rsa"))
      return -1;
  return 0;
}


gsti_key_t
_gsti_key_fromblob (BSTRING blob)
{
  gsti_error_t err = 0;
  BUFFER buf;
  gsti_key_t pk = NULL;
  byte * p = NULL;
  size_t n, i;

  if (blob->len == 4)
    return NULL;
  _gsti_buf_init (&buf);
  _gsti_buf_putraw (buf, blob->d, blob->len);
  p = _gsti_buf_getstr (buf, &n);
  if (check_pubalgo (p))
    {
      _gsti_free (p);
      err = gsti_error (GPG_ERR_BUG);
      goto leave;		/* not supported */
    }
  pk = _gsti_xcalloc (1, sizeof *pk);
  pk->secret = 0;
  
  for (i = 0; i < pkalgo_get_nkey (0, p); i++)
    {
      err = _gsti_buf_getmpi (buf, &pk->key[i], &n);
      if (err)
	goto leave;
    }
  /* XXX generic code */
  if (strstr (p, "dss"))
    pk->type = SSH_PK_DSS;
  else
    pk->type = SSH_PK_RSA;
  pk->nkey = pk_table[pk->type].nkey;
 leave:
  _gsti_free (p);
  _gsti_buf_free (buf);
  return pk;
}

BSTRING
_gsti_key_getblob (gsti_key_t pk)
{
  BUFFER buf;
  BSTRING a;
  byte *p;
  size_t n;

  if (!pk || pk->type > SSH_PK_LAST)
    return _gsti_bstring_make (NULL, 4);
  _gsti_buf_init (&buf);
  p = _gsti_ssh_get_pkname (pk->type, 0, &n);
  _gsti_buf_putstr (buf, p, n);
  for (n = 0; n < pk_table[pk->type].nkey; n++)
    _gsti_buf_putmpi (buf, pk->key[n]);
  
  a = _gsti_bstring_make (_gsti_buf_getptr (buf), _gsti_buf_getlen (buf));

  _gsti_free (p);
  _gsti_buf_free (buf);

  return a;
}


byte *
gsti_key_fingerprint (gsti_key_t ctx, int mdalgo)
{
  gpg_error_t err;
  gcry_md_hd_t hd;
  byte buf[512], *hash, *name;
  size_t n = sizeof buf - 1;
  int i, dlen;

  if (!ctx)
    return NULL;
  name = _gsti_ssh_get_pkname (ctx->type, 1, &n);
  if (!name)
    return NULL;
  dlen = gcry_md_get_algo_dlen (mdalgo);
  err = gcry_md_open (&hd, mdalgo, 0);
  if (err)
    return NULL;
  gcry_md_write (hd, name, n);
  for (i = 0; i < pkalgo_get_nkey (ctx->type, NULL); i++)
    {
      if (!gcry_mpi_print (GCRYMPI_FMT_SSH, buf, sizeof buf - 1, &n,
			   ctx->key[i]))
	gcry_md_write (hd, buf, n);
    }
  gcry_md_final (hd);
  hash = gcry_xmalloc (dlen + 1);
  hash[dlen] = 0;
  memcpy (hash, gcry_md_read (hd, 0), dlen);
  gcry_md_close (hd);
  _gsti_free (name);

  return hash;
}


void
gsti_key_free (gsti_key_t ctx)
{
  if (!ctx)
    return;

  free_mpi_array (ctx->key, ctx->nkey);
  _gsti_free (ctx);
}


gsti_error_t
_gsti_sig_decode (BSTRING key, BSTRING sig, const byte * hash,
		  gsti_key_t * r_pk)
{
  gsti_error_t err;
  BUFFER buf;
  gsti_key_t pk;
  gcry_mpi_t _sig[2];
  byte *p = NULL, tmpbuf[20];
  size_t n;

  pk = _gsti_key_fromblob (key);
  if (!pk)
    return gsti_error (GPG_ERR_INV_OBJ);
  _gsti_buf_init (&buf);
  _gsti_buf_putraw (buf, sig->d, sig->len);
  p = _gsti_buf_getstr (buf, &n);
  if (check_pubalgo (p))
    {
      err = gsti_error (GPG_ERR_INV_OBJ);
      goto leave;
    }
  _gsti_free (p);
  p = _gsti_buf_getstr (buf, &n);
  if (pk->type == SSH_PK_DSS && n != 40)
    {
      err = gsti_error (GPG_ERR_BUG);
      goto leave;
    }

  if (pk->type == SSH_PK_DSS)
    {
      /* There is no separation for the both mpis so we say the first
         has a maximum of 160 bits (20 bytes). */
      memcpy (tmpbuf, p, 20);
      err = gcry_mpi_scan (&_sig[0], GCRYMPI_FMT_USG, tmpbuf, 20, NULL);
      if (!err)
        {
          memcpy (tmpbuf, p+20, 20);
          err = gcry_mpi_scan (&_sig[1], GCRYMPI_FMT_USG, tmpbuf, 20, NULL);
        }
    }
  else
    {
      err = gcry_mpi_scan (&_sig[0], GCRYMPI_FMT_USG, p, n, NULL);
      _sig[1] = NULL;
    }
  if (!err)
    err = _gsti_key_verify (pk, hash, _sig);
  free_mpi_array (_sig, 2);

 leave:
  _gsti_free (p);
  _gsti_buf_free (buf);
  if (!err && r_pk)
    *r_pk = pk;
  return err;
}


BSTRING
_gsti_sig_encode (gsti_key_t sk, const byte * hash)
{
  gsti_error_t err;
  gcry_mpi_t sig[2];
  BUFFER buf;
  BSTRING a;
  byte *p, buffer[256];
  size_t n, n2;

  if (!sk)
    return _gsti_bstring_make (NULL, 4);
  err = _gsti_key_sign (sk, hash, sig);
  if (err)
    {
      _gsti_log_info (0, "signing failed err=%d\n", err);
      return NULL;
    }
  p = _gsti_ssh_get_pkname (sk->type, 0, &n);
  _gsti_buf_init (&buf);
  _gsti_buf_putstr (buf, p, n);

  if (sk->type == SSH_PK_DSS)
    {
      err = gcry_mpi_print (GCRYMPI_FMT_USG, buffer, sizeof buffer - 1, &n,
                            sig[0]);
      if (!err)
        err = gcry_mpi_print (GCRYMPI_FMT_USG, buffer + n, sizeof buffer - 1,
                              &n2, sig[1]);
      if (!err)
        _gsti_buf_putstr (buf, buffer, n + n2);
    }
  else
    {
      err = gcry_mpi_print (GCRYMPI_FMT_USG, buffer, sizeof buffer-1,
                            &n, sig[0]);
      if (!err)
        _gsti_buf_putstr (buf, buffer, n);
      sig[1] = NULL;
    }
  
  free_mpi_array (sig, 2);

  a = _gsti_bstring_make (_gsti_buf_getptr (buf), _gsti_buf_getlen (buf));

  _gsti_free (p);
  _gsti_buf_free (buf);
  if (err)
    {
      _gsti_log_info (0, "sig: mpi encoding failed %s\n", gsti_strerror (err));
      _gsti_bstring_free (a);
      return NULL;
    }
  return a;
}


static gcry_mpi_t
read_one_mpi (gcry_sexp_t s_key, const char * val)
{
  gcry_sexp_t lst;
  gcry_mpi_t a;

  lst = gcry_sexp_find_token (s_key, val, 0);
  if (!lst)
    return NULL;
  a = gcry_sexp_nth_mpi (lst, 1, 0);
  gcry_sexp_release (lst);
  return a;
}


static int
read_pk_algo (gcry_sexp_t s_key)
{
  gcry_sexp_t lst;
  int algo = SSH_PK_NONE;
  
  if (!s_key)
    return SSH_PK_NONE;
  /* XXX iterate over the pubkey table */
  if ((lst = gcry_sexp_find_token (s_key, "rsa", 0)))
    algo = SSH_PK_RSA;
  else if ((lst = gcry_sexp_find_token (s_key, "dss", 0)))
    algo = SSH_PK_DSS;
  gcry_sexp_release (lst);
  return algo;
}


gsti_error_t
gsti_key_from_sexp (void * ctx_key, gsti_key_t * r_key)
{
    gcry_sexp_t sec=NULL, s_key;
  gsti_key_t key;
  const char * s;
  char tmp[2];
  int algo, i;
  
  if (!ctx_key || !r_key)
    return gsti_error (GPG_ERR_INV_ARG);
  s_key = ctx_key;
  algo = read_pk_algo (s_key);
  if (algo == SSH_PK_NONE)
    return gsti_error (GPG_ERR_INV_OBJ);
  sec = gcry_sexp_find_token (s_key, "private-key", 0);
  *r_key = key = _gsti_xcalloc (1, sizeof * key);
  key->type = algo;
  key->nkey = pk_table[algo].nkey;
  key->secret = sec? 1 : 0;
  gcry_sexp_release (sec);
  s = pk_table[algo].key_elements;
  for (i=0; s && *s; i++, s++)
    {
      tmp[0] = *s;
      tmp[1] = 0;
      key->key[i] = read_one_mpi (s_key, tmp);
    }
  if (key->secret == 0)
    return 0;
  key->nkey += pk_table[algo].nskey;
  s = pk_table[algo].sec_elements;
  for (;s && *s; i++, s++)
    {
      tmp[0] = *s;
      tmp[1] = 0;
      key->key[i] = read_one_mpi (s_key, tmp);
    }
  return 0;
}
