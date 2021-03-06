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


static int check_pubalgo (const char * s, int slen, int * algid);

static struct
{
  const char *algname;
  const char *key_elements;
  size_t npkey;
  const char *sig_elements;
  size_t nsig;
  const char *sec_elements;
  size_t nskey;
  gsti_key_type_t algid;
} pk_table[] =
{
  {"none",    "dummy", 0, "dummy", 0, "dummy", 0, SSH_PK_NONE},
  {"ssh-dss", "pqgy",  4, "rs",    2, "x",     1, SSH_PK_DSS},
  {"ssh-rsa", "en",    2, "s",     1, "dpqu",  4, SSH_PK_RSA},
  {0}
};


gcry_mpi_t
get_mpissh (gcry_mpi_t dat)
{
  gcry_mpi_t a = NULL;
  gpg_error_t rc;
  size_t n;
  byte buf[512+4];

  rc = gcry_mpi_print (GCRYMPI_FMT_SSH, buf, sizeof buf, &n, dat);
  if (!rc)
    rc = gcry_mpi_scan (&a, GCRYMPI_FMT_SSH, buf, n, NULL);
  if (!rc)
    gcry_mpi_release (dat);
  return a;
}


static gsti_error_t
sexp_get_sshmpi (gcry_sexp_t s_sig, gsti_key_type_t pktype, gcry_mpi_t sig[2])
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
      err = gcry_sexp_build (&s_a, NULL, "(data (flags pkcs1) (hash %s %b))",
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
_gsti_rsa_sign (gsti_key_t ctx, const void *data, size_t datalen,
                gcry_mpi_t sig[2])
{
  gsti_error_t err;
  gcry_sexp_t s_hash = NULL, s_key = NULL, s_sig = NULL;
  unsigned char sha1_digest[20];
  
  if (ctx->type != SSH_PK_RSA)
    return gsti_error (GPG_ERR_BUG);
  if (!ctx->secret && !ctx->sign_fnc)
    return gsti_error (GPG_ERR_INV_OBJ);
  
  gcry_md_hash_buffer (GCRY_MD_SHA1, sha1_digest, data, datalen);
  err = sexp_from_buffer (&s_hash, sha1_digest, sizeof sha1_digest, 1);
  if (!err)
    {
      /* Usually it does not make sense to use a public key for signing.
         However if the callback is used, it might want to use the public
         key for looking up the private key; in particular for smartcards
         this is very useful.  */
      if (ctx->nkey == 2)
        err = gcry_sexp_build (&s_key, NULL,
                               "(puplic-key(rsa(e%m)(n%m)))",
                               ctx->key[0],
                               ctx->key[1]);
      else if (ctx->nkey == 6)
        err = gcry_sexp_build (&s_key, NULL,
                        "(private-key(rsa(e%m)(n%m)(d%m)(p%m)(q%m)(u%m)))",
                               ctx->key[0],
                               ctx->key[1],
                               ctx->key[2],
                               ctx->key[3],
                               ctx->key[4],
                               ctx->key[5]);
      else
        err = gsti_error (GPG_ERR_BUG);
    }

  if (!err)
    {
      if (ctx->sign_fnc)
        err = ctx->sign_fnc (ctx->sign_fnc_value, &s_sig, s_hash, s_key);
      else
        err = gcry_pk_sign (&s_sig, s_hash, s_key);
    }

  if (!err)
    err = sexp_get_sshmpi (s_sig, SSH_PK_RSA, sig);

  gcry_sexp_release (s_hash);
  gcry_sexp_release (s_key);
  gcry_sexp_release (s_sig);

  sig[1] = NULL;
  return err;
}


gsti_error_t
_gsti_dss_sign (gsti_key_t ctx, const void *data, size_t datalen,
                gcry_mpi_t sig[2])
{
  gsti_error_t err;
  gcry_sexp_t s_hash = NULL, s_key = NULL, s_sig = NULL;
  unsigned char sha1_digest[20];

  if (ctx->type != SSH_PK_DSS)
    return gsti_error (GPG_ERR_BUG);
  if (!ctx->secret && !ctx->sign_fnc)
    return gsti_error (GPG_ERR_INV_OBJ);

  gcry_md_hash_buffer (GCRY_MD_SHA1, sha1_digest, data, datalen);
  err = sexp_from_buffer (&s_hash, sha1_digest, sizeof sha1_digest, 0);
  if (!err)
    {
      /* Usually it does not make sense to use a public key for signing.
         However if the callback is used, it might want to use the public
         key for looking up the private key; in particular for smartcards
         this is very useful.  */
      if (ctx->nkey == 4)
        err = gcry_sexp_build (&s_key, NULL,
                               "(public-key(dsa(p%m)(q%m)(g%m)(y%m)))",
                               ctx->key[0],	/* p */
                               ctx->key[1],	/* q */
                               ctx->key[2],	/* g */
                               ctx->key[3]	/* y */);
      if (ctx->nkey == 5)
        err = gcry_sexp_build (&s_key, NULL,
                               "(private-key(dsa(p%m)(q%m)(g%m)(y%m)(x%m)))",
                               ctx->key[0],	/* p */
                               ctx->key[1],	/* q */
                               ctx->key[2],	/* g */
                               ctx->key[3],	/* y */
                               ctx->key[4] /* x */ );

      else
        err = gsti_error (GPG_ERR_BUG);
    }

  if (!err)
    {
      if (ctx->sign_fnc)
        err = ctx->sign_fnc (ctx->sign_fnc_value, &s_sig, s_hash, s_key);
      else
        err = gcry_pk_sign (&s_sig, s_hash, s_key);
    }
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
                           "(public-key(rsa(e%m)(n%m)))",
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
    default:
      return gsti_error (GPG_ERR_BUG);
    }
}
    

gsti_error_t
_gsti_key_sign (gsti_key_t ctx, const void *data, size_t datalen,
                gcry_mpi_t sig[2])
{
  if (!ctx)
    return gsti_error (GPG_ERR_BUG);
  
  switch (ctx->type)
    {
    case SSH_PK_DSS:
      return _gsti_dss_sign (ctx, data, datalen, sig);
    case SSH_PK_RSA:
      return _gsti_rsa_sign (ctx, data, datalen, sig);
    default:
      return gsti_error (GPG_ERR_BUG);
    }
}


/* Read a bstring object from the stream FP and store it at the
   address A.  With ISMPI set to true, the function assumes that the
   bstring contains an multi precision integer value and prepends the
   length as a 4 byte big endian value. */
static gsti_error_t
read_bstring (FILE * fp, int ismpi, gsti_bstr_t * r_a)
{
  struct stat statbuf;
  gsti_error_t err;
  gsti_bstr_t a;
  byte buf[4];
  u32 len = 0, n;
  byte *data;

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
  err = gsti_bstr_make (&a, NULL, ismpi ? len + 4 : len);
  if (err)
      return err;
  data = gsti_bstr_data (a);
  if (ismpi)
    {
      *(data++) = len >> 24;
      *(data++) = len >> 16;
      *(data++) = len >> 8;
      *(data++) = len;
    }
  _gsti_log_debug (0, "got string with a length of %d\n", len);
  while (len--)
    *(data++) = fgetc (fp);

  *r_a = a;
  return 0;
}


static gcry_mpi_t
bstring_to_sshmpi (gsti_bstr_t bstr)
{
  gcry_mpi_t a;

  if (gsti_bstr_length (bstr) < 5)
    return NULL;
  if (gcry_mpi_scan (&a, GCRYMPI_FMT_SSH, gsti_bstr_data (bstr),
		     gsti_bstr_length (bstr), NULL))
    return NULL;

  return a;
}


static gsti_error_t
read_key (FILE * fp, gsti_key_t ctx, int n, int algo, int keytype)
{
  gsti_error_t err;
  gsti_bstr_t a;
  int i;
  
  for (i = 0; i < n; i++)
    {
      err = read_bstring (fp, 1, &a);
      if (err)
	return err;
      ctx->key[i] = bstring_to_sshmpi (a);
      gsti_bstr_free (a);
    }
  /* XXX the GCRYMPI_FLAG_SECURE casues a segfault at the end in
     gsti_key_free, so do not use it for the moment */
  ctx->type = algo;
  ctx->nkey = n;
  ctx->secret = keytype ? 1 : 0;
  return 0;
}


/* Read an RSA key into the key context CTX.  Assume a secret key when
   KEYTYPE is true. */
static gsti_error_t
read_rsa_key (FILE * fp, int keytype, gsti_key_t ctx)
{
  gsti_error_t err;
  gsti_bstr_t a;
  size_t n;

  /* Get the properties of the key, check the name and start reading
     the elements. */
  n = pk_table[SSH_PK_RSA].npkey;
  if (keytype)
    n += pk_table[SSH_PK_RSA].nskey;
  err = read_bstring (fp, 0, &a);
  if (err)
    return err;
  if (gsti_bstr_length (a) != 7 || strncmp (gsti_bstr_data (a), "ssh-rsa", 7))
    {
      _gsti_log_info (0, "read_rsa_key: %s: not a rsa key blob\n",
		      gsti_bstr_data (a));
      gsti_bstr_free (a);
      return gsti_error (GPG_ERR_INV_OBJ);
    }
  gsti_bstr_free (a);
  err = read_key (fp, ctx, n, SSH_PK_RSA, keytype);
  return err;
}


static gsti_error_t
read_dss_key (FILE * fp, int keytype, gsti_key_t ctx)
{
  gsti_error_t err;
  gsti_bstr_t a;
  size_t n;

  n = pk_table[SSH_PK_DSS].npkey;
  if (keytype)
    n += pk_table[SSH_PK_DSS].nskey; /* secret key */
  err = read_bstring (fp, 0, &a);
  if (err)
    return err;
  if (gsti_bstr_length (a) != 7 || strncmp (gsti_bstr_data (a), "ssh-dss", 7))
    {
      _gsti_log_info (0, "read_dss_key: %s: not a dss key blob\n",
		      gsti_bstr_data (a));
      gsti_bstr_free (a);
      return gsti_error (GPG_ERR_INV_OBJ);
    }
  gsti_bstr_free (a);
  err = read_key (fp, ctx, n, SSH_PK_DSS, keytype);
  return err;
}


/* Create a new key object and fill read in the object. */
static gsti_error_t
parse_key_entry (FILE * fp, gsti_key_type_t pktype, int keytype,
		 gsti_key_t * r_ctx)
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


/* Start reading from FP and expect the name of the public key
   algorithm. Return its type. */
static gsti_key_type_t
pktype_from_file (FILE * fp)
{
  gsti_error_t err;
  gsti_bstr_t a;
  int type = 0;

  err = read_bstring (fp, 0, &a);
  fseek (fp, 0, SEEK_SET); /* Rewind. */
  if (err)
    return 0;
  check_pubalgo (gsti_bstr_data (a), gsti_bstr_length (a), &type);
  gsti_bstr_free (a);
  return type;
}


/* Read a public or secret key from the given file.  It is expected
   that the file contains one key and as a result, only the first
   record will be read!  */
gsti_error_t
gsti_key_load (const char *file, int keytype, gsti_key_t *r_ctx)
{
  gsti_error_t err;
  FILE *inp;
  gsti_key_type_t pktype;

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
  gsti_bstr_t dat = NULL;
  FILE * outp;
  int i, n;
  
  if (!file || !ctx)
    return gsti_error (GPG_ERR_INV_ARG);

  err = _gsti_key_getblob (ctx, &dat);
  if (err)
      return err;
  outp = fopen (file, "wb");
  if (!outp)
    {
      gsti_bstr_free (dat);
      return gsti_error_from_errno (errno);
    }
  fwrite (gsti_bstr_data (dat), 1, gsti_bstr_length (dat), outp);
  gsti_bstr_free (dat);
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
_gsti_ssh_cmp_pkname (gsti_key_type_t pktype, const char *name, size_t len)
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


gsti_error_t
_gsti_ssh_get_pkname (gsti_key_type_t pktype, int asbstr, byte ** r_namebuf,
		      size_t * r_n)
{
  const char *s;
  size_t len, n = 0;
  byte *p;

  if (pktype > SSH_PK_LAST)
    return gsti_error (GPG_ERR_PUBKEY_ALGO);
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
  *r_namebuf = p;
  return 0;
}


static int
pkalgo_get_npkey (int algid, const char *name)
{
  const char *s;
  int i;

  if (algid != 0 && algid < SSH_PK_LAST)
    return pk_table[algid].npkey;
  else if (name)
    {
      for (i = 0; (s = pk_table[i].algname); i++)
	{
	  if (!strncmp (s, name, strlen (s)))
	    return pk_table[i].npkey;
	}
    }
  return -1;
}


static int
check_pubalgo (const char * s, int slen, int * algid)
{
  int i;
  
  for (i=0; i < SSH_PK_LAST; i++)
    {
      if (slen != strlen (pk_table[i].algname))
        continue;
      if (!strncmp (s, pk_table[i].algname, slen))
        {
          if (algid)
            *algid = pk_table[i].algid;
          return 0;
        }
    }
  return -1;
}


gsti_error_t
_gsti_key_fromblob (gsti_bstr_t blob, gsti_key_t * r_key)
{
  gsti_error_t err = 0;
  gsti_buffer_t buf;
  gsti_key_t pk = NULL;
  char *p = NULL;
  size_t n, i;
  int algid;

  *r_key = NULL;
  if (gsti_bstr_length (blob) == 4)
    return 0;

  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putraw (buf, gsti_bstr_data (blob), gsti_bstr_length (blob));
  if (err)
    goto leave;

  err = gsti_buf_getstr (buf, &p, &n);
  if (err)
    goto leave;

  if (check_pubalgo (p, strlen (p), &algid))
    {
      _gsti_free (p);
      err = gsti_error (GPG_ERR_PUBKEY_ALGO);
      goto leave;		/* not supported */
    }
  pk = _gsti_xcalloc (1, sizeof *pk);
  pk->secret = 0;
  
  for (i = 0; i < pkalgo_get_npkey (0, p); i++)
    {
      err = gsti_buf_getmpi (buf, &pk->key[i]);
      if (err)
	goto leave;
    }
  pk->type = algid;
  pk->nkey = pk_table[pk->type].npkey;
  
 leave:
  _gsti_free (p);
  gsti_buf_free (buf);
  *r_key = pk;
  return err;
}

gsti_error_t
_gsti_key_getblob (gsti_key_t pk, gsti_bstr_t * r_blob)
{
  gsti_buffer_t buf;
  gsti_bstr_t a;
  gsti_error_t err;
  unsigned char *p;
  size_t n;

  *r_blob = NULL;
  if (!pk || pk->type > SSH_PK_LAST)
    {
      err = gsti_bstr_make (r_blob, NULL, 4);
      if (!err)
          err = gsti_error (GPG_ERR_NO_SECKEY);
      return err;
    }
  err = gsti_buf_alloc (&buf);
  if (err)
    return err;
  err = _gsti_ssh_get_pkname (pk->type, 0, &p, &n);
  if (!err)
    err = gsti_buf_putstr (buf, (char*)p, n);
  if (err)
    {
      gsti_buf_free (buf);
      return err;
    } 
  for (n = 0; n < pk_table[pk->type].npkey; n++)
    {
      err = gsti_buf_putmpi (buf, pk->key[n]);
      if (err)
        {
          gsti_buf_free (buf);
          return err;
        }
    }
  err = gsti_bstr_make (&a, gsti_buf_getptr (buf), gsti_buf_readable (buf));

  _gsti_free (p);
  gsti_buf_free (buf);
  *r_blob = a;
  return err;
}


gsti_error_t
gsti_key_fingerprint (gsti_key_t ctx, int mdalgo, byte ** r_fprbuf)
{
  gpg_error_t err;
  gcry_md_hd_t hd;
  byte buf[512], *hash, *name;
  size_t n = sizeof buf - 1;
  int i, dlen;

  *r_fprbuf = NULL;
  if (!ctx)
    return gsti_error (GPG_ERR_INV_ARG);
  err = _gsti_ssh_get_pkname (ctx->type, 1, &name, &n);
  if (err)
    return err;
  dlen = gcry_md_get_algo_dlen (mdalgo);
  err = gcry_md_open (&hd, mdalgo, 0);
  if (err)
    {
      _gsti_free (name);
      return err;
    }
  gcry_md_write (hd, name, n);
  for (i = 0; i < pkalgo_get_npkey (ctx->type, NULL); i++)
    {
      if (!gcry_mpi_print (GCRYMPI_FMT_SSH, buf, sizeof buf - 1, &n,
			   ctx->key[i]))
	gcry_md_write (hd, buf, n);
    }
  gcry_md_final (hd);
  hash = _gsti_xmalloc (dlen + 1);
  hash[dlen] = 0;
  memcpy (hash, gcry_md_read (hd, 0), dlen);
  gcry_md_close (hd);
  _gsti_free (name);
  *r_fprbuf = hash;
  return 0;
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
_gsti_sig_decode (gsti_bstr_t key, gsti_bstr_t sig, const byte *hash,
		  gsti_key_t *r_pk)
{
  gsti_error_t err;
  gsti_buffer_t buf;
  gsti_key_t pk;
  gcry_mpi_t _sig[2];
  char *p = NULL, tmpbuf[20];
  size_t n;

  err = _gsti_key_fromblob (key, &pk);
  if (err)
    return err;

  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putraw (buf, gsti_bstr_data (sig), gsti_bstr_length (sig));
  if (err)
    goto leave;

  err = gsti_buf_getstr (buf, &p, &n);
  if (err)
    goto leave;

  if (check_pubalgo (p, strlen (p), NULL))
    {
      err = gsti_error (GPG_ERR_INV_OBJ);
      goto leave;
    }
  _gsti_free (p);
  p = NULL;

  err = gsti_buf_getstr (buf, &p, &n);
  if (err)
    goto leave;
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
  gsti_buf_free (buf);
  if (!err && r_pk)
    *r_pk = pk;
  return err;
}


/* Create a signature for HASH using the key SK and return the
   signature at R_SIG. */
gsti_error_t
_gsti_sig_encode (gsti_key_t sk, const void *data, size_t datalen,
                  gsti_bstr_t * r_sig)
{
  gsti_error_t err;
  gcry_mpi_t sig[2];
  gsti_buffer_t buf;
  gsti_bstr_t a;
  unsigned char *p = NULL, buffer[256];
  size_t n, n2;

  *r_sig = NULL;
  if (!sk)
    {
      err = gsti_bstr_make (r_sig, NULL, 4);
      return err;
    }
  err = _gsti_key_sign (sk, data, datalen, sig);
  if (err)
    {
      _gsti_log_info (0, "signing failed: %s\n", gsti_strerror (err));
      return err;
    }
  err = _gsti_ssh_get_pkname (sk->type, 0, &p, &n);
  if (!err)
    err = gsti_buf_alloc (&buf);
  if (err)
    {
      free_mpi_array (sig, 2);
      return err;
    }
  err = gsti_buf_putstr (buf, (char*)p, n);
  _gsti_free (p);
  p = NULL;
  if (err)
    {
      free_mpi_array (sig, 2);
      gsti_buf_free (buf);
      return err;
    }
  if (sk->type == SSH_PK_DSS)
    {
      err = gcry_mpi_print (GCRYMPI_FMT_USG, buffer, sizeof buffer - 1, &n,
                            sig[0]);
      if (!err)
        err = gcry_mpi_print (GCRYMPI_FMT_USG, buffer + n, sizeof buffer - 1,
                              &n2, sig[1]);
      if (!err)
	err = gsti_buf_putstr (buf, (char*)buffer, n + n2);
    }
  else
    {
      err = gcry_mpi_print (GCRYMPI_FMT_USG, buffer, sizeof buffer-1,
                            &n, sig[0]);
      if (!err)
        err = gsti_buf_putstr (buf, (char*)buffer, n);
      sig[1] = NULL;
    }
  
  free_mpi_array (sig, 2);

  if (!err)
    err = gsti_bstr_make (&a, gsti_buf_getptr (buf), gsti_buf_readable (buf));

  gsti_buf_free (buf);
  
  if (err)
    {
      _gsti_log_info (0, "sig: mpi encoding failed %s\n", gsti_strerror (err));
      gsti_bstr_free (a); a=NULL;
    }
  *r_sig = a;
  return err;
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
  gcry_sexp_t lst = NULL;
  const char * s;
  int algo = SSH_PK_NONE;
  int i;
  
  if (!s_key)
    return SSH_PK_NONE;
  for (i=0; (s = pk_table[i].algname); i++)
    {
      lst = gcry_sexp_find_token (s_key, s+4, 0); /* skip 'ssh-' */
      if (lst)
        {
          algo = pk_table[i].algid;
          break;
        }
      gcry_sexp_release (lst);
      lst = NULL;
    }
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
  key->nkey = pk_table[algo].npkey;
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
