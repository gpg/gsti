/* kex.c - connect, key exchange and service request
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
#include <assert.h>

#include "types.h"
#include "utils.h"
#include "buffer.h"
#include "api.h"
#include "memory.h"
#include "stream.h"
#include "packet.h"
#include "kex.h"
#include "pubkey.h"
#include "moduli.h"

#define PUT32_BIT(buf, val) do { \
  *(buf)++ = (val) >> 24; \
  *(buf)++ = (val) >> 16; \
  *(buf)++ = (val) >>  8; \
  *(buf)++ = (val) >>  0; \
} while (0)


static const char host_version_string[] =
  SSH_IDENT_PREFIX SSH_VERSION_2 "-GSTI_"VERSION "GNU Transport Library";

static const byte diffie_hellman_group1_prime[130] = { 0x04, 0x00,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2,
  0x21, 0x68, 0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1,
  0x29, 0x02, 0x4E, 0x08, 0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6,
  0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A, 0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD,
  0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B, 0x30, 0x2B, 0x0A, 0x6D,
  0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51, 0xC2, 0x45,
  0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
  0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED,
  0xEE, 0x38, 0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11,
  0x7C, 0x4B, 0x1F, 0xE6, 0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};


/* The table of supported MAC algorithms.  */
static algorithm_list hmac_list[] =
  {
    /* Required.  */
    { SSH_MAC_HMAC_SHA1, SSH_HMAC_SHA1, 0, 0, 20 },

    /* Recommended.  */
    { SSH_MAC_HMAC_SHA1_96, SSH_HMAC_SHA1, 0, 0, 12 },

    /* Optional.  */
    { SSH_MAC_HMAC_MD5, SSH_HMAC_MD5, 0, 0, 16 },
    { SSH_MAC_HMAC_MD5_96, SSH_HMAC_MD5, 0, 0, 12 },

    /* Local defined extension */
    { "hmac-ripemd160@g10code.com", SSH_HMAC_RMD160, 0, 0, 20 },

    { 0 }
  };


/* The table of supported ciphers.  */
static algorithm_list cipher_list[] =
  {
    /* Required.  */
    { SSH_CIPHER_3DES_CBC,
      SSH_CIPHER_3DES, 8, GCRY_CIPHER_MODE_CBC, 24 },

    /* Optional.  */
    { SSH_CIPHER_BLOWFISH_CBC,
      SSH_CIPHER_BLOWFISH, 8, GCRY_CIPHER_MODE_CBC, 16 },
    { SSH_CIPHER_CAST128_CBC,
      SSH_CIPHER_CAST128, 8, GCRY_CIPHER_MODE_CBC, 16 },
    { SSH_CIPHER_TWOFISH256_CBC,
      SSH_CIPHER_TWOFISH256, 16, GCRY_CIPHER_MODE_CBC, 32 },

    /* Recommended.  */
    { SSH_CIPHER_AES128_CBC,
      SSH_CIPHER_AES128, 16, GCRY_CIPHER_MODE_CBC, 16 },

    { 0 }
  };


static int
cmp_bstring (gsti_bstr_t a, gsti_bstr_t b)
{
  int rc = 0;
  size_t len_a = gsti_bstr_length (a);
  size_t len_b = gsti_bstr_length (b);

  if (len_a < len_b)
    rc = -1;
  else if (len_a > len_b)
    rc = 1;
  else
    rc = memcmp (gsti_bstr_data (a), gsti_bstr_data (b), len_a);

  return rc;
}


/* Initialize the GEX parameters to defaults. */
void
_gsti_kex_set_defaults (gsti_ctx_t ctx)
{
  ctx->gex.min = MIN_GROUPSIZE;
  ctx->gex.n = 2048;
  ctx->gex.max = MAX_GROUPSIZE;  
}


gsti_error_t
kex_send_version (gsti_ctx_t ctx)
{
  gsti_error_t err;
  write_stream_t wst = ctx->write_stream;
  const char *ver = host_version_string;

  err = _gsti_stream_writen (wst, ver, strlen (ver));
  if (err)
    return err;
  err = _gsti_stream_writen (wst, "\r\n", 2);
  if (err)
    return err;

  return _gsti_stream_flush (wst);
}


/* This functions reads from the input source until it either finds a
   valid version string, which it will parse ans store away for later
   reference.  If it does not find such a string it returns an
   error.  */
gsti_error_t
kex_wait_on_version (gsti_ctx_t ctx)
{
  gsti_error_t err;
  read_stream_t rst = ctx->read_stream;
  char version[300];
  int any = 0, pos = 0;
  int c;

  /* Wait for the initial SSH_IDENT_PREFIX_LEN bytes.  */
  while ((c = _gsti_stream_get (rst)) != -1)
    {
      any = 1;

      if (c == '\n')
	pos = 0;
      else if (pos >= 0 && pos < SSH_IDENT_PREFIX_LEN)
	{
	  if (SSH_IDENT_PREFIX[pos] != c)
	    pos = -1; /* Skip this line.  */
	  else
	    {
	      pos++;

	      /* Check if we have read all of SSH_IDENT_PREFIX.  */
	      if (pos == SSH_IDENT_PREFIX_LEN)
		break;
	    }
	}
    }
  if (c == -1)
    return any ? gsti_error (GPG_ERR_PROTOCOL_VIOLATION)
      : gsti_error (GPG_ERR_NO_DATA);

  /* Store the version string.  */
  memcpy (version, SSH_IDENT_PREFIX, SSH_IDENT_PREFIX_LEN);
  c = 0;
  for (pos = SSH_IDENT_PREFIX_LEN; pos < sizeof (version) - 1; pos++)
    {
      c = _gsti_stream_get (rst);
      if (c == -1 || c == '\n')
	break;
      version[pos] = c;
    }
  if (c == -1)
    return gsti_error (GPG_ERR_PROTOCOL_VIOLATION);
  if (c != '\n')
    return gsti_error (GPG_ERR_TOO_LARGE);
  if (version[pos - 1] == '\r')
    pos--;
  version[pos] = 0;
  _gsti_free (ctx->peer_version_string);

  err = gsti_bstr_make (&ctx->peer_version_string, version, strlen (version));

  return err;
}


static void
free_msg_kexinit (MSG_kexinit * kex)
{
  if (kex)
    {
      _gsti_strlist_free (kex->kex_algo);
      _gsti_strlist_free (kex->server_host_key_algos);
      _gsti_strlist_free (kex->encr_algos_c2s);
      _gsti_strlist_free (kex->encr_algos_s2c);
      _gsti_strlist_free (kex->mac_algos_c2s);
      _gsti_strlist_free (kex->mac_algos_s2c);
      _gsti_strlist_free (kex->compr_algos_c2s);
      _gsti_strlist_free (kex->compr_algos_s2c);
    }
}


/* Parse a SSH_MSG_KEXINIT and return the parsed information in a
   newly allocated struture.  Rteurns 0 on success or an
   errorcode.  */
static gsti_error_t
parse_msg_kexinit (MSG_kexinit * kex, int we_are_server, byte * old_cookie,
		   const gsti_buffer_t buf)
{
  gsti_error_t err = 0;
  STRLIST algolist[10] = { NULL };
  char *p;
  u32 len;
  int i;
  int val;

  memset (kex, 0, sizeof *kex);
  if (gsti_buf_readable (buf) < (1 + 16 + 10 * 4 + 1 + 4))
    return gsti_error (GPG_ERR_TOO_SHORT);

  err = gsti_buf_getc (buf, &val);
  if (err)
    goto leave;
  if (val != SSH_MSG_KEXINIT)
    {
      err = gsti_error (GPG_ERR_BUG);
      goto leave;
    }

  err = gsti_buf_getraw (buf, kex->cookie, 16);
  if (err)
    goto leave;

  if (!we_are_server)
    {
      /* We skip the cookie the server sent to us. This makes sure both
         sides can calculate the same key data. Instead we use the one
         we generated.  */
      memcpy (kex->cookie, old_cookie, 16);
    }

  /* Get 10 strings.  */
  for (i = 0; i < 10; i++)
    {
      err = gsti_buf_getstr (buf, &p, &len);
      if (err)
	goto leave;

      algolist[i] = p ? _gsti_algolist_parse (p, len) : NULL;
      _gsti_free (p);
    }
  kex->kex_algo = algolist[0];
  kex->server_host_key_algos = algolist[1];
  kex->encr_algos_c2s = algolist[2];
  kex->encr_algos_s2c = algolist[3];
  kex->mac_algos_c2s = algolist[4];
  kex->mac_algos_s2c = algolist[5];
  kex->compr_algos_c2s = algolist[6];
  kex->compr_algos_s2c = algolist[7];
  /* We don't need the two language lists.  */

  err = gsti_buf_getbool (buf, &kex->first_kex_packet_follows);
  if (err)
    goto leave;

  /* Make sure that the reserved value is zero.  */
  err = gsti_buf_getuint32 (buf, &val);
  if (err)
    goto leave;
  if (val)
    {
      err = gsti_error (GPG_ERR_INV_PACKET);
      goto leave;
    }

  /* Make sure the message length matches.  */
  if (gsti_buf_readable (buf))
    err = gsti_error (GPG_ERR_INV_PACKET);

leave:
  if (err)
    {
      free_msg_kexinit (kex);
      memset (kex, 0, sizeof *kex);
    }
  return err;
}


/* Build a KEX packet.  */
static gsti_error_t
build_msg_kexinit (MSG_kexinit * kex, packet_buffer_t pkt)
{
  STRLIST algolist[10];
  byte *p = pkt->payload;
  size_t length = pkt->size, n;
  int i;

  assert (length > 100);

  pkt->type = SSH_MSG_KEXINIT;
  p++;
  length--;
  memcpy (p, kex->cookie, 16);
  p += 16;
  length -= 16;
  /* Put 10 strings.  */
  algolist[0] = kex->kex_algo;
  algolist[1] = kex->server_host_key_algos;
  algolist[2] = kex->encr_algos_c2s;
  algolist[3] = kex->encr_algos_s2c;
  algolist[4] = kex->mac_algos_c2s;
  algolist[5] = kex->mac_algos_s2c;
  algolist[6] = kex->compr_algos_c2s;
  algolist[7] = kex->compr_algos_s2c;
  algolist[8] = NULL;
  algolist[9] = NULL;
  for (i = 0; i < 10; i++)
    {
      n = _gsti_algolist_build (p, length, algolist[i]);
      if (!n)
	return gsti_error (GPG_ERR_TOO_SHORT);
      assert (n <= length);
      p += n;
      length -= n;
    }
  if (!length)
    return gsti_error (GPG_ERR_TOO_SHORT);
  *p++ = !!kex->first_kex_packet_follows;
  length--;
  if (length < 4)
    return gsti_error (GPG_ERR_TOO_SHORT);
  PUT32_BIT (p, 0); /* a reserved u32 */
  length -= 4;
  pkt->payload_len = p - pkt->payload;

  return 0;
}


static void
dump_msg_kexinit (gsti_ctx_t ctx, MSG_kexinit * kex)
{
  _gsti_log_debug (ctx, "MSG_kexinit:\n");
  _gsti_dump_hexbuf ("cookie: ", kex->cookie, 16);
  _gsti_dump_strlist ("kex_algorithm", kex->kex_algo);
  _gsti_dump_strlist ("server_host_key_algos", kex->server_host_key_algos);
  _gsti_dump_strlist ("encr_algos_c2s", kex->encr_algos_c2s);
  _gsti_dump_strlist ("encr_algos_s2c", kex->encr_algos_s2c);
  _gsti_dump_strlist ("mac_algos_c2s", kex->mac_algos_c2s);
  _gsti_dump_strlist ("mac_algos_s2c", kex->mac_algos_s2c);
  _gsti_dump_strlist ("compr_algos_c2s", kex->compr_algos_c2s);
  _gsti_dump_strlist ("compr_algos_s2c", kex->compr_algos_s2c);
  if (kex->first_kex_packet_follows)
    _gsti_log_debug (ctx, "fist_kex_packet_follows\n");
  _gsti_log_debug (ctx, "\n");
}



/* Parse a SSH_MSG_KEXDH_INIT and return the parsed information in a
   newly allocated struture.  Returns 0 on success or an
   errorcode.  */
static gsti_error_t
parse_msg_kexdh_init (MSG_kexdh_init * kexdh, const gsti_buffer_t buf)
{
  gsti_error_t err = 0;
  int val;

  memset (kexdh, 0, sizeof *kexdh);
  if (gsti_buf_readable (buf) < (1 + 4))
    return gsti_error (GPG_ERR_TOO_SHORT);

  err = gsti_buf_getc (buf, &val);
  if (err)
    goto leave;

  if (val != SSH_MSG_KEXDH_INIT)
    {
      err = gsti_error (GPG_ERR_BUG);
      goto leave;
    }
  err = gsti_buf_getmpi (buf, &kexdh->e);
  if (err)
    goto leave;

#if 0
  /* FIXME: This check is disabled, because it is bogus and needs to
     be rewritten to really compare against the mpi, and not the byte
     length.  */

  /* A value which is not in the range [1, p-1] is considered as a
     protocol violation.  */
  if ((n - 4) > sizeof diffie_hellman_group1_prime)
    return gsti_error (GPG_ERR_PROTOCOL_VIOLATION);
#endif

  /* Make sure the message length matches.  */
  if (gsti_buf_readable (buf))
    err = gsti_error (GPG_ERR_INV_PACKET);

leave:
  return err;
}


/* Build a KEXDH packet.  */
static gsti_error_t
build_msg_kexdh_init (MSG_kexdh_init * kexdh, packet_buffer_t pkt)
{
  gsti_error_t err;
  gsti_buffer_t buf = NULL;
  size_t len;

  assert (pkt->size > 100);

  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putc (buf, 0);
  if (!err)
    err = gsti_buf_putmpi (buf, kexdh->e);

  if (!err)
    {
      len = gsti_buf_readable (buf);
      if (len > pkt->size - 1)
	return gsti_error (GPG_ERR_TOO_LARGE);
      pkt->type = SSH_MSG_KEXDH_INIT;
      pkt->payload_len = len;
      err = gsti_buf_getraw (buf, pkt->payload, len);
      assert (!err);
    }

  gsti_buf_free (buf);
  return err;
}


static void
dump_msg_kexdh_init (gsti_ctx_t ctx, MSG_kexdh_init * kexdh)
{
  _gsti_log_debug (ctx, "MSG_kexdh_init:\n");
  _gsti_dump_mpi ("e=", kexdh->e);
  _gsti_log_debug (ctx, "\n");
}


/* Parse a SSH_MSG_KEXDH_REPLY and return the parsed information in a
   newly allocated struture.  Returns 0 on success or an
   errorcode.  */
static gsti_error_t
parse_msg_kexdh_reply (MSG_kexdh_reply * dhr, gsti_buffer_t buf)
{
  gsti_error_t err = 0;
  int val;

  memset (dhr, 0, sizeof *dhr);

  if (gsti_buf_readable (buf) < (1 + 4 + 4 + 4)) 
    return gsti_error (GPG_ERR_TOO_SHORT);

  err = gsti_buf_getc (buf, &val);
  if (err)
    return err;

  if (val != SSH_MSG_KEXDH_REPLY)
    {
      err = gsti_error (GPG_ERR_BUG);
      goto leave;
    }

  err = gsti_buf_getbstr (buf, &dhr->k_s);
  if (err)
    goto leave;
  err = gsti_buf_getmpi (buf, &dhr->f);
  if (err)
    goto leave;

#if 0
  /* FIXME: This check is disabled, because it is bogus and needs to
     be rewritten to really compare against the mpi, and not the byte
     length.  */

  /* A value which is not in the range [1, p-1] is considered as a
     protocol violation.  */
  if ((n - 4) > sizeof diffie_hellman_group1_prime)
    return gsti_error (GPG_ERR_PROTOCOL_VIOLATION);
#endif

  err = gsti_buf_getbstr (buf, &dhr->sig_h);
  if (err)
    goto leave;

  /* make sure the msg length matches */
  if (gsti_buf_readable (buf))
    {
      _gsti_log_info (0, "parse_msg_kexdh_reply: %lu bytes remain\n",
		      gsti_buf_readable (buf));
      err = gsti_error (GPG_ERR_INV_PACKET);
    }

leave:
  return err;
}

/* Build a KEXDH_REPLY packet.  */
static gsti_error_t
build_msg_kexdh_reply (MSG_kexdh_reply * dhr, packet_buffer_t pkt)
{
  gsti_error_t err;
  gsti_buffer_t buf = NULL;
  size_t len;

  assert (pkt->size > 100);

  pkt->type = SSH_MSG_KEXDH_REPLY;

  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putc (buf, 0);
  if (!err)
    err = gsti_buf_putbstr (buf, dhr->k_s);
  if (!err)
    err = gsti_buf_putmpi (buf, dhr->f);
  if (!err)
    err = gsti_buf_putbstr (buf, dhr->sig_h);

  if (!err)
    {
      len = gsti_buf_readable (buf);
      if (len > pkt->size)
	err = gsti_error (GPG_ERR_TOO_LARGE);
      else
	{
	  pkt->payload_len = len;
	  err = gsti_buf_getraw (buf, pkt->payload, len);
	  assert (!err);
	}
    }

  gsti_buf_free (buf);
  return err;
}


static void
dump_msg_kexdh_reply (gsti_ctx_t ctx, MSG_kexdh_reply * dhr)
{
  _gsti_log_debug (ctx, "MSG_kexdh_reply:\n");
  _gsti_dump_bstring ("k_s=", dhr->k_s);
  _gsti_dump_mpi ("f=", dhr->f);
  _gsti_dump_bstring ("sig_h=", dhr->sig_h);
  _gsti_log_debug (ctx, "\n");
}


/* Choose a random value x and calculate e = g^x mod p.  Returns e and
   if ret_x is not NULL x.  */
static gcry_mpi_t
calc_dh_secret (gcry_mpi_t * ret_x)
{
  gcry_mpi_t e, g, x, prime;
  size_t n = sizeof diffie_hellman_group1_prime;

  if (gcry_mpi_scan (&prime, GCRYMPI_FMT_STD,
		     diffie_hellman_group1_prime, n, NULL))
    abort ();
    /*_gsti_dump_mpi( "prime=", prime );*/

  g = gcry_mpi_set_ui (NULL, 2);
  x = gcry_mpi_snew (200);
  gcry_mpi_randomize (x, 200, GCRY_STRONG_RANDOM);

  e = gcry_mpi_new (1024);
  gcry_mpi_powm (e, g, x, prime);
  if (ret_x)
    *ret_x = x;
  else
    gcry_mpi_release (x);
  gcry_mpi_release (g);
  gcry_mpi_release (prime);
  return e;
}


static void
hash_mpi (gcry_md_hd_t md, gcry_mpi_t a)
{
  byte buf[512];
  size_t n;

  if (gcry_mpi_print (GCRYMPI_FMT_SSH, buf, sizeof buf - 1, &n, a))
    _gsti_log_info (0, "Oops: MPI too large for hashing\n");
  else
    gcry_md_write (md, buf, n);
}


static gcry_mpi_t
calc_dh_key (gcry_mpi_t f, gcry_mpi_t x)
{
  gcry_mpi_t k, prime;
  size_t n = sizeof diffie_hellman_group1_prime;

  if (gcry_mpi_scan (&prime, GCRYMPI_FMT_STD,
		     diffie_hellman_group1_prime, n, NULL))
    abort ();

  k = gcry_mpi_snew (1024);
  gcry_mpi_powm (k, f, x, prime);
  gcry_mpi_release (prime);
  return k;
}


/* Calculate the exchange hash value and put it into the handle.  */
static gsti_error_t
calc_exchange_hash (gsti_ctx_t ctx, gsti_bstr_t i_c, gsti_bstr_t i_s,
		    gsti_bstr_t k_s, gcry_mpi_t e, gcry_mpi_t f)
{
  gsti_error_t err;
  gcry_md_hd_t md;
  gsti_bstr_t pp;
  const char *ver = host_version_string;
  int algo = GCRY_MD_SHA1, dlen;

  err = gcry_md_open (&md, algo, 0);
  if (err)
    return err;

  if (ctx->we_are_server)
    {
      _gsti_bstring_hash (md, ctx->peer_version_string);
      err = gsti_bstr_make (&pp, ver, strlen (ver));
      if (err)
        return err;
      _gsti_bstring_hash (md, pp);
      _gsti_free (pp);
    }
  else
    {
      err = gsti_bstr_make (&pp, ver, strlen (ver));
      if (err)
        return err;
      _gsti_bstring_hash (md, pp);
      _gsti_free (pp);
      _gsti_bstring_hash (md, ctx->peer_version_string);
    }
  _gsti_bstring_hash (md, i_c);
  _gsti_bstring_hash (md, i_s);
  _gsti_bstring_hash (md, k_s);
  hash_mpi (md, e);
  hash_mpi (md, f);
  hash_mpi (md, ctx->kex.k);

  dlen = gcry_md_get_algo_dlen (algo);
  err = gsti_bstr_make (&ctx->kex.h, gcry_md_read (md, algo), dlen);
  if (err)
    {
      gcry_md_close (md);
      return err;
    }
  if (!ctx->session_id)		/* initialize the session id the first time */
    err = gsti_bstr_make (&ctx->session_id, gcry_md_read (md, algo), dlen);
  gcry_md_close (md);
  _gsti_dump_hexbuf ("SesID=", gsti_bstr_data (ctx->session_id),
		     gsti_bstr_length (ctx->session_id));
  return err;
}


/* Hmm. We need to have a new_kex structure so that the old
   kex data can be used until we have send the NEWKEYs msg
   Well, doesn't matter for now. */
static gsti_bstr_t
construct_one_key (gsti_ctx_t ctx, gcry_md_hd_t md1, int algo,
		   const byte * letter, size_t size)
{
  gsti_error_t err;
  gsti_bstr_t hash;
  gcry_md_hd_t md;
  size_t n, n1;

  if (gcry_md_copy (&md, md1))
    abort ();
  err = gsti_bstr_make (&hash, NULL, size);
  if (err)
    {
      gcry_md_close (md);
      return NULL;
    }
  gcry_md_write (md, letter, 1);
  gcry_md_write (md, gsti_bstr_data (ctx->session_id),
		 gsti_bstr_length (ctx->session_id));
  n = gcry_md_get_algo_dlen (algo);
  if (n > size)
    n = size;
  memcpy (gsti_bstr_data (hash), gcry_md_read (md, algo), n);
  while (n < size)
    {
      gcry_md_close (md);
      if (gcry_md_copy (&md, md1))
	abort ();	/* Fixme: add an error return to this fucntion. */
      gcry_md_write (md, gsti_bstr_data (hash), n);
      n1 = gcry_md_get_algo_dlen (algo);
      if (n1 > size - n)
	n1 = size - n;
      memcpy (gsti_bstr_data (hash) + n, gcry_md_read (md, algo), n1);
      n += n1;
    }
  gcry_md_close (md);

  return hash;
}


static gsti_error_t
construct_keys (gsti_ctx_t ctx)
{
  gsti_error_t err;
  gcry_md_hd_t md;
  int algo = GCRY_MD_SHA1;
  int keylen, blksize, maclen;

  if (ctx->kex.iv_a)
    return 0;			/* already constructed */

  err = gcry_md_open (&md, algo, 0);
  if (err)
    return err;

  hash_mpi (md, ctx->kex.k);
  gcry_md_write (md, gsti_bstr_data (ctx->kex.h),
		 gsti_bstr_length (ctx->kex.h));

  blksize = ctx->ciph_blksize;
  maclen = ctx->mac_len;
  keylen = gcry_cipher_get_algo_keylen (ctx->ciph_algo);

  ctx->kex.iv_a = construct_one_key (ctx, md, algo, "\x41", blksize);
  ctx->kex.iv_b = construct_one_key (ctx, md, algo, "\x42", blksize);
  ctx->kex.key_c = construct_one_key (ctx, md, algo, "\x43", keylen);
  ctx->kex.key_d = construct_one_key (ctx, md, algo, "\x44", keylen);
  ctx->kex.mac_e = construct_one_key (ctx, md, algo, "\x45", maclen);
  ctx->kex.mac_f = construct_one_key (ctx, md, algo, "\x46", maclen);
  gcry_md_close (md);

  _gsti_dump_hexbuf ("key A=", gsti_bstr_data (ctx->kex.iv_a),
		     gsti_bstr_length (ctx->kex.iv_a));
  _gsti_dump_hexbuf ("key B=", gsti_bstr_data (ctx->kex.iv_b),
		     gsti_bstr_length (ctx->kex.iv_b));
  _gsti_dump_hexbuf ("key C=", gsti_bstr_data (ctx->kex.key_c),
		     gsti_bstr_length (ctx->kex.key_c));
  _gsti_dump_hexbuf ("key D=", gsti_bstr_data (ctx->kex.key_d),
		     gsti_bstr_length (ctx->kex.key_d));
  _gsti_dump_hexbuf ("key E=", gsti_bstr_data (ctx->kex.mac_e),
		     gsti_bstr_length (ctx->kex.mac_e));
  _gsti_dump_hexbuf ("key F=", gsti_bstr_data (ctx->kex.mac_f),
		     gsti_bstr_length (ctx->kex.mac_f));

  return 0;
}


static void
build_cipher_list (gsti_ctx_t ctx, STRLIST * c2s, STRLIST * s2c)
{
  const char *s;
  int i;

  /* do it in reserved order so it's correct in the list */
  i = DIM (cipher_list) - 1;
  while (i--)
    {
      s = cipher_list[i].name;
      *s2c = _gsti_strlist_insert (*s2c, s);
      *c2s = _gsti_strlist_insert (*c2s, s);
    }
}


static void
build_hmac_list (gsti_ctx_t ctx, STRLIST * c2s, STRLIST * s2c)
{
  const char *s;
  int i;

  /* do it in reserved order so it's correct in the list */
  i = DIM (hmac_list) - 1;
  while (i--)
    {
      s = hmac_list[i].name;
      *s2c = _gsti_strlist_insert (*s2c, s);
      *c2s = _gsti_strlist_insert (*c2s, s);
    }
}


static void
build_compress_list (gsti_ctx_t ctx, STRLIST * c2s, STRLIST * s2c)
{
  *c2s = _gsti_strlist_insert (NULL, SSH_COMPRESSION_NONE);
  *s2c = _gsti_strlist_insert (NULL, SSH_COMPRESSION_NONE);
#ifdef USE_NEWZLIB
  if (ctx->zlib.use)
    {
      *c2s = _gsti_strlist_insert (*c2s, SSH_COMPRESSION_ZLIB);
      *s2c = _gsti_strlist_insert (*s2c, SSH_COMPRESSION_ZLIB);
    }
#endif
}


static void
build_kex_list (gsti_ctx_t ctx, STRLIST * lst)
{
  *lst = _gsti_strlist_insert (NULL, SSH_GEX_DHG_SHA1);
  *lst = _gsti_strlist_insert (*lst, SSH_KEX_DHG1_SHA1);
  ctx->kex.type = SSH_KEX_GROUP_EXCHANGE;
}


static void
build_pkalgo_list (STRLIST * lst)
{
  *lst = _gsti_strlist_insert (NULL, SSH_PKA_SSH_RSA);
  *lst = _gsti_strlist_insert (*lst, SSH_PKA_SSH_DSS);
}


gsti_error_t
kex_send_init_packet (gsti_ctx_t ctx)
{
  gsti_error_t err = 0;
  MSG_kexinit kex;
  const byte *p;

  /* First send our kexinit packet.  */
  memset (&kex, 0, sizeof kex);

  /* We need the cookie later, so store it.  */
  gcry_randomize (kex.cookie, 16, GCRY_STRONG_RANDOM);
  memcpy (ctx->cookie, kex.cookie, 16);

  build_kex_list (ctx, &kex.kex_algo);
  build_pkalgo_list (&kex.server_host_key_algos);
  build_cipher_list (ctx, &kex.encr_algos_c2s, &kex.encr_algos_s2c);
  build_hmac_list (ctx, &kex.mac_algos_c2s, &kex.mac_algos_s2c);
  build_compress_list (ctx, &kex.compr_algos_c2s, &kex.compr_algos_s2c);
  err = build_msg_kexinit (&kex, &ctx->pkt);
  if (!err)
    err = _gsti_packet_write (ctx);
  if (err)
    {
      free_msg_kexinit (&kex);
      return err;
    }
  /* Must do it here because write_packet fills in the packet type.  */
  p = ctx->pkt.payload;
  err = gsti_bstr_make (&ctx->host_kexinit_data, p, ctx->pkt.payload_len);
  if (!err)
    err = _gsti_packet_flush (ctx);
  return err;
}


/* Choose a MAC algorithm that is supported by both sides.  */
static gsti_error_t
choose_mac_algo (gsti_ctx_t ctx, STRLIST cli, STRLIST srv)
{
  gsti_error_t err = 0;
  STRLIST l;
  const char *s;
  int i;

  for (l = cli; l && !err; l = l->next)
    {
      err = _gsti_algolist_find (srv, l->d);
      if (!err)
	continue;
      for (i = 0; (s = hmac_list[i].name); i++)
	{
	  if (!strcmp (s, l->d))
	    {
	      _gsti_log_debug (ctx, "chosen mac: %s (maclen %d)\n",
			       hmac_list[i].name, hmac_list[i].len);
	      ctx->mac_algo = hmac_list[i].algid;
	      ctx->mac_len = hmac_list[i].len;
	      return 0;
	    }
	}
    }
  return gsti_error (GPG_ERR_INV_OBJ);
}


/* Choose a cipher algorithm which is available on both sides.  */
static int
choose_cipher_algo (gsti_ctx_t ctx, STRLIST cli, STRLIST srv)
{
  gsti_error_t err = 0;
  STRLIST l;
  const char *s;
  int i;

  for (l = cli; l && !err; l = l->next)
    {
      err = _gsti_algolist_find (srv, l->d);
      if (!err)
	continue;
      for (i = 0; (s = cipher_list[i].name); i++)
	{
	  if (!strcmp (s, l->d))
	    {
	      _gsti_log_debug (ctx,
			       "chosen cipher: %s (blklen %d, keylen %d)\n",
			       cipher_list[i].name,
			       cipher_list[i].blksize, cipher_list[i].len);
	      ctx->ciph_blksize = cipher_list[i].blksize;
	      ctx->ciph_algo = cipher_list[i].algid;
	      ctx->ciph_mode = cipher_list[i].mode;
	      return 0;
	    }
	}
    }
  return gsti_error (GPG_ERR_INV_OBJ);
}


static gsti_error_t
choose_kex_algo (gsti_ctx_t ctx, STRLIST peer)
{
  char *p;
  int res;

  /* FIXME: Check for extensions the server does not understand.  */
  if (ctx->we_are_server)
    {
      p = strstr (peer->d, "exchange");
      res = p ? SSH_KEX_GROUP_EXCHANGE : SSH_KEX_GROUP1;
      if (ctx->kex.type != res)
	ctx->kex.type = res;
      _gsti_log_debug (ctx, "chosen kex-algo: %s\n", peer->d);
    }
  return 0;
}


/* Process a received key init packet.  */
gsti_error_t
kex_proc_init_packet (gsti_ctx_t ctx)
{
  gsti_error_t err;
  MSG_kexinit kex;

  if (ctx->pkt.type != SSH_MSG_KEXINIT)
    return gsti_error (GPG_ERR_BUG);
  err = parse_msg_kexinit (&kex, ctx->we_are_server, ctx->cookie, ctx->pktbuf);
  if (err)
    return err;
  err = choose_mac_algo (ctx, kex.mac_algos_c2s, kex.mac_algos_s2c);
  if (err)
    return err;
  err = choose_cipher_algo (ctx, kex.encr_algos_c2s, kex.encr_algos_s2c);
  if (err)
    return err;
  err = choose_kex_algo (ctx, kex.kex_algo);
  if (err)
    return err;

  if (!ctx->we_are_server)
    {
      /* We replace the cookie inside with the right cookie to
         calculate a valid message digest.  */
      memcpy (ctx->pkt.packet_buffer + 6, ctx->cookie, 16);
      ctx->pkt.payload = ctx->pkt.packet_buffer + 5;
    }
  else
    {
      /* The server still has its own cookie in the host data, we need
         to replace this with the received (client) cookie.  */
      memcpy (gsti_bstr_data (ctx->host_kexinit_data) + 1, kex.cookie, 16);
    }
  /* Make a copy of the received payload which we will need later.  */
  err = gsti_bstr_make (&ctx->peer_kexinit_data, ctx->pkt.payload,
		  ctx->pkt.payload_len);

  dump_msg_kexinit (ctx, &kex);
  return err;
}


/* Send a KEX init packet (we are in the client role).  */
gsti_error_t
kex_send_kexdh_init (gsti_ctx_t ctx)
{
  gsti_error_t err = 0;
  MSG_kexdh_init kexdh;

  memset (&kexdh, 0, sizeof kexdh);
  kexdh.e = ctx->kexdh_e = calc_dh_secret (&ctx->secret_x);
  err = build_msg_kexdh_init (&kexdh, &ctx->pkt);
  if (err)
    return err;
  err = _gsti_packet_write (ctx);
  if (err)
    return err;
  err = _gsti_packet_flush (ctx);
  return err;
}


/* Process the received DH init (we are in the server role).  */
gsti_error_t
kex_proc_kexdh_init (gsti_ctx_t ctx)
{
  gsti_error_t err;
  MSG_kexdh_init kexdh;

  if (ctx->pkt.type != SSH_MSG_KEXDH_INIT)
    return gsti_error (GPG_ERR_BUG);

  err = parse_msg_kexdh_init (&kexdh, ctx->pktbuf);
  if (err)
    return err;

  /* We need the received e later.  */
  ctx->kexdh_e = kexdh.e;

  dump_msg_kexdh_init (ctx, &kexdh);
  return 0;
}


/* Send a DH init packet (we are in the server role).  */
gsti_error_t
kex_send_kexdh_reply (gsti_ctx_t ctx)
{
  gsti_error_t err;
  MSG_kexdh_reply dhr;
  gcry_mpi_t y;

  memset (&dhr, 0, sizeof dhr);
  err = _gsti_key_getblob (ctx->hostkey, &dhr.k_s);
  if (err)
      return err;

  /* Generate our secret and the public value for it.  */
  dhr.f = calc_dh_secret (&y);
  /* Now we can calculate the shared secret.  */
  ctx->kex.k = calc_dh_key (ctx->kexdh_e, y);
  gcry_mpi_release (y);
  /* And the hash.  */
  err = calc_exchange_hash (ctx, ctx->host_kexinit_data,
			    ctx->peer_kexinit_data,
			    dhr.k_s, ctx->kexdh_e, dhr.f);
  gcry_mpi_release (ctx->kexdh_e);
  if (err)
    return err;
  err = _gsti_sig_encode (ctx->hostkey, gsti_bstr_data (ctx->kex.h),
                          &dhr.sig_h);
  if (!err)
      err = build_msg_kexdh_reply (&dhr, &ctx->pkt);
  if (!err)
    dump_msg_kexdh_reply (ctx, &dhr);
  if (!err)
    err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);
  return err;
}

/* Process the received DH value and take the encryption kes into use.
   (we are in the client role).  */
gsti_error_t
kex_proc_kexdh_reply (gsti_ctx_t ctx)
{
  gsti_error_t err;
  MSG_kexdh_reply dhr;

  if (ctx->pkt.type != SSH_MSG_KEXDH_REPLY)
    return gsti_error (GPG_ERR_BUG);

  err = parse_msg_kexdh_reply (&dhr, ctx->pktbuf);
  if (err)
    return err;

  dump_msg_kexdh_reply (ctx, &dhr);

  ctx->kex.k = calc_dh_key (dhr.f, ctx->secret_x);
  gcry_mpi_release (ctx->secret_x);

  err = calc_exchange_hash (ctx, ctx->host_kexinit_data,
			    ctx->peer_kexinit_data,
			    dhr.k_s, ctx->kexdh_e, dhr.f);
  gcry_mpi_release (ctx->kexdh_e);
  if (err)
    return err;

  err = _gsti_sig_decode (dhr.k_s, dhr.sig_h, gsti_bstr_data (ctx->kex.h),
			  &ctx->hostkey);

  return err;
}


gsti_error_t
kex_send_newkeys (gsti_ctx_t ctx)
{
  gsti_error_t err;

  err = construct_keys (ctx);
  if (err)
    return err;

  ctx->pkt.type = SSH_MSG_NEWKEYS;
  ctx->pkt.payload_len = 1;
  err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);
  if (err)
    return err;

  /* Now we have to take the encryption keys into use.  */
  err = gcry_cipher_open (&ctx->encrypt_hd, ctx->ciph_algo, ctx->ciph_mode, 0);
  if (!ctx->ciph_blksize)
    ctx->ciph_blksize = gcry_cipher_get_algo_blklen (ctx->ciph_algo);
  if (err)
    ;
  else if (ctx->we_are_server)
    {
      if (!err)
	err = gcry_cipher_setkey (ctx->encrypt_hd,
				  gsti_bstr_data (ctx->kex.key_d),
				  gsti_bstr_length (ctx->kex.key_d));
      if (!err)
	err = gcry_cipher_setiv (ctx->encrypt_hd,
				 gsti_bstr_data (ctx->kex.iv_b),
				 gsti_bstr_length (ctx->kex.iv_b));
      if (!err)
	{
	  err = gcry_md_open (&ctx->send_mac, ctx->mac_algo,
			      GCRY_MD_FLAG_HMAC);
	  if (!err)
	    err = gcry_md_setkey (ctx->send_mac,
				  gsti_bstr_data (ctx->kex.mac_f),
				  gsti_bstr_length (ctx->kex.mac_f));
	}
    }
  else
    {
      if (!err)
	err = gcry_cipher_setkey (ctx->encrypt_hd,
				  gsti_bstr_data (ctx->kex.key_c),
				  gsti_bstr_length (ctx->kex.key_c));
      if (!err)
	err = gcry_cipher_setiv (ctx->encrypt_hd,
				 gsti_bstr_data (ctx->kex.iv_a),
				 gsti_bstr_length (ctx->kex.iv_a));
      if (!err)
	{
	  err = gcry_md_open (&ctx->send_mac, ctx->mac_algo,
			      GCRY_MD_FLAG_HMAC);
	  if (!err)
	    err = gcry_md_setkey (ctx->send_mac,
				  gsti_bstr_data (ctx->kex.mac_e),
				  gsti_bstr_length (ctx->kex.mac_e));
	}
    }
  if (err)
    return _gsti_log_err (ctx, err, "setup encryption keys failed\n");
  return err;
}


/* Process a received newkeys message and take the decryption keys in
   use.  */
gsti_error_t
kex_proc_newkeys (gsti_ctx_t ctx)
{
  gsti_error_t err;

  if (ctx->pkt.type != SSH_MSG_NEWKEYS)
    return gsti_error (GPG_ERR_BUG);

  err = construct_keys (ctx);
  if (err)
    return err;

  err = gcry_cipher_open (&ctx->decrypt_hd, ctx->ciph_algo, ctx->ciph_mode, 0);
  if (!ctx->ciph_blksize)
    ctx->ciph_blksize = gcry_cipher_get_algo_blklen (ctx->ciph_algo);
  if (err)
    ;
  else if (ctx->we_are_server)
    {
      if (!err)
	err = gcry_cipher_setkey (ctx->decrypt_hd,
				  gsti_bstr_data (ctx->kex.key_c),
				  gsti_bstr_length (ctx->kex.key_c));
      if (!err)
	err = gcry_cipher_setiv (ctx->decrypt_hd,
				 gsti_bstr_data (ctx->kex.iv_a),
				 gsti_bstr_length (ctx->kex.iv_a));
      if (!err)
	{
	  err = gcry_md_open (&ctx->recv_mac, ctx->mac_algo,
			      GCRY_MD_FLAG_HMAC);
	  if (!err)
	    err = gcry_md_setkey (ctx->recv_mac,
				  gsti_bstr_data (ctx->kex.mac_e),
				  gsti_bstr_length (ctx->kex.mac_e));
	}
    }
  else
    {
      if (!err)
	err = gcry_cipher_setkey (ctx->decrypt_hd,
				  gsti_bstr_data (ctx->kex.key_d),
				  gsti_bstr_length (ctx->kex.key_d));
      if (!err)
	err = gcry_cipher_setiv (ctx->decrypt_hd,
				 gsti_bstr_data (ctx->kex.iv_b),
				 gsti_bstr_length (ctx->kex.iv_b));
      if (!err)
	{
	  err = gcry_md_open (&ctx->recv_mac, ctx->mac_algo,
			      GCRY_MD_FLAG_HMAC);
	  if (!err)
	    err = gcry_md_setkey (ctx->recv_mac,
				  gsti_bstr_data (ctx->kex.mac_f),
				  gsti_bstr_length (ctx->kex.mac_f));
	}
    }

  if (err)
    return _gsti_log_err (ctx, err, "setup decryption keys failed\n");
  return err;
}


gsti_error_t
kex_send_disconnect (gsti_ctx_t ctx, u32 reason)
{
  gsti_error_t err = 0;
  packet_buffer_t pkt = &ctx->pkt;
  gsti_buffer_t buf = NULL;
  size_t len;

  pkt->type = SSH_MSG_DISCONNECT;

  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putc (buf, 0);
  if (!err)
    err = gsti_buf_putuint32 (buf, reason);
  if (!err)
    err = gsti_buf_putstr (buf, NULL, 4);
  if (!err)
    err = gsti_buf_putstr (buf, NULL, 4);

  if (!err)
    {
      len = gsti_buf_readable (buf);
      if (len > pkt->size)
	err = gsti_error (GPG_ERR_TOO_LARGE);
      else
	{
	  pkt->payload_len = len;
	  err = gsti_buf_getraw (buf, pkt->payload, len);
	  assert (!err);
	}
    }

  gsti_buf_free (buf);
  return err;
}


/* Parse a SSH_MSG_SERVICE_{ACCEPT,REQUEST} and return the service
   name.  Returns 0 on success or an errorcode.  */
static gsti_error_t
parse_msg_service (gsti_bstr_t * svcname, const gsti_buffer_t buf, int type)
{
  gsti_error_t err;
  size_t n;
  int val;

  *svcname = NULL;
  if (gsti_buf_readable (buf) < (1 + 4))
    return gsti_error (GPG_ERR_TOO_SHORT);

  err = gsti_buf_getc (buf, &val);
  if (err)
    goto leave;

  if (val != type)
    {
      err = gsti_error (GPG_ERR_BUG);
      goto leave;
    }

  err = gsti_buf_getbstr (buf, svcname);
  if (err)
    goto leave;

  /* Make sure the message length matches.  */
  n = gsti_buf_readable (buf);
  if (n)
    {
      _gsti_log_info (0, "parse_msg_service: %lu bytes remaining\n", (u32) n);
      err = gsti_error (GPG_ERR_INV_PACKET);
    }

leave:
  return err;
}


/* Build a SERVICE_{Accept,REQUEST} packet.  */
static gsti_error_t
build_msg_service (gsti_bstr_t svcname, packet_buffer_t pkt, int type)
{
  gsti_error_t err = 0;
  gsti_buffer_t buf = NULL;
  size_t len;

  assert (pkt->size > 100);
  if (!svcname)
    {
      _gsti_log_info (0, "build_msg_service: no service name\n");
      return gsti_error (GPG_ERR_BUG);
    }

  pkt->type = type;

  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putc (buf, 0);
  if (!err)
    err = gsti_buf_putbstr (buf, svcname);

  if (!err)
    {
      len = gsti_buf_readable (buf);
      if (len > pkt->size)
	{
	  err = gsti_error (GPG_ERR_TOO_LARGE);
	  gsti_buf_free (buf);
	  return err;
	}
      else
	{
	  pkt->payload_len = len;
	  err = gsti_buf_getraw (buf, pkt->payload, len);
	  assert (!err);
	}
    }

  gsti_buf_free (buf);
  return err;
}



gsti_error_t
kex_send_service_request (gsti_ctx_t ctx, const char *name)
{
  gsti_error_t err;

  err = gsti_bstr_make (&ctx->service_name, name, strlen (name));
  if (!err)
    err = build_msg_service (ctx->service_name,
                             &ctx->pkt, SSH_MSG_SERVICE_REQUEST);
  if (!err)
    err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);
  if (err)
    {
      _gsti_free (ctx->service_name);
      ctx->service_name = NULL;
    }
  return err;
}


gsti_error_t
kex_proc_service_request (gsti_ctx_t ctx)
{
  gsti_error_t err;
  gsti_bstr_t svcname;

  if (ctx->pkt.type != SSH_MSG_SERVICE_REQUEST)
    return gsti_error (GPG_ERR_BUG);

  err = parse_msg_service (&svcname, ctx->pktbuf, SSH_MSG_SERVICE_REQUEST);
  if (err)
    return err;

  if (gsti_bstr_length (svcname) < 12 || memcmp (gsti_bstr_data (svcname),
						 "ssh-userauth", 12))
    return kex_send_disconnect (ctx, SSH_DISCONNECT_SERVICE_NOT_AVAILABLE);

  /* Store the servicename, so that it can later be answered.  */
  if (ctx->service_name)
    return _gsti_log_err (ctx, gsti_error (GPG_ERR_BUG),
			  "a service is already in use\n");

  ctx->service_name = svcname;
  return err;
}


gsti_error_t
kex_send_service_accept (gsti_ctx_t ctx)
{
  gsti_error_t err;

  err = build_msg_service (ctx->service_name, &ctx->pkt,
			   SSH_MSG_SERVICE_ACCEPT);
  if (!err)
    err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);
  return err;
}


gsti_error_t
kex_proc_service_accept (gsti_ctx_t ctx)
{
  gsti_error_t err;
  gsti_bstr_t svcname;
  int res;

  if (ctx->pkt.type != SSH_MSG_SERVICE_ACCEPT)
    return gsti_error (GPG_ERR_BUG);

  err = parse_msg_service (&svcname, ctx->pktbuf, SSH_MSG_SERVICE_ACCEPT);
  if (err)
    return err;

  if (!ctx->service_name)
    return _gsti_log_err (ctx, gsti_error (GPG_ERR_BUG),
			  "no service request sent\n");
  res = cmp_bstring (ctx->service_name, svcname);
  _gsti_free (svcname);
  if (res)
    return _gsti_log_err (ctx, gsti_error (GPG_ERR_PROTOCOL_VIOLATION),
			 "service name does not match requested one\n");
  return 0;
}


static gsti_error_t
build_gex_request (MSG_gexdh_request * gex, packet_buffer_t pkt)
{
  byte *p = pkt->payload;
  size_t length = pkt->size;

  p++;
  PUT32_BIT (p, gex->min);
  length -= 4;
  if (length < 8)
    return gsti_error (GPG_ERR_TOO_SHORT);
  PUT32_BIT (p, gex->n);
  length -= 4;
  if (length < 4)
    return gsti_error (GPG_ERR_TOO_SHORT);
  PUT32_BIT (p, gex->max);
  pkt->type = SSH_MSG_KEX_DH_GEX_REQUEST;
  pkt->payload_len = p - pkt->payload;
  return 0;
}


gsti_error_t
kex_send_gex_request (gsti_ctx_t ctx)
{
  gsti_error_t err;
  MSG_gexdh_request gex;

  memset (&gex, 0, sizeof gex);
  gex.n = ctx->gex.n;
  gex.min = ctx->gex.min;
  gex.max = ctx->gex.max;
  err = build_gex_request (&gex, &ctx->pkt);
  if (!err)
    err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);
  return err;
}


static gsti_error_t
parse_gex_request (MSG_gexdh_request * gex, const gsti_buffer_t buf)
{
  gsti_error_t err;
  int val;

  if (gsti_buf_readable (buf) < (4 + 4 + 4))
    return gsti_error (GPG_ERR_TOO_SHORT);

  memset (gex, 0, sizeof *gex);
  err = gsti_buf_getc (buf, &val);
  if (err)
    return err;

  if (val != SSH_MSG_KEX_DH_GEX_REQUEST)
    return gsti_error (GPG_ERR_BUG);

  err = gsti_buf_getuint32 (buf, &gex->min);
  if (!err)
    err = gsti_buf_getuint32 (buf, &gex->n);
  if (!err)
    err = gsti_buf_getuint32 (buf, &gex->max);
  if (err)
    return err;

  if (gsti_buf_readable (buf))
    return gsti_error (GPG_ERR_INV_PACKET);

  return 0;
}


static unsigned int
choose_dh_size (unsigned int n)
{
  unsigned int nbits = 0;

  if (n >= 1024 && n < 1536)
    nbits = 1023;
  else if (n >= 1536 && n < 2048)
    nbits = 1534;
  else if (n >= 2048 && n < 3190)
    nbits = 2046;
  else if (n >= 3190 && n < 4096)
    nbits = 3190;
  else
    nbits = 4094;
  return nbits;
}


static const byte *
select_dh_modulus (size_t n, size_t * r_size)
{
  const byte *p;

  *r_size = (n + 7) / 8;
  switch (n)
    {
    case 1023:
      p = mpi_array_1023;
    case 1534:
      p = mpi_array_1534;
    case 2046:
      p = mpi_array_2046;
    case 3190:
      p = mpi_array_3190;
    case 4094:
      p = mpi_array_4094;
    default:
      p = mpi_array_1534;
    }
  return p;
}


gsti_error_t
kex_proc_gex_request (gsti_ctx_t ctx)
{
  gsti_error_t err;
  MSG_gexdh_request gex;

  if (ctx->pkt.type != SSH_MSG_KEX_DH_GEX_REQUEST)
    return gsti_error (GPG_ERR_BUG);

  err = parse_gex_request (&gex, ctx->pktbuf);
  if (err)
    return err;

  if (gex.n < gex.min || gex.n > gex.max)
    return gsti_error (GPG_ERR_INV_PACKET);
  if (gex.max > MAX_GROUPSIZE)
    gex.max = MAX_GROUPSIZE;
  if (gex.n > gex.max)
    gex.n = MAX_GROUPSIZE;
  else
    gex.n = choose_dh_size (gex.n);

  ctx->gex.n = gex.n;
  ctx->gex.min = gex.min;
  ctx->gex.max = gex.max;

  return 0;
}


static void
free_gex_group (MSG_gexdh_group * gex)
{
  if (gex)
    {
      gcry_mpi_release (gex->p);
      gcry_mpi_release (gex->g);
    }
}


static gsti_error_t
build_gex_group (MSG_gexdh_group * gex, packet_buffer_t pkt)
{
  gsti_error_t err;
  gsti_buffer_t buf;

  err = gsti_buf_alloc (&buf);
  if (err)
    return err;

  err = gsti_buf_putc (buf, 0);
  if (!err)
    err = gsti_buf_putmpi (buf, gex->p);
  if (!err)
    err = gsti_buf_putmpi (buf, gex->g);

  if (!err)
    {
      size_t len = gsti_buf_readable (buf);
      pkt->type = SSH_MSG_KEX_DH_GEX_GROUP;
      pkt->payload_len = len;
      err = gsti_buf_getraw (buf, pkt->payload, len);
      assert (!err);
    }

  gsti_buf_free (buf);
  return err;
}


gsti_error_t
kex_send_gex_group (gsti_ctx_t ctx)
{
  gsti_error_t err;
  MSG_gexdh_group gex;
  const byte *mod;
  size_t n;

  memset (&gex, 0, sizeof gex);

  gex.g = gcry_mpi_set_ui (NULL, 2);
  mod = select_dh_modulus (ctx->gex.n, &n);
  err = gcry_mpi_scan (&gex.p, GCRYMPI_FMT_USG, mod, n, NULL);
  if (!err)
    err = build_gex_group (&gex, &ctx->pkt);
  if (!err)
    err = _gsti_packet_write (ctx);
  if (!err)
    err = _gsti_packet_flush (ctx);
  free_gex_group (&gex);
  return err;
}


static gsti_error_t
parse_gex_group (MSG_gexdh_group * gex, const gsti_buffer_t buf)
{
  gsti_error_t err;
  int val;

  if (gsti_buf_readable (buf) < (4 + 4))
    return gsti_error (GPG_ERR_TOO_SHORT);

  memset (gex, 0, sizeof *gex);
  err = gsti_buf_getc (buf, &val);
  if (err)
    return err;

  if (val != SSH_MSG_KEX_DH_GEX_GROUP)
    return gsti_error (GPG_ERR_BUG);

  err = gsti_buf_getmpi (buf, &gex->p);
  if (!err)
    err = gsti_buf_getmpi (buf, &gex->g);
  if (!err && gsti_buf_readable (buf))
    err = gsti_error (GPG_ERR_INV_PACKET);

  return err;
}


gsti_error_t
kex_proc_gex_group (gsti_ctx_t ctx)
{
  gsti_error_t err;
  MSG_gexdh_group gex;

  if (ctx->pkt.type != SSH_MSG_KEX_DH_GEX_GROUP)
    return gsti_error (GPG_ERR_BUG);
  err = parse_gex_group (&gex, ctx->pktbuf);
  if (err)
    return err;

  return 0;
}
