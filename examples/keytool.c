/* keytool.c - Key API example
 *      Copyright (C) 2002 Timo Schulz
 *
 * This file is part of GSTI.
 *
 * GSTI is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * GSTI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>		/* ????? fixme */
#include <gcrypt.h>

#include "gsti.h"
#include "types.h"
#include "pubkey.h"

#define DSS_PUBKEY "dsa.pub"
#define DSS_SECKEY "dsa.sec"

#define RSA_PUBKEY "rsa.pub"
#define RSA_SECKEY "rsa.sec"


/* fingerprint #77:82:ed:59:b0:a3:b3:5b:8b:c1:66:cd:01:9b:97:80# */
/* secret key #7e:17:76:1b:3a:fe:05:ff:a9:08:4e:2b:6c:fd:aa:a6:c0:a6:b5:90# */

static void
print_fpr (unsigned char *fpr, int n)
{
  unsigned char *fprhex;
  int i;

  fprhex = calloc (1, 128);
  for (i = 0; i < n; i++)
    {
      int c = (i != (n - 1)) ? ':' : ' ';
      sprintf (fprhex + 3 * i, "%02X%c", fpr[i], c);
    }
  fprintf (stderr, "%s\n", fprhex);
  free (fprhex);
}


static void
genkey (int algo)
{
  gcry_sexp_t s_key = NULL, s_param = NULL;
  gsti_error_t err;
  gsti_key_t key;
  const char * s;
  int nbits = 1024;

  algo = SSH_PK_RSA; /* XXX */
  switch (algo)
    {
    case SSH_PK_DSS: s = "(genkey(dsa(nbits %d)))"; break;
    case SSH_PK_RSA: s = "(genkey(rsa(nbits %d)))"; break;
    default:         printf ("invalid pk algo '%d'\n", algo); return;
    }
  err = gcry_sexp_build (&s_param, NULL, s, nbits);
  if (!err)
    err = gcry_pk_genkey (&s_key, s_param);
  if (err)
    printf ("genkey: %s\n", gsti_strerror (err));

  gcry_sexp_release (s_param);
  gcry_sexp_dump (s_key);

  gsti_key_from_sexp (s_key, &key);
  gcry_sexp_release (s_key);

  gsti_key_save (RSA_PUBKEY, 0, key);
  gsti_key_save (RSA_SECKEY, 1, key);
  gsti_key_free (key);
}


int
main (int argc, char **argv)
{
  gcry_mpi_t sig[2];
  GSTI_KEY key;
  unsigned char *fpr;
  int rc, md_arr[2], i;

  gsti_control (GSTI_SECMEM_INIT);
  if (argc != 1)
    {
      argc--, argv++;
      genkey (atoi (*argv));
      return 0;
    }
  
  rc = gsti_key_load (DSS_PUBKEY, 0, &key);
  if (rc)
    {
      printf ("load pubkey: %s: `%s'\n", DSS_PUBKEY, gsti_strerror (rc));
      exit (1);
    }
  md_arr[0] = GSTI_DIGEST_MD5;
  md_arr[1] = GSTI_DIGEST_SHA1;
  for (i = 0; i < 2; i++)
    {
      fpr = gsti_key_fingerprint (key, md_arr[i]);
      if (!fpr)
	printf ("could not get fingerprint.\n");
      else
        {
          print_fpr (fpr, i==0? 16 : 20);
          free (fpr);
        }
    }

  gsti_key_free (key);
  key = NULL;

  rc = gsti_key_load (RSA_PUBKEY, 0, &key);
  if (rc)
    {
      printf ("load rsa pubkey: %s: %s\n", RSA_PUBKEY, gsti_strerror (rc));
      exit (1);
    }
  md_arr[0] = GSTI_DIGEST_MD5;
  md_arr[1] = GSTI_DIGEST_SHA1;
  for (i=0; i < 2; i++)
    {
      fpr = gsti_key_fingerprint (key, md_arr[i]);
      if (!fpr)
        printf ("could not get fngerprint.\n");
      else
        {
          print_fpr (fpr, i == 0? 16 : 20);
          free (fpr);
        }
    }

  gsti_key_free (key);
  key= NULL;
  sig[0] = sig[1] = NULL;
  
  rc = gsti_key_load (DSS_SECKEY, 1, &key);
  if (rc)
    { 
      printf ("load seckey: %s: `%s'\n", DSS_SECKEY, gsti_strerror (rc));
      goto leave;
    }
  
  rc = _gsti_dss_sign (key, fpr, sig);
  if (rc)
    {
      printf ("signing test failed: %s\n", gsti_strerror (rc));
      goto leave;
    }
  rc = _gsti_dss_verify (key, fpr, sig);
  if (rc)
    {
      printf ("verify signature failed: %s\n", gsti_strerror (rc));
      goto leave;
    }
   printf ("key check: ok (rc=%d)\n", rc);

 leave:
  if (fpr)
    free (fpr);
  if (sig[0])
    gcry_mpi_release (sig[0]);
  if (sig[1])
    gcry_mpi_release (sig[1]);
  gsti_key_free (key);
  gsti_control (GSTI_SECMEM_RELEASE);

  return 0;
}
