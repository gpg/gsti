/* pubkey.h
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

#ifndef GSTI_PUBKEY_H
#define GSTI_PUBKEY_H

enum
{
  SSH_PK_NONE = 0,
  SSH_PK_DSS = 1,
};

struct gsti_key_s
{
  gcry_mpi_t key[5];
  unsigned nkey;
  int type;
  unsigned int secret:1;
};

int _gsti_dss_sign (GSTI_KEY ctx, const byte * hash, gcry_mpi_t sig[2]);
int _gsti_dss_verify (GSTI_KEY ctx, const byte * hash, gcry_mpi_t sig[2]);

BSTRING _gsti_key_getblob (GSTI_KEY pk);
GSTI_KEY _gsti_key_fromblob (BSTRING blob);

BSTRING _gsti_sig_encode (GSTI_KEY sk, const byte * hash);
int _gsti_sig_decode (BSTRING key, BSTRING sig, const byte * hash,
		      GSTI_KEY * r_pk);

byte *_gsti_ssh_get_pkname (int pktype, int asbstr, size_t * r_n);
int _gsti_ssh_cmp_pkname (int pktype, const char *name, size_t len);
int _gsti_ssh_cmp_keys (GSTI_KEY a, GSTI_KEY b);


#endif /*GSTI_PUBKEY_H */
