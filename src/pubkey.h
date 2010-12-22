/* pubkey.h
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

#ifndef GSTI_PUBKEY_H
#define GSTI_PUBKEY_H

typedef enum
{
  SSH_PK_NONE = 0,
  SSH_PK_DSS = 1,
  SSH_PK_RSA = 2,
  SSH_PK_LAST = 3,
} gsti_key_type_t;


struct gsti_key_s
{
  gcry_mpi_t key[6];
  unsigned nkey;
  gsti_key_type_t type;
  unsigned int secret : 1;
  gsti_sign_fnc_t sign_fnc;
  void *sign_fnc_value;
};

gsti_error_t _gsti_key_getblob (gsti_key_t pk, gsti_bstr_t * r_blob);
gsti_error_t _gsti_key_fromblob (gsti_bstr_t blob, gsti_key_t * r_key);

gsti_error_t _gsti_sig_encode (gsti_key_t sk, const void *data, size_t datalen,
                               gsti_bstr_t *r_sig);
gsti_error_t _gsti_sig_decode (gsti_bstr_t key, gsti_bstr_t sig,
			       const byte * hash, gsti_key_t *r_pk);

gsti_error_t _gsti_ssh_get_pkname (gsti_key_type_t pktype, int asbstr,
				   byte **r_namebuf, size_t *r_n);
gsti_error_t _gsti_ssh_cmp_pkname (gsti_key_type_t pktype, const char *name,
				   size_t len);
gsti_error_t _gsti_ssh_cmp_keys (gsti_key_t a, gsti_key_t b);

#endif	/*GSTI_PUBKEY_H */
