/* auth.h - SSH authentication
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
   along with GSTI; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  */

#ifndef GSTI_AUTH_H
#define GSTI_AUTH_H 1

struct gsti_auth_s
{
  int method;
  gsti_key_t key;
  gsti_bstr_t blob;
  char *user;
};

/*-- auth.c --*/
gsti_error_t _gsti_auth_send_accept_packet (gsti_ctx_t ctx);
gsti_error_t _gsti_auth_proc_accept_packet (gsti_ctx_t ctx);

gsti_error_t _gsti_auth_send_pkok_packet (gsti_ctx_t ctx, gsti_auth_t auth);
gsti_error_t _gsti_auth_proc_pkok_packet (gsti_ctx_t ctx, gsti_auth_t auth);

gsti_error_t _gsti_auth_send_init_packet (gsti_ctx_t ctx, gsti_auth_t auth,
                                          int trypk);
gsti_error_t _gsti_auth_proc_init_packet (gsti_ctx_t ctx, gsti_auth_t auth,
                                          int trypk);

gsti_error_t _gsti_auth_send_failure_packet (gsti_ctx_t ctx);

#endif /*GSTI_AUTH_H*/
