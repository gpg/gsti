/* kex.h - kex exchange (KEX)
   Copyright (C) 1999 Werner Koch
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

#ifndef GSTI_KEX_H
#define GSTI_KEX_H

gsti_error_t kex_send_version (gsti_ctx_t ctx);
gsti_error_t kex_wait_on_version (gsti_ctx_t ctx);

gsti_error_t kex_send_init_packet (gsti_ctx_t ctx);
gsti_error_t kex_proc_init_packet (gsti_ctx_t ctx);

gsti_error_t kex_send_kexdh_init (gsti_ctx_t ctx);
gsti_error_t kex_proc_kexdh_init (gsti_ctx_t ctx);

gsti_error_t kex_send_kexdh_reply (gsti_ctx_t ctx);
gsti_error_t kex_proc_kexdh_reply (gsti_ctx_t ctx);

gsti_error_t kex_send_newkeys (gsti_ctx_t ctx);
gsti_error_t kex_proc_newkeys (gsti_ctx_t ctx);

gsti_error_t kex_send_service_request (gsti_ctx_t ctx, const char *name);
gsti_error_t kex_proc_service_request (gsti_ctx_t ctx);
gsti_error_t kex_send_service_accept (gsti_ctx_t ctx);
gsti_error_t kex_proc_service_accept (gsti_ctx_t ctx);

gsti_error_t kex_send_gex_request (gsti_ctx_t ctx);
gsti_error_t kex_proc_gex_request (gsti_ctx_t ctx);

gsti_error_t kex_send_gex_group (gsti_ctx_t ctx);
gsti_error_t kex_proc_gex_group (gsti_ctx_t ctx);


#endif /* GSTI_KEX_H */
