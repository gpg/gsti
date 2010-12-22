/* banner.h - SSH userauth banner
   Copyright (C) 2010 g10 Code GmbH
 
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

#ifndef GSTI_BANNER_H
#define GSTI_BANNER_H 1

gsti_error_t _gsti_auth_send_banner_packet (gsti_ctx_t ctx);
gsti_error_t _gsti_auth_proc_banner_packet (gsti_ctx_t ctx);
gsti_error_t _gsti_banner_run_auth_cb (gsti_ctx_t ctx);

#endif /*GSTI_BANNER_H*/
