/* kex.h - kex exchange (KEX)
 *	Copyright (C) 1999 Werner Koch
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

#ifndef GSTI_KEX_H
#define GSTI_KEX_H

int kex_send_version (GSTIHD hd);
int kex_wait_on_version (GSTIHD hd);

int kex_send_init_packet (GSTIHD hd);
int kex_proc_init_packet (GSTIHD hd);

int kex_send_kexdh_init (GSTIHD hd);
int kex_proc_kexdh_init (GSTIHD hd);

int kex_send_kexdh_reply (GSTIHD hd);
int kex_proc_kexdh_reply (GSTIHD hd);

int kex_send_newkeys (GSTIHD hd);
int kex_proc_newkeys (GSTIHD hd);

int kex_send_service_request (GSTIHD hd, const char *name);
int kex_proc_service_request (GSTIHD hd);
int kex_send_service_accept (GSTIHD hd);
int kex_proc_service_accept (GSTIHD hd);

int kex_send_gex_request (GSTIHD hd);
int kex_proc_gex_request (GSTIHD hd);

int kex_send_gex_group (GSTIHD hd);
int kex_proc_gex_group (GSTIHD hd);


#endif /* GSTI_KEX_H */
