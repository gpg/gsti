/* main.c - Main APIs
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
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/stat.h>
#include <gcrypt.h>

#include "types.h"
#include "buffer.h"
#include "memory.h"
#include "packet.h"
#include "api.h"
#include "moduli.h"


static const char *
parse_version_number (const char *s, int *number)
{
  int val = 0;

  if (*s == '0' && isdigit (s[1]))
    return NULL;		/* leading zeros are not allowed */
  for (; isdigit (*s); s++)
    {
      val *= 10;
      val += *s - '0';
    }
  *number = val;
  return val < 0 ? NULL : s;
}


static const char *
parse_version_string (const char *s, int *major, int *minor, int *micro)
{
  s = parse_version_number (s, major);
  if (!s || *s != '.')
    return NULL;
  s++;
  s = parse_version_number (s, minor);
  if (!s || *s != '.')
    return NULL;
  s++;
  s = parse_version_number (s, micro);
  if (!s)
    return NULL;
  return s;			/* patchlevel */
}


/****************
 * Check that the the version of the library is at minimum the requested one
 * and return the version string; return NULL if the condition is not
 * satisfied.  If a NULL is passed to thsi function, no check is done,
 * but the version string is simpley returned.
 */
const char *
gsti_check_version (const char *req_version)
{
  const char *ver = VERSION;
  int my_major, my_minor, my_micro;
  int rq_major, rq_minor, rq_micro;
  const char *my_plvl, *rq_plvl;

  if (!req_version)
    return ver;

  my_plvl = parse_version_string (ver, &my_major, &my_minor, &my_micro);
  if (!my_plvl)
    return NULL;		/* very strange our own version is bogus */
  rq_plvl = parse_version_string (req_version, &rq_major, &rq_minor,
				  &rq_micro);
  if (!rq_plvl)
    return NULL;		/* req version string is invalid */

  if (my_major > rq_major
      || (my_major == rq_major && my_minor > rq_minor)
      || (my_major == rq_major && my_minor == rq_minor
	  && my_micro > rq_micro)
      || (my_major == rq_major && my_minor == rq_minor
	  && my_micro == rq_micro && strcmp (my_plvl, rq_plvl) >= 0))
    {
      return ver;
    }
  return NULL;
}


void
gsti_control (enum gsti_ctl_cmds ctl)
{
  switch (ctl)
    {
    case GSTI_DISABLE_LOCKING:
      gcry_control (GCRYCTL_DISABLE_INTERNAL_LOCKING);
      break;

    case GSTI_SECMEM_INIT:
      gcry_control (GCRYCTL_INIT_SECMEM, 16384, 0);
      gcry_control (GCRYCTL_DISABLE_SECMEM_WARN);
      break;

    case GSTI_SECMEM_RELEASE:
      gcry_control (GCRYCTL_TERM_SECMEM);
      break;
    }
}


static void
init_gex_default (GSTIHD hd)
{
  hd->gex.min = MIN_GROUPSIZE;
  hd->gex.n = 2048;
  hd->gex.max = MAX_GROUPSIZE;
}


GSTIHD
gsti_init (void)
{
  GSTIHD hd;

  hd = _gsti_xcalloc (1, sizeof *hd);
  _gsti_packet_init (hd);
  init_gex_default (hd);
  return hd;
}


static void
_gsti_free_auth (GSTIHD hd)
{
  if (hd)
    {
      _gsti_free (hd->auth.user);
      gsti_key_free (hd->auth.key);
    }
}


void
gsti_deinit (GSTIHD hd)
{
  if (!hd)
    return;

  _gsti_free_auth (hd);
  _gsti_read_stream_free (hd->read_stream);
  _gsti_write_stream_free (hd->write_stream);
  _gsti_strlist_free (hd->local_services);
  _gsti_bstring_free (hd->peer_version_string);
  _gsti_bstring_free (hd->host_kexinit_data);
  _gsti_bstring_free (hd->peer_kexinit_data);
  _gsti_free (hd->service_name);
  _gsti_bstring_free (hd->session_id);
  _gsti_bstring_free (hd->kex.h);
  _gsti_bstring_free (hd->kex.iv_a);
  _gsti_bstring_free (hd->kex.iv_b);
  _gsti_bstring_free (hd->kex.key_c);
  _gsti_bstring_free (hd->kex.key_d);
  _gsti_bstring_free (hd->kex.mac_e);
  _gsti_bstring_free (hd->kex.mac_f);
  gcry_cipher_close (hd->encrypt_hd);
  gcry_cipher_close (hd->decrypt_hd);
  gsti_key_free (hd->hostkey);
  _gsti_packet_free (hd);
  _gsti_free (hd);
}


gsti_error_t
gsti_set_readfnc (GSTIHD hd, GSTI_READ_FNC readfnc)
{
  if (!hd)
    return gsti_error (GPG_ERR_INV_ARG);

  hd->readfnc = readfnc;

  return 0;
}


gsti_error_t
gsti_set_writefnc (GSTIHD hd, GSTI_WRITE_FNC writefnc)
{
  if (!hd)
    return gsti_error (GPG_ERR_INV_ARG);

  hd->writefnc = writefnc;

  return 0;
}


/* A client can request a special service using this function.  A
   servicename must have a @ in it, so that it does not conflict with
   any standard service.  Comma and colons should be avoided in a
   service name.  If this is not used, a standard SSH service is used.
   A server must use this function to set acceptable services.  A
   client uses the first service from the list.  */
gsti_error_t
gsti_set_service (GSTIHD hd, const char *svcname)
{
  STRLIST s;

  if (!hd)
    return gsti_error (GPG_ERR_INV_ARG);  
  if (!svcname || !*svcname)
    return 0;
  hd->local_services = _gsti_algolist_parse (svcname, strlen (svcname));
  for (s = hd->local_services; s; s = s->next)
    {
      if (!strchr (s->d, '@'))
	;
      _gsti_log_info (hd, "service `%s'\n", s->d);
    }
  return 0;
}


/* Read data from the GSTI stream.  This automagically initializes the
   the system and decides whether we are client or server.  We are the
   server side when this function is called before the first
   gsti_write and vice versa.  Everything to setup the secure
   transport is handled here.

   LENGTH must point to a variable having the size of the provided
   buffer and will receive the actuall number of bytes read, which may
   be less than the buffer. EOF is indicated by returning a zero
   length.  */
gsti_error_t
gsti_read (GSTIHD hd, void *buffer, size_t * length)
{
  gsti_error_t err;

  if (!hd)
    return gsti_error (GPG_ERR_INV_ARG);

  hd->user_read_buffer = buffer;
  hd->user_read_bufsize = *length;
  hd->user_read_nbytes = 0;

  err = fsm_user_read (hd);
  if (err)
    return err;

  *length = hd->user_read_nbytes;
  return 0;
}


/* The counterpart to gsti_read.  */
gsti_error_t
gsti_write (GSTIHD hd, const void *buffer, size_t length)
{
  if (!hd)
    return gsti_error (GPG_ERR_INV_ARG);

  if (hd->local_services)
    {
      const byte *p = buffer;
      /* Check that the buffer contains valid packet types.  */
      if (!length || *p < 192)
	return gsti_error (GPG_ERR_INV_ARG);
    }

  hd->user_write_buffer = buffer;
  hd->user_write_bufsize = length;

  return fsm_user_write (hd);
}


gsti_error_t
gsti_set_hostkey (GSTIHD hd, const char *file)
{
  struct stat statbuf;

  if (!hd)
    return gsti_error (GPG_ERR_INV_ARG);
  if (stat (file, &statbuf))
    return gsti_error_from_errno (errno);

  return gsti_key_load (file, 1, &hd->hostkey);
}


gsti_error_t
gsti_set_client_key (GSTIHD hd, const char *file)
{
  struct stat statbuf;

  if (!hd)
    return gsti_error (GPG_ERR_INV_ARG);
  if (stat (file, &statbuf))
    return gsti_error_from_errno (errno);

  return gsti_key_load (file, 1, &hd->auth.key);
}


gsti_error_t
gsti_set_client_user (GSTIHD hd, const char *user)
{
  if (!hd)
    return gsti_error (GPG_ERR_INV_ARG);

  _gsti_free (hd->auth.user);
  hd->auth.user = _gsti_xstrdup (user);

  return 0;
}


gsti_error_t
gsti_set_auth_method (GSTIHD hd, int methd)
{
  if (!hd)
    return gsti_error (GPG_ERR_INV_ARG);

  switch (methd)
    {
    case GSTI_AUTH_PUBLICKEY:
      hd->auth.method = methd;
      break;
    default:
      return gsti_error (GPG_ERR_PROT_VIOL);
    }

  return 0;
}


gsti_error_t
gsti_set_compression (GSTIHD hd, int val)
{
#ifndef USE_ZLIB
  hd->zlib.use = 0;
  return gsti_error (GPG_ERR_NOT_IMPLEMENTED);
#else
  if (!hd)
    return gsti_error (GPG_ERR_INV_ARG);
  hd->zlib.use = val;
  return 0;
#endif
}


gsti_error_t
gsti_set_dhgex (GSTIHD hd, unsigned int min, unsigned int n, unsigned int max)
{
  if (!hd)
    return gsti_error (GPG_ERR_INV_ARG);

  if (n < min || n > max)
    return gsti_error (GPG_ERR_INV_ARG);

  hd->gex.min = min;
  hd->gex.n = n;
  hd->gex.max = max;

  return 0;
}
