/* logging.c - GSTI logging interface.
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

#include <assert.h>
#include <stdio.h>
#include <stdarg.h>

#include <gcrypt.h>

#include "gsti.h"
#include "types.h"
#include "buffer.h"
#include "memory.h"
#include "api.h"


/* Log the message FMT with the arguments ARG_PTR for the context CTX,
   under the level LEVEL.  */
static void
_gsti_logv (GSTIHD ctx, gsti_log_level_t level,
	    const char *fmt, va_list arg_ptr)
{
  gio_stream_t log_stream;

  if (ctx && ctx->log_level < level)
    return;

  if (ctx && ctx->log_stream)
    log_stream = ctx->log_stream;
  else
    /* FIXME: Reimplement this in terms of GIO, when it is written.  */
    log_stream = stderr;

  /* FIXME: This is not atomic.  Also, it does not show the context in
     which the error occured.  */
  switch (level)
    {
    case GSTI_LOG_INFO:
      break;

    case GSTI_LOG_DEBUG:
      /* FIXME: Reimplement this in terms of GIO, when it is written.  */
      fputs ("DBG: ", log_stream);
      break;

    case GSTI_LOG_NONE:
    default:
      assert (!"unexpected log level");
    }
  /* FIXME: Reimplement this in terms of GIO, when it is written.  */
  vfprintf (log_stream, fmt, arg_ptr);
}


/* Log the error ERR, which occured in context CTX, and return it.  */
int
_gsti_log_err (GSTIHD ctx, int err, const char *fmt, ...)
{
  va_list arg;

  va_start (arg, fmt);
  _gsti_logv (ctx, GSTI_LOG_DEBUG, fmt, arg);
  va_end (arg);

  return err;
}


/* Log the information FMT for context CTX.  */
void
_gsti_log_info (GSTIHD ctx, const char *fmt, ...)
{
  va_list arg;

  va_start (arg, fmt);
  _gsti_logv (ctx, GSTI_LOG_INFO, fmt, arg);
  va_end (arg);
}


/* Log the debug message FMT for context CTX.  */
void
_gsti_log_debug (GSTIHD ctx, const char *fmt, ...)
{
  va_list arg;

  va_start (arg, fmt);
  _gsti_logv (ctx, GSTI_LOG_DEBUG, fmt, arg);
  va_end (arg);
}


/* Set the stream for logging output for context CTX to STREAM.  This
   acquires a new reference to the stream.  */
gsti_error_t
gsti_set_log_stream (GSTIHD ctx, gio_stream_t stream)
{
  gio_stream_t new_stream;

  if (ctx->log_stream)
    {
      /* FIXME: Implement this in terms of GIO, when it is written.  */
      fflush (ctx->log_stream);
      ctx->log_stream = NULL;
    }

  /* FIXME: Implement this in terms of GIO, when it is written.  */
  new_stream = fdopen (fileno (stream), "r");
  if (!new_stream)
    return gsti_error (GPG_ERR_INV_ARG);

  ctx->log_stream = new_stream;
  return 0;
}


/* Set the maximum level up to which messages are passed to the log
   handler for the context CTX.  */
void
gsti_set_log_level (GSTIHD ctx, gsti_log_level_t level)
{
  ctx->log_level = level;
}
