/* stream.h
 *	Copyright (C) 1999 Werner Koch
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

#ifndef GSTI_STREAM_H
#define GSTI_STREAM_H

#include "types.h"
/*
 * It would be nice to use glic streams but we can't do so becuase
 * this library is supposed to be run on many different kinds of systems
 */

typedef struct read_stream_s *read_stream_t;
struct read_stream_s
{
  gsti_read_fnc_t readfnc;
  void * fnc_ctx;
  int read_eof;			/* last read returned eof */
  int error;			/* an error has been encountered */
  size_t size;			/* allocated size */
  /* todo: replace counts by pointers */
  size_t start;			/* number of invalid bytes at the begin of the buffer */
  size_t len;			/* currently filled to this len */
  unsigned char buf[1];
};


typedef struct write_stream_s *write_stream_t;
struct write_stream_s
{
  gsti_write_fnc_t writefnc;
  void * fnc_ctx;
  int error;			/* an error has been encountered */
  size_t size;			/* allocated size */
  /* todo: replace counts by pointers */
  size_t used;			/* currently filled to this len */
  unsigned char buf[1];
};



#define _gsti_stream_get(a)  \
     ( ( (a)->start >= (a)->len )?  _gsti_stream_getbyte( (a) ) \
				  : ( (a)->buf[(a)->start++] ) )
#define _gsti_stream_put(a,c)  \
     ( ( (a)->used >= (a)->size )?  _gsti_stream_putbyte( (a), (c) ) \
				  : ( (a)->buf[(a)->used++] = (c), 0 ) )

#define _gsti_stream_eof(a)   ( (a)->start >= a->len && (a)->read_eof )
#define _gsti_stream_error(a) ( (a)->error )

read_stream_t _gsti_read_stream_new (gsti_read_fnc_t readfnc, void * fnc_ctx);
void _gsti_read_stream_free (read_stream_t a);

int _gsti_stream_getbyte (read_stream_t a);
gsti_error_t _gsti_stream_readn (read_stream_t a, byte * buffer, size_t nbytes);

write_stream_t _gsti_write_stream_new (gsti_write_fnc_t writefnc, void * fnc_ctx);
void _gsti_write_stream_free (write_stream_t a);

int _gsti_stream_putbyte (write_stream_t a, int c);
gsti_error_t _gsti_stream_writen (write_stream_t a, const byte * buffer,
				  size_t nbytes);
gsti_error_t _gsti_stream_flush (write_stream_t a);


#endif /* GSTI_STREAM_H */
