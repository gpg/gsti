/* buffer.h - Buffer handling.
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
   along with GSTI; if not, write to the Free Software Foundation,
   Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA  */

#ifndef GSTI_BUFFER_H
#define GSTI_BUFFER_H	1

#include <gcrypt.h>

#include "types.h"


/* Formatted buffers.  */

/* Buffers are losely formatted objects that support the SSH data
   types.  */
struct gsti_buffer
{
  /* The buffer data.  */
  gsti_byte_t *data;

  /* The allocated size of the buffer.  */
  size_t size;

  /* The amount of data in the buffer.  */
  size_t end;

  /* The current offset into the buffer.  This is used and
     automatically adjusted by the various get functions.  */
  size_t offset;
};

typedef struct gsti_buffer *gsti_buffer_t;


/* Allocate a new buffer and return it in R_BUF.  */
gpg_error_t gsti_buf_alloc (gsti_buffer_t *r_buf);

/* Destroy the buffer BUF and release all associated resources.  */
void gsti_buf_free (gsti_buffer_t buf);

/* Set the content of the buffer to AMOUNT bytes starting from DATA,
   and reset the buffer offset.  */
gpg_error_t gsti_buf_set (gsti_buffer_t buf, const char *data, size_t amount);


/* Functions for appending to the buffer.  These functions do not
   change the offset into the buffer.  They grow the buffer by
   allocating more space if necessary.  */

/* Append the character CHR to the buffer BUF.  */
gpg_error_t gsti_buf_putc (gsti_buffer_t buf, int chr);

/* Append the byte VAL to the buffer BUF.  */
gpg_error_t gsti_buf_putbyte (gsti_buffer_t buf, gsti_byte_t val);

/* Append the boolean VAL to the buffer BUF.  */
gpg_error_t gsti_buf_putbool (gsti_buffer_t buf, int val);

/* Append the 32-bit unsigned integer to the buffer BUF.  */
gpg_error_t gsti_buf_putuint32 (gsti_buffer_t buf, gsti_uint32_t val);

/* Append the string data, AMOUNT bytes starting from DATA, to the
   buffer BUF.  */
gpg_error_t gsti_buf_putstr (gsti_buffer_t buf, const char *data,
			      size_t amount);

/* Append the binary string BSTR to the buffer BUF.  */
gpg_error_t gsti_buf_putbstr (gsti_buffer_t buf, gsti_bstr_t bstr);

/* Append the MPI VAL to the buffer BUF.  */
gpg_error_t gsti_buf_putmpi (gsti_buffer_t buf, gcry_mpi_t mpi);

/* Append AMOUNT bytes starting from DATA to the buffer BUF.  */
gpg_error_t gsti_buf_putraw (gsti_buffer_t buf, const char *data,
			      size_t amount);


/* Functions for reading from the buffer.  These functions usually
   increase the buffer offset.  */

/* Return the amount of data left for reading in the buffer BUF
   without changing the buffer offset.  */
size_t gsti_buf_readable (gsti_buffer_t buf);

/* Return a pointer to the first byte of the currently readable buffer
   data.  */
void *gsti_buf_getptr (gsti_buffer_t buf);

/* Return the character at the current offset in the buffer BUF in
   R_CHR, and increase the offset to point to the byte following that
   character.  Returns the GPG_ERR_INV_PACKET error code if there is
   no more character in the buffer.  */
gpg_error_t gsti_buf_getc (gsti_buffer_t buf, int *r_chr);

/* Return the byte at the current offset in the buffer BUF in R_VAL, and
   increase the offset to point to the byte following that character.
   Returns the GPG_ERR_INV_PACKET error code if there is no more
   character in the buffer.  */
gpg_error_t gsti_buf_getbyte (gsti_buffer_t buf, gsti_byte_t *r_val);

/* Return the boolean at the current offset in the buffer BUF in
   R_VAL, and increase the offset to point to the byte following that
   boolean.  Returns the GPG_ERR_INV_PACKET error code if there is no
   boolean in the buffer.  */
gpg_error_t gsti_buf_getbool (gsti_buffer_t buf, int *r_val);

/* Return the 32-bit unsigned integer at the current offset in the
   buffer BUF in R_VAL, and increase the offset to point to the byte
   following that integer.  Returns the GPG_ERR_INV_PACKET error code
   if there is no more character in the buffer.  */
gpg_error_t gsti_buf_getuint32 (gsti_buffer_t buf, gsti_uint32_t *r_val);

/* Return the string at the current offset in the buffer BUF in R_STR
   and its length in R_LENGTH, and increase the offset to point to the
   byte following that string.  Returns the GPG_ERR_INV_PACKET error
   code if there is no valid string in the buffer.  The returned
   string is allocated with malloc and must be freed by the user.  */
gpg_error_t gsti_buf_getstr (gsti_buffer_t buf, char **r_str,
			      size_t *r_length);

/* Return the binary string at the current offset in the buffer BUF in
   R_BSTR, and increase the offset to point to the byte following that
   binary string.  Returns the GPG_ERR_INV_PACKET error code if there
   is no valid binary string in the buffer.  */
gpg_error_t gsti_buf_getbstr (gsti_buffer_t buf, gsti_bstr_t *r_bstr);

/* Return the MPI at the current offset in the buffer BUF in R_VAL,
   and increase the offset to point to the byte following that MPI.
   Returns the GPG_ERR_INV_PACKET error code if there is no valid MPI
   in the buffer.  */
gpg_error_t gsti_buf_getmpi (gsti_buffer_t buf, gcry_mpi_t *r_val);

/* Return AMOUNT bytes starting from the current offset in the buffer
   BUF in DATA, and increase the offset to point to the byte following
   that data.  Returns the GPG_ERR_INV_PACKET error code if there are
   not AMOUNT bytes available in the buffer.  */
gpg_error_t gsti_buf_getraw (gsti_buffer_t buf, char *data, size_t amount);


#endif	/* GSTI_BUFFER_H */
