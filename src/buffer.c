/* buffer.c - Buffer handling for GSTI.
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

#if HAVE_CONFIG_H
#include <config.h>
#endif

#include <errno.h>
#include <stdlib.h>

#include <gcrypt.h>

#include "gsti.h"

#include "ssh.h"
#include "buffer.h"

/* FIXME: The code assumes that size_t can hold a 32 bit unsigned
   integer.  */


/* The buffer size will always be a multiple of this.  Must be a power
   of 2.  */
#define GSTI_BUFFER_STEP_SIZE	(1 << 10)


/* Ensure that at least AMOUNT of bytes are free in the buffer BUF,
   growing the buffer if necessary.  */
static gsti_error_t
buffer_grow (gsti_buffer_t buf, size_t amount)
{
  size_t new_size = buf->end + amount;
  unsigned char *new_data;

  if (new_size <= buf->size)
    return 0;

  /* Round up to nearest buffer size.  */
  new_size = (new_size + GSTI_BUFFER_STEP_SIZE - 1)
    & ~(GSTI_BUFFER_STEP_SIZE - 1);

  if (!buf->data)
    new_data = malloc (new_size);
  else
    new_data = realloc (buf->data, new_size);

  if (!new_data)
    return gpg_error_from_errno (errno);

  buf->data = new_data;
  buf->size = new_size;

  return 0;
}


/* Create a new buffer and return it in R_BUF.  */
gsti_error_t
gsti_buf_alloc (gsti_buffer_t *r_buf)
{
  gsti_buffer_t buf;

  buf = malloc (sizeof (*buf));

  if (!buf)
    return gpg_error_from_errno (errno);

  buf->data = NULL;
  buf->size = 0;
  buf->end = 0;
  buf->offset = 0;

  *r_buf = buf;
  return 0;
}


/* Destroy the buffer BUF and release all associated resources.  */
void
gsti_buf_free (gsti_buffer_t buf)
{
  if (!buf)
    return;

  if (buf->data)
    free (buf->data);
  free (buf);
}


/* Set the content of the buffer to AMOUNT bytes starting from DATA,
   and reset the buffer offset.  */
gsti_error_t
gsti_buf_set (gsti_buffer_t buf, const char *data, size_t amount)
{
  buf->end = 0;
  buf->offset = 0;

  return gsti_buf_putraw (buf, data, amount);
}


/* Append the character CHR to the buffer BUF.  */
gsti_error_t
gsti_buf_putc (gsti_buffer_t buf, int chr)
{
  gsti_error_t err;

  err = buffer_grow (buf, 1);
  if (!err)
    buf->data[buf->end++] = (unsigned char) (chr & 0xff);

  return err;
}


/* Append the byte VAL to the buffer BUF.  */
gsti_error_t
gsti_buf_putbyte (gsti_buffer_t buf, unsigned char val)
{
  gsti_error_t err;

  err = buffer_grow (buf, 1);
  if (!err)
    buf->data[buf->end++] = val;

  return err;
}


/* Append the boolean VAL to the buffer BUF.  */
gpg_error_t
gsti_buf_putbool (gsti_buffer_t buf, int val)
{
  return gsti_buf_putbyte (buf, val ? SSH_TRUE : SSH_FALSE);
}


/* Append the 32-bit unsigned integer to the buffer BUF.  */
gsti_error_t
gsti_buf_putuint32 (gsti_buffer_t buf, gsti_uint32_t val)
{
  gsti_error_t err;

  err = buffer_grow (buf, 4);
  if (!err)
    {
      buf->data[buf->end++] = val >> 24;
      buf->data[buf->end++] = val >> 16;
      buf->data[buf->end++] = val >> 8;
      buf->data[buf->end++] = val;
    }

  return err;
}


/* Append the string data, AMOUNT bytes starting from DATA, to the
   buffer BUF.  */
gsti_error_t
gsti_buf_putstr (gsti_buffer_t buf, const char *data, size_t amount)
{
  gsti_error_t err;

  err = gsti_buf_putuint32 (buf, amount);
  if (err)
    return err;

  return gsti_buf_putraw (buf, data, amount);
}


/* Append the binary string BSTR to the buffer BUF.  */
gpg_error_t
gsti_buf_putbstr (gsti_buffer_t buf, gsti_bstr_t bstr)
{
  if (!bstr)
    return 0;

  return gsti_buf_putstr (buf, gsti_bstr_data (bstr), gsti_bstr_length (bstr));
}


/* Append the MPI VAL to the buffer BUF.  */
gsti_error_t
gsti_buf_putmpi (gsti_buffer_t buf, gcry_mpi_t mpi)
{
  gsti_error_t err;
  unsigned char mpibuf[512];
  size_t mpilen;

  err = gcry_mpi_print (GCRYMPI_FMT_SSH, mpibuf, sizeof (mpibuf), &mpilen,
			mpi);
  if (!err)
    err = gsti_buf_putraw (buf, mpibuf, mpilen);

  return err;
}


/* Append AMOUNT bytes starting from DATA to the buffer BUF.  */
gsti_error_t
gsti_buf_putraw (gsti_buffer_t buf, const char *data, size_t amount)
{
  gsti_error_t err;

  err = buffer_grow (buf, amount);
  if (!err)
    {
      memcpy (&buf->data[buf->end], data, amount);
      buf->end += amount;
    }

  return err;
}


/* Return the amount of data left for reading in the buffer BUF.  */
size_t
gsti_buf_readable (gsti_buffer_t buf)
{
  return buf->end - buf->offset;
}


/* Return a pointer to the first byte of the currently readable buffer
   data.  */
void *
gsti_buf_getptr (gsti_buffer_t buf)
{
  return &buf->data[buf->offset];
}


/* Return the character at the current offset in the buffer BUF in
   VAL, and increase the offset to point to the byte following that
   character.  Returns the GPG_ERR_INV_PACKET error code if there is
   no more character in the buffer.  */
gsti_error_t
gsti_buf_getc (gsti_buffer_t buf, int *r_chr)
{
  if (gsti_buf_readable (buf) < 1)
    return gsti_error (GPG_ERR_INV_PACKET);

  *r_chr = (char) buf->data[buf->offset++];
  return 0;
}


/* Return the byte at the current offset in the buffer BUF in R_VAL, and
   increase the offset to point to the byte following that character.
   Returns the GPG_ERR_INV_PACKET error code if there is no more
   character in the buffer.  */
gsti_error_t
gsti_buf_getbyte (gsti_buffer_t buf, unsigned char *r_val)
{
  if (gsti_buf_readable (buf) < 1)
    return gsti_error (GPG_ERR_INV_PACKET);

  *r_val = buf->data[buf->offset++];
  return 0;
}



/* Return the boolean at the current offset in the buffer BUF in
   R_VAL, and increase the offset to point to the byte following that
   boolean.  Returns the GPG_ERR_INV_PACKET error code if there is no
   boolean in the buffer.  */
gpg_error_t
gsti_buf_getbool (gsti_buffer_t buf, int *r_val)
{
  gpg_error_t err;
  gsti_byte_t val;

  err = gsti_buf_getbyte (buf, &val);
  if (err)
    return err;

  *r_val = val ? 1 : 0;
  return 0;
}


/* Return the 32-bit unsigned integer at the current offset in the
   buffer BUF in VAL, and increase the offset to point to the byte
   following that integer.  Returns the GPG_ERR_INV_PACKET error code
   if there is no more character in the buffer.  */
gsti_error_t
gsti_buf_getuint32 (gsti_buffer_t buf, gsti_uint32_t *val)
{
  if (gsti_buf_readable (buf) < 4)
    return gsti_error (GPG_ERR_INV_PACKET);

  *val = buf->data[buf->offset++] << 24;
  *val |= buf->data[buf->offset++] << 16;
  *val |= buf->data[buf->offset++] << 8;
  *val |= buf->data[buf->offset++];

  return 0;
}
  

/* Return the string at the current offset in the buffer BUF in R_STR
   and its length in R_LENGTH (without the trailing zero), and
   increase the offset to point to the byte following that string.  A
   trailing zero will be appended to the string.  Returns the
   GPG_ERR_INV_PACKET error code if there is no valid string in the
   buffer.  The returned string is allocated with malloc and must be
   freed by the user.  */
gsti_error_t
gsti_buf_getstr (gsti_buffer_t buf, char **r_str, size_t *r_length)
{
  gsti_error_t err;
  char *str;
  size_t len;

  err = gsti_buf_getuint32 (buf, &len);
  if (err)
    return err;

  if (len > gsti_buf_readable (buf))
    return gsti_error (GPG_ERR_INV_PACKET);

  str = malloc (len + 1);
  if (!str)
    return gpg_error_from_errno (errno);

  err = gsti_buf_getraw (buf, str, len);
  if (err)
    {
      free (str);
      return err;
    }
  str[len] = '\0';

  *r_str = str;
  *r_length = (size_t) len;

  return 0;
}


/* Return the binary string at the current offset in the buffer BUF in
   R_BSTR, and increase the offset to point to the byte following that
   binary string.  Returns the GPG_ERR_INV_PACKET error code if there
   is no valid binary string in the buffer.  */
gpg_error_t
gsti_buf_getbstr (gsti_buffer_t buf, gsti_bstr_t *r_bstr)
{
  gsti_error_t err;
  size_t len;

  err = gsti_buf_getuint32 (buf, &len);
  if (err)
    return err;

  if (len > gsti_buf_readable (buf))
    return gsti_error (GPG_ERR_INV_PACKET);

  err = gsti_bstr_make (r_bstr, buf->data + buf->offset, len);
  if (err)
    return err;

  buf->offset += len;

  return 0;
}



/* Return the MPI at the current offset in the buffer BUF in R_VAL,
   and increase the offset to point to the byte following that MPI.
   Returns the GPG_ERR_INV_PACKET error code if there is no valid MPI
   in the buffer.  */
gsti_error_t
gsti_buf_getmpi (gsti_buffer_t buf, gcry_mpi_t *r_val)
{
  gsti_error_t err;
  unsigned char mpibuf[512];
  size_t mpilen;

  err = gsti_buf_getuint32 (buf, &mpilen);
  if (err)
    return err;

  if (mpilen > sizeof (mpibuf) - 4)
    return gsti_error (GPG_ERR_INV_PACKET);

  mpibuf[0] = mpilen >> 24;
  mpibuf[1] = mpilen >> 16;
  mpibuf[2] = mpilen >> 8;
  mpibuf[3] = mpilen;
  gsti_buf_getraw (buf, mpibuf + 4, mpilen);

  return gcry_mpi_scan (r_val, GCRYMPI_FMT_SSH, mpibuf, mpilen + 4, NULL);
}


/* Return AMOUNT bytes starting from the current offset in the buffer
   BUF in DATA, and increase the offset to point to the byte following
   that data.  Returns the GPG_ERR_INV_PACKET error code if there are
   not AMOUNT bytes available in the buffer.  */
gsti_error_t
gsti_buf_getraw (gsti_buffer_t buf, char *data, size_t amount)
{
  if (amount > gsti_buf_readable (buf))
    return gsti_error (GPG_ERR_INV_PACKET);

  memcpy (data, buf->data + buf->offset, amount);
  buf->offset += amount;

  return 0;
}
