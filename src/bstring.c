/* bstring.c - Binary string management for GSTI.
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

#include "gsti.h"

#include "types.h"


struct gsti_bstr
{
  /* The length of the binary string.  */
  size_t length;

  /* This is really the whole string following here.  */
  gsti_byte_t data[1];
};


/* Create a new binary string from AMOUNT bytes starting from DATA,
   and return it in BSTR.  */
gsti_error_t
gsti_bstr_make (gsti_bstr_t *bstr, const gsti_byte_t *data, size_t amount)
{
  *bstr = malloc (sizeof (struct gsti_bstr) - 1 + amount);

  if (!*bstr)
    return gpg_error_from_errno (errno);

  (*bstr)->length = amount;
  if (data)
    memcpy ((*bstr)->data, data, amount);

  return 0;
}


/* Free the binary string BSTR.  */
void
gsti_bstr_free (gsti_bstr_t bstr)
{
  if (bstr)
    free (bstr);
}


/* Return the length of the binary string BSTR.  */
size_t
gsti_bstr_length (gsti_bstr_t bstr)
{
  return bstr->length;
}


/* Return the data of the binary string BSTR.  */
gsti_byte_t *gsti_bstr_data (gsti_bstr_t bstr)
{
  return bstr->data;
}
