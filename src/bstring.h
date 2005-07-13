/* bstring.h - Binary string handling.
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

#ifndef GSTI_BSTRING_H
#define GSTI_BSTRING_H	1


/* Binary strings.  */

/* Binary strings are strings which may contain binary zeroes.  */
struct gsti_bstr;
typedef struct gsti_bstr *gsti_bstr_t;

/* Create a new binary string from AMOUNT bytes starting from DATA,
   and return it in BSTR.  */
gpg_error_t gsti_bstr_make (gsti_bstr_t *bstr,
			    const void *data, size_t amount);

/* Free the binary string BSTR.  */
void gsti_bstr_free (gsti_bstr_t bstr);

/* Return the length of the binary string BSTR.  */
size_t gsti_bstr_length (gsti_bstr_t bstr);

/* Return the data of the binary string BSTR.  */
void *gsti_bstr_data (gsti_bstr_t bstr);


#endif	/* GSTI_BSTRING_H */
