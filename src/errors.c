/* errors.c -  error codes and strings
 *	Copyright (C) 1999 Free Software Foundation, Inc.
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

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <gcrypt.h>

#include "api.h"


const char*
gsti_strerror( int ec )
{
    switch( ec ) {
      case GSTI_SUCCESS:     return "success";
      case GSTI_GENERAL:     return "general error";
      case GSTI_BUG:	     return "internal error";
      case GSTI_INV_ARG:     return "invalid argument";
      case GSTI_NO_DATA:     return "no data to process (eof)";
      case GSTI_NOT_SSH:     return "not connected to a SSH protocol stream";
      case GSTI_PRE_EOF:     return "premature end-of-file";
      case GSTI_TOO_SHORT:   return "an entity is too short";
      case GSTI_TOO_LARGE:   return "an entity is too large";
      case GSTI_READ_ERROR:  return "read error";
      case GSTI_WRITE_ERROR: return "write error";
      case GSTI_INV_PKT:     return "invalid packet";
      case GSTI_INV_OBJ:     return "invalid object";
      case GSTI_PROT_VIOL:   return "protocol violation";

      default: return "[?]";
    }
}


int
map_gcry_rc( int rc )
{
    switch( rc )  {
      case 0: return 0;
      case GCRYERR_INV_ARG:	return GSTI_INV_ARG;
      case GCRYERR_INTERNAL:	return GSTI_BUG;
      case GCRYERR_TOO_SHORT:	return GSTI_TOO_SHORT;
      case GCRYERR_TOO_LARGE:	return GSTI_TOO_LARGE;
      case GCRYERR_INV_OBJ:	return GSTI_INV_OBJ;
      default: return GSTI_GENERAL;
    }
}

