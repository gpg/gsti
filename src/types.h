/* types.h
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

#ifndef GSTI_TYPES_H
#define GSTI_TYPES_H

/* all the user visible type are here */
#include <gsti.h>

#ifndef HAVE_BYTE_TYPEDEF
#undef byte
typedef unsigned char byte;
#define HAVE_BYTE_TYPEDEF
#endif

#ifndef HAVE_U32_TYPEDEF
#undef u32
typedef unsigned int u32;
#define HAVE_U32_TYPEDEF
#endif

#ifndef HAVE_U16_TYPEDEF
#undef u16
typedef unsigned short u16;
#define HAVE_U16_TYPEDEF
#endif

typedef struct strlist_s
{
  struct strlist_s *next;
  char d[1];
} *STRLIST;


/****************
 * I don't think that string is a good name for an generic data object,
 * so we call it BSTRING for BinaryString
 */
typedef struct bstring_s
{
  size_t len;
  unsigned char d[1];
} *BSTRING;

#ifndef DIM
#define DIM(v) (sizeof(v)/sizeof((v)[0]))
#endif

#endif /* GSTI_TYPES_H */
