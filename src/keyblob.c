/* keyblob.c  -  key blob handling
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

#include <config.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "memory.h"
#include "keyblob.h"


/****************
 * A secret keyfile has only two lines of the form:
 * ID=<decriptive string for this key>
 * DSA-X=<hexdata>
 *
 *
 * The public keyfile consists of multiple lines:
 *
 * ID=<decriptive string for the following keydata>
 * DSA-P=<hexdata>
 * DSA-Q=<hexdata>
 * DSA-G=<hexdata>
 * DSA-Y=<hexdata>
 *
 * Blank lines and lines starting with a # as first non-white space
 * character are comments.  Blanks arounf the equal sign are not allowed.
 */

/****************
 * Read an parse a line and return the line broken into the relevant parts
 * The line is modified.
 */
static int
parse_line( char *line, char **name, char **value )
{
    byte *mark, *p = line;

    *name = *value = NULL;
    while( isspace(*p) )
	p++;
    if( !*p || *p == '#' )
	return 0;
    *name = p;
    for(p++; *p && !isspace(*p) && *p != '='; p++ )
	;
    if( *p != '=' )
	return -1;  /* syntax error */
    p++;
    if( !*p || isspace(*p) )
	return -1; /* syntax error */
    *name = p;
    /* remove trailing spaces */
    for( mark = NULL,p++; *p; p++ ) {
	if( isspace( *p ) ) {
	    if( !mark )
		mark = p;
	}
	else
	    mark = NULL ;
    }
    if( mark )
	*mark = 0;  /* cut */
    return 0;
}



/****************
 * FIXME: better use mmap of read() for the secret key.
 */
static int
read_keyfile( FILE *fp, )
{


}




