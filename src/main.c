/* main.c  -  Main APIs
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
#include <ctype.h>
#include <string.h>

#include "api.h"
#include "memory.h"
#include "fsm.h"
#include "packet.h"

static const char*
parse_version_number( const char *s, int *number )
{
    int val = 0;

    if( *s == '0' && isdigit(s[1]) )
	return NULL; /* leading zeros are not allowed */
    for ( ; isdigit(*s); s++ ) {
	val *= 10;
	val += *s - '0';
    }
    *number = val;
    return val < 0? NULL : s;
}


static const char *
parse_version_string( const char *s, int *major, int *minor, int *micro )
{
    s = parse_version_number( s, major );
    if( !s || *s != '.' )
	return NULL;
    s++;
    s = parse_version_number( s, minor );
    if( !s || *s != '.' )
	return NULL;
    s++;
    s = parse_version_number( s, micro );
    if( !s )
	return NULL;
    return s; /* patchlevel */
}

/****************
 * Check that the the version of the library is at minimum the requested one
 * and return the version string; return NULL if the condition is not
 * satisfied.  If a NULL is passed to thsi function, no check is done,
 * but the version string is simpley returned.
 */
const char *
gsti_check_version( const char *req_version )
{
    const char *ver = VERSION;
    int my_major, my_minor, my_micro;
    int rq_major, rq_minor, rq_micro;
    const char *my_plvl, *rq_plvl;

    if ( !req_version )
	return ver;

    my_plvl = parse_version_string( ver, &my_major, &my_minor, &my_micro );
    if ( !my_plvl )
	return NULL;  /* very strange our own version is bogus */
    rq_plvl = parse_version_string( req_version, &rq_major, &rq_minor,
								&rq_micro );
    if ( !rq_plvl )
	return NULL;  /* req version string is invalid */

    if ( my_major > rq_major
	|| (my_major == rq_major && my_minor > rq_minor)
	|| (my_major == rq_major && my_minor == rq_minor
				 && my_micro > rq_micro)
	|| (my_major == rq_major && my_minor == rq_minor
				 && my_micro == rq_micro
				 && strcmp( my_plvl, rq_plvl ) >= 0) ) {
	return ver;
    }
    return NULL;
}


GSTIHD
gsti_init()
{
    GSTIHD hd;

    hd = gsti_calloc( 1, sizeof *hd );
    init_packet(hd);
    return hd;
}


int
gsti_deinit( GSTIHD hd )
{
    /* TODO ... */
    if( hd )
	gsti_free( hd );
    return 0;
}


int
gsti_set_readfnc( GSTIHD hd, GSTI_READ_FNC readfnc )
{
    hd->readfnc = readfnc;
    return 0;
}

int
gsti_set_writefnc( GSTIHD hd, GSTI_WRITE_FNC writefnc )
{
    hd->writefnc = writefnc;
    return 0;
}


/****************
 * A client can request a special service using this function.
 * A servicename must habe a @ in it, so that it does not conflict
 * with any standard service. Comma and colons should be avoided in
 * a service name.
 * If this is not used, a standard SSH service is used.
 * A server must use this function to set acceptable services.
 * A client uses the first service from the list.
 */
int
gsti_set_service( GSTIHD hd, const char *svcname )
{
    STRLIST s;

    if( !svcname || !*svcname )
	return 0;
    hd->local_services = parse_algorithm_list( svcname, strlen(svcname));
    for(s=hd->local_services; s; s= s->next ) {
	if( !strchr(s->d,'@') )
	    ;
    }
    return 0;
}

/****************
 * Read data from the GSTI stream.  This automagically initializes the
 * the system and decides whether we are client or server.  We are the
 * server side when this function is called before the first gsti_write
 * and vice versa.  Everything to setup the secure transport is handled
 * here.
 *
 * length must point to a variable having the size of the provided buffer
 * and will receive the actuall number of bytes read, which may be less
 * than the buffer. EOF is indicated by returning a zero length.
 * Returns: errocode.
 */
int
gsti_read( GSTIHD hd, void *buffer, size_t *length )
{
    int rc = 0;
    hd->user_read_buffer = buffer;
    hd->user_read_bufsize= *length;
    hd->user_read_nbytes = 0;
    /*rc = fsm_user_read( hd );*/
    *length = hd->user_read_nbytes;
    return rc;
}

/****************
 * The counterpart to gsti_read.
 */
int
gsti_write( GSTIHD hd, const void *buffer, size_t length )
{
    if( hd->local_services ) {
	const byte *p = buffer;
	/* check that the buffer contains valid packet types */
	if( !length || *p < 192 )
	    return GSTI_INV_ARG;
    }

    hd->user_write_buffer  = buffer;
    hd->user_write_bufsize = length;
    return -1 /*fsm_user_write( hd )*/;
}



