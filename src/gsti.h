/* gsti.h -  GNU secure transport initiative
 *	Copyright (C) 1999, 2000 Free Software Foundation, Inc.
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

#ifndef _GSTI_H
#define _GSTI_H
#ifdef __cplusplus
extern "C" {
#endif


/*
 * The version of this header should match the one of the library
 * It should not be used by a program because gcry_check_version()
 * should reurn the same version.  The purpose of this macro is to
 * let autoconf (using the AM_PATH_GSTI macro) check that this
 * header matches the installed library.
 * NOTE: Please do not chnange the formatting of this line;
 *	 configure may set it to the correct version.
 */
#define GSTI_VERSION "0.0.1"

enum {
    GSTI_SUCCESS = 0,	 /* "no error" */
    GSTI_GENERAL = 1,	 /* catch all the other errors code */
    GSTI_BUG	 = 2,	 /* internal error */
    GSTI_INV_ARG = 3,	 /* invalid argument */
    GSTI_NO_DATA = 4,	 /* no data to process (eof) */
    GSTI_NOT_SSH = 5,	 /* not connected to a SSH protocol stream */
    GSTI_PRE_EOF = 6,	 /* premature EOF */
    GSTI_TOO_SHORT=7,	 /* some entity is too short */
    GSTI_TOO_LARGE=8,	 /* .. too long */
    GSTI_READ_ERROR = 9,
    GSTI_WRITE_ERROR = 10,
    GSTI_INV_PKT = 11,
    GSTI_INV_OBJ = 12,
    GSTI_INV_MAC = 13,
    GSTI_PROT_VIOL = 14,
};


/* Our handle type */
struct gsti_context;
typedef struct gsti_context* GSTIHD;

/* some handy types */
typedef int (*GSTI_READ_FNC)( GSTIHD, void*, size_t* );
typedef int (*GSTI_WRITE_FNC)( GSTIHD, const void*, size_t );


typedef struct {
    size_t	datalen;
    const char *data;
    unsigned long seqno;
} GSTI_PKTDESC;


/*-- main.c --*/
const char *gsti_check_version( const char *req_version );
GSTIHD gsti_init( void );
int gsti_deinit( GSTIHD hd );
int gsti_set_readfnc( GSTIHD hd, GSTI_READ_FNC readfnc );
int gsti_set_writefnc( GSTIHD hd, GSTI_WRITE_FNC writefnc );
int gsti_set_service( GSTIHD hd, const char *svcname );
int gsti_read( GSTIHD hd, void *buffer, size_t *length );
int gsti_write( GSTIHD hd, const void *buffer, size_t length );

/*-- fsm.c --*/
int gsti_get_packet( GSTIHD hd, GSTI_PKTDESC *pkt );
int gsti_put_packet( GSTIHD hd, GSTI_PKTDESC *pkt );

/*-- errors.c --*/
const char *gsti_strerror( int ec );







#ifdef __cplusplus
}
#endif
#endif /* _GSTI_H */
