/* client.c  -	An example how to use gsti
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <gsti.h>

#define PGMNAME "ex-client: "

static int conn_fd = -1;

static void
log_rc( int rc, const char *text)
{
    const char *s;
    if( !*(s=gsti_strerror(rc)) || !strcmp(s,"[?]") )
	fprintf( stderr, PGMNAME "gsti_%s: rc=%d\n", text, rc );
    else
	fprintf( stderr, PGMNAME "gsti_%s: %s\n", text, s );
}

static void
make_connection( const char *host )
{
    struct sockaddr_in name;
    struct hostent *hostinfo;

    conn_fd = socket(PF_INET, SOCK_STREAM, 0 );
    if( conn_fd == -1 ) {
	fprintf( stderr, PGMNAME "socket() failed: %s\n", strerror(errno) );
	exit(2);
    }

    hostinfo = gethostbyname(host);
    if( !hostinfo ) {
	fprintf( stderr, PGMNAME "unknown host `%s'\n", host );
	exit(1);
    }
    name.sin_family = AF_INET;
    name.sin_port = htons(9000);
    name.sin_addr = *(struct in_addr*)hostinfo->h_addr;
    if( connect( conn_fd, (struct sockaddr*)&name, sizeof name) ) {
	fprintf( stderr, PGMNAME "connect() failed: %s\n", strerror(errno) );
	exit(2);
    }

}


static int
myread( GSTIHD hd, void *buffer, size_t *nbytes )
{
    int n;

    do {
	n = read( conn_fd, buffer, *nbytes );
    } while( n == -1 && errno == EINTR );
    if( n == -1 ) {
	fprintf( stderr, PGMNAME "myread: error: %s\n", strerror(errno) );
	return GSTI_READ_ERROR;
    }
    /*dump_hexbuf( stderr, "myread: ", buffer, n );*/
    *nbytes = n;
    return 0;
}


static int
mywrite( GSTIHD hd, const void *buffer, size_t nbytes )
{
    int n;
    const char *p = buffer;

    if( !buffer )
	return 0; /* no need for flushing */
    do {
	/*dump_hexbuf( stderr, "mywrite: ", p, nbytes );*/
	n = write( conn_fd, p, nbytes );
	if( n == -1 ) {
	    fprintf( stderr, PGMNAME "mywrite: error: %s\n", strerror(errno) );
	    return GSTI_WRITE_ERROR;
	}
	nbytes -= n;
	p += n;
    } while( nbytes );
    return 0;
}



int
main( int argc, char **argv )
{
    int rc;
    GSTIHD hd;
    GSTI_PKTDESC pkt;
    char buffer[100];
    size_t nbytes;

    if( argc ) { argc--; argv++; }

    hd = gsti_init();
    gsti_set_readfnc( hd, myread );
    gsti_set_writefnc( hd, mywrite );
   /* rc = gsti_set_service( hd, "log-lines@gnu.org" );
    log_rc( rc, "set-service" );*/

    make_connection(argc? *argv: "localhost");

    pkt.data = "\xf0""hallo";
    pkt.datalen = 5;
    rc = gsti_put_packet( hd, &pkt );
    log_rc( rc, "put_packet" );
    rc = gsti_put_packet( hd, NULL );
    log_rc( rc, "flush_packet" );


    gsti_deinit( hd );
    return 0;
}


