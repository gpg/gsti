/* server.c  -	An example how to use gsti
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

#define PUBKEY "dsa.pub"
#define SECKEY "dsa.sec"

#define PGMNAME "ex-server: "

static int listen_fd = -1;
static int conn_fd = -1;

void
dump_hexbuf( FILE *fp, const char *prefix,const unsigned char *buf,size_t len )
{
    fputs( prefix, fp );
    for( ; len ; len--, buf++ )
        fprintf( fp, "%02X ", *buf );
    putc( '\n', fp );    
}

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
wait_connection( void )
{
    struct sockaddr_in name;
    struct sockaddr_in peer_name;
    int namelen;
    int one = 1;

    if( listen_fd != -1 )
        close( listen_fd );

    listen_fd = socket( PF_INET, SOCK_STREAM, 0 );
    if( listen_fd == -1 ) {
        fprintf( stderr, PGMNAME "socket() failed: %s", strerror(errno) );
        exit(2);
    }

    if( setsockopt( listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one) ){
        fprintf( stderr, PGMNAME "setsocketopt() failed: %s", strerror(errno));
        exit(2);
    }

    name.sin_family = AF_INET;
    name.sin_port = htons(9000);
    name.sin_addr.s_addr = htonl(INADDR_ANY);
    if( bind( listen_fd, (struct sockaddr*)&name, sizeof name) ) {
        fprintf( stderr, PGMNAME "bind() failed: %s", strerror(errno) );
        exit(2);
    }

    if( listen( listen_fd, 1 ) ) {
        fprintf( stderr, PGMNAME "listen() failed: %s\n", strerror(errno) );
        exit(2);
    }

    namelen = sizeof peer_name;
    conn_fd = accept( listen_fd, (struct sockaddr *)&peer_name, &namelen);
    if( conn_fd == -1 ) {
        fprintf( stderr, PGMNAME "accept() failed: %s\n", strerror(errno) );
        exit(2);
    }
    close( listen_fd );
    listen_fd = -1; /* not needed anymore */
}


static int
myread( GSTIHD hd, void *buffer, size_t *nbytes )
{
    int n;

    do {
        n = read( conn_fd, buffer, *nbytes );
    } while( n == -1 && errno == EINTR );
    if( n == -1 ) {
        fprintf( stderr, PGMNAME "myread: error: %s\n", strerror( errno ) );
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
    int rc, i;
    GSTIHD hd;
    GSTI_PKTDESC pkt;

    if( argc ) {
        argc--;
        argv++;
    }

    gsti_control( GSTI_SECMEM_INIT );
    gsti_set_log_level( GSTI_LOG_DEBUG );
    hd = gsti_init();
    gsti_set_hostkey( hd, SECKEY );
    gsti_set_readfnc( hd, myread );
    gsti_set_writefnc( hd, mywrite );

    /*rc = gsti_set_service( hd, "log-lines@gnu.org,dummy@gnu.org" );*/
    /*log_rc( rc, "set-service" );*/

    wait_connection();

    for( i = 0; i < 2; i++ ) {
        rc = gsti_get_packet( hd, &pkt );
        log_rc( rc, "get-packet" );
        if( !rc )
            dump_hexbuf( stderr, "got packet: ", pkt.data, pkt.datalen );
    }

    gsti_control( GSTI_SECMEM_RELEASE );
    rc = gsti_deinit( hd );
    log_rc( rc, "deinit" );
    return 0;
}


