/* keytool.c
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

#include <stdio.h>
#include <malloc.h>

#include "gsti.h"

#define PUBKEY "dsa.pub"
#define SECKEY "dsa.sec"

/* fingerprint #77:82:ed:59:b0:a3:b3:5b:8b:c1:66:cd:01:9b:97:80# */
/* secret key #7e:17:76:1b:3a:fe:05:ff:a9:08:4e:2b:6c:fd:aa:a6:c0:a6:b5:90# */

void
print_fpr( unsigned char *fpr )
{
    unsigned char *fprhex;
    int i;
    
    fprhex = calloc( 1, 128 );
    for( i = 0; i < 16; i++ ) {
        int c = (i != 15)? ':' : ' ';
        sprintf( fprhex + 3*i, "%02X%c", fpr[i], c );
    }
    fprintf( stderr, "%s\n", fprhex );
    free( fprhex );
}


int
main( int argc, char **argv )
{
    GSTI_KEY key;
    unsigned char *fpr;
    int rc;

    rc = gsti_key_load( PUBKEY, GSTI_PK_DSS, 0, &key );
    if( rc ) {
        printf( "load pubkey: %s: `%s'\n", PUBKEY, gsti_strerror( rc ) );
        exit( 1 );
    }
    fpr = gsti_key_fingerprint( key, GSTI_DIGEST_MD5 );
    if( !fpr )
        printf( "could not get fingerprint.\n" );
    else
        print_fpr( fpr );
    gsti_key_free( key );

    rc = gsti_key_load( SECKEY, GSTI_PK_DSS, 1, &key );
    if( rc )
        printf( "load seckey: %s: `%s'\n", SECKEY, gsti_strerror( rc ) );
    gsti_key_free( key );
    
    return 0;
}
