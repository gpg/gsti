dnl Autoconf macros for libgsti

# Configure paths for GSTI
# Shamelessly stolen from the one of XDELTA by Owen Taylor
# Werner Koch   99-12-08

dnl AM_PATH_GSTI([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND ]]])
dnl Test for gsti, and define GSTI_CFLAGS and GSTI_LIBS
dnl
AC_DEFUN(AM_PATH_GSTI,
[dnl
dnl Get the cflags and libraries from the gsti-config script
dnl
AC_ARG_WITH(gsti-prefix,
          [  --with-gsti-prefix=PFX   Prefix where gsti is installed (optional)],
          gsti_config_prefix="$withval", gsti_config_prefix="")
AC_ARG_ENABLE(gstitest,
          [  --disable-gstitest    Do not try to compile and run a test gsti program],
          , enable_gstitest=yes)

  if test x$gsti_config_prefix != x ; then
     gsti_config_args="$gsti_config_args --prefix=$gsti_config_prefix"
     if test x${GSTI_CONFIG+set} != xset ; then
        GSTI_CONFIG=$gsti_config_prefix/bin/gsti-config
     fi
  fi

  AC_PATH_PROG(GSTI_CONFIG, gsti-config, no)
  min_gsti_version=ifelse([$1], ,0.0.0,$1)
  AC_MSG_CHECKING(for gsti - version >= $min_gsti_version)
  no_gsti=""
  if test "$GSTI_CONFIG" = "no" ; then
    no_gsti=yes
  else
    GSTI_CFLAGS=`$GSTI_CONFIG $gsti_config_args --cflags`
    GSTI_LIBS=`$GSTI_CONFIG $gsti_config_args --libs`
    gsti_config_version=`$GSTI_CONFIG $gsti_config_args --version`
    if test "x$enable_gstitest" = "xyes" ; then
      ac_save_CFLAGS="$CFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $GSTI_CFLAGS"
      LIBS="$LIBS $GSTI_LIBS"
dnl
dnl Now check if the installed gsti is sufficiently new. Also sanity
dnl checks the results of gsti-config to some extent
dnl
      rm -f conf.gstitest
      AC_TRY_RUN([
#include <gsti.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int
main ()
{
    system ("touch conf.gstitest");

    if( strcmp( gsti_check_version(NULL), "$gsti_config_version" ) )
    {
      printf("\n*** 'gsti-config --version' returned %s, but GSTI (%s)\n",
             "$gsti_config_version", gsti_check_version(NULL) );
      printf("*** was found! If gsti-config was correct, then it is best\n");
      printf("*** to remove the old version of GSTI. You may also be able to fix the error\n");
      printf("*** by modifying your LD_LIBRARY_PATH enviroment variable, or by editing\n");
      printf("*** /etc/ld.so.conf. Make sure you have run ldconfig if that is\n");
      printf("*** required on your system.\n");
      printf("*** If gsti-config was wrong, set the environment variable GSTI_CONFIG\n");
      printf("*** to point to the correct copy of gsti-config, and remove the file config.cache\n");
      printf("*** before re-running configure\n");
    }
    else if ( strcmp(gsti_check_version(NULL), GSTI_VERSION ) )
    {
      printf("*** GSTI header file (version %s) does not match\n", GSTI_VERSION);
      printf("*** library (version %s)\n", GSTI_VERSION, gsti_check_version(NULL) );
    }
    else
    {
      if ( gsti_check_version( "$min_gsti_version" ) )
      {
        return 0;
      }
     else
      {
        printf("\n*** An old version of GSTI (%s) was found.\n",
                gsti_check_version(NULL) );
        printf("*** You need a version of GSTI newer than %s. The latest version of\n",
               "$min_gsti_version" );
        printf("*** GSTI is always available from ftp://ftp.gnupg.org/pub/gcrypt/gsti.\n");
        printf("*** \n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the gsti-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of GSTI, but you can also set the GSTI_CONFIG environment to point to the\n");
        printf("*** correct copy of gsti-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
      }
    }
  return 1;
}
],, no_gsti=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       LIBS="$ac_save_LIBS"
     fi
  fi
  if test "x$no_gsti" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])
  else
     AC_MSG_RESULT(no)
     if test "$GSTI_CONFIG" = "no" ; then
       echo "*** The gsti-config script installed by GSTI could not be found"
       echo "*** If GSTI was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the GSTI_CONFIG environment variable to the"
       echo "*** full path to gsti-config."
     else
       if test -f conf.gstitest ; then
        :
       else
          echo "*** Could not run gsti test program, checking why..."
          CFLAGS="$CFLAGS $GSTI_CFLAGS"
          LIBS="$LIBS $GSTI_LIBS"
          AC_TRY_LINK([
#include <gsti.h>
#include <stdio.h>
],      [ return !!gsti_check_version(NULL); ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding GSTI or finding the wrong"
          echo "*** version of GSTI. If it is not finding GSTI, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
          echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means GSTI was incorrectly installed"
          echo "*** or that you have moved GSTI since it was installed. In the latter case, you"
          echo "*** may want to edit the gsti-config script: $GSTI_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     GSTI_CFLAGS=""
     GSTI_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  AC_SUBST(GSTI_CFLAGS)
  AC_SUBST(GSTI_LIBS)
  rm -f conf.gstitest
])

dnl *-*wedit:notab*-*  Please keep this as the last line.
