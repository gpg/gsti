
dnl GNUPG_FIX_HDR_VERSION(FILE, NAME)
dnl Make the version number in gcrypt/gcrypt.h the same as the one here.
dnl (this is easier than to have a .in file just for one substitution)
dnl
AC_DEFUN(GNUPG_FIX_HDR_VERSION,
  [ sed "s/^#define $2 \".*/#define $2 \"$VERSION\"/" $1 > $1.tmp
    if cmp -s $1 $1.tmp 2>/dev/null; then
	rm -f $1.tmp
    else
	rm -f $1
	if mv $1.tmp $1 ; then
	    :
	else
	    AC_MSG_ERROR([[
*** Failed to fix the version string macro $2 in $1.
*** The old file has been saved as $1.tmp
			 ]])
	fi
	AC_MSG_WARN([fixed the $2 macro in $1])
    fi
  ])


