#!/bin/sh

if test "$1" = "--build-w32"; then
	if test -e Makefile; then
		echo "Run \"make distclean\" first"
		exit
	fi
	CC=`mingw32 --get-path gcc`
	CPP=`mingw32 --get-path cpp`
	AR=`mingw32 --get-path ar`
	RANLIB=`mingw32 --get-path ranlib`
	export CC CPP AR RANLIB
	./configure --host=i386-pc-mingw32 --target=i386--mingw32
	exit
fi

aclocal -I /usr/local/share/aclocal
autoheader
automake --gnu --add-missing
autoconf

./configure --enable-maintainer-mode

