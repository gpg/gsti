## Process this file with automake to produce Makefile.in
# Copyright (C) 1999, 2000 Werner Koch
# Copyright (C) 2002 Timo Schulz
# Copyright (C) 2004 g10 Code GmbH
#
# This file is part of GSTI.
#
# GSTI is free software; you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as
# published by the Free Software Foundation; either version 2.1 of
# the License, or (at your option) any later version.
#
# GSTI is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS = dist-bzip2

EXTRA_DIST = README-alpha autogen.sh

SUBDIRS = m4 src examples tests doc


dist-hook:
	@set -e; echo "$(VERSION)" > $(distdir)/VERSION

