# Makefile.am --
# Copyright 2021 Steve Grubb
# All Rights Reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
# Authors:
#   Steve Grubb <sgrubb@redhat.com>
#

CONFIG_CLEAN_FILES = *.rej *.orig

AM_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/src
LIBS = -lpcap

AM_CFLAGS = -W -Wall -Wshadow -Wformat -Wundef
bin_PROGRAMS = nstreams
noinst_HEADERS = cache.h config_rules.h networks.h output.h parse_tcpdump.h ports.h read_pcap.h includes.h
nstreams_SOURCES = config_rules.c ports.c nstreams.c read_pcap.c networks.c parse_tcpdump.c output.c cache.c

