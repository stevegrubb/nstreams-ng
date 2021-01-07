dnl
dnl autoconf script for nstreams
dnl


AC_REVISION($Revision: 1.3 $)dnl
AC_INIT(nstreams-ng, 1.1)
AC_PREREQ(2.12)dnl
AM_CONFIG_HEADER(config.h)

echo Configuring nstreams-ng $VERSION

AC_CONFIG_MACRO_DIR([m4])
AC_CANONICAL_TARGET
AM_INIT_AUTOMAKE(foreign subdir-objects)
AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

echo .
echo Checking for programs
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_AWK

echo .
echo Checking for header files
AC_CHECK_HEADERS(errno.h sys/types.h netinet/in.h sys/socket.h netdb.h \
arpa/inet.h string.h signal.h netinet/in_systm.h sys/types.h sys/time.h \
unistd.h ctype.h getopt.h)

AC_CHECK_LIB(pcap, pcap_open_live,,AC_ERROR("*** You need the pcap library"))

AC_CHECK_FUNCS(bzero inet_ntoa)

AC_DEFINE_UNQUOTED(ETC_NSTREAMS_NETWORKS, "${sysconfdir}/nstreams-networks", [Networks database])
AC_DEFINE_UNQUOTED(ETC_NSTREAMS_SERVICES, "${sysconfdir}/nstreams-services", [Services database])

AC_OUTPUT(Makefile src/Makefile docs/Makefile)

echo .
echo "

  nstreams-ng Version:    $VERSION
  Target:                 $target
  Installation prefix:    $prefix
  Compiler:               $CC
  Compiler flags:
`echo $CFLAGS | fmt -w 50 | sed 's,^,                          ,'`
"

