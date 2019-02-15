#
# configure.in for the OpenSSL TPM engine project
#

AC_INIT(openssl-tpm2-engine, 2.2.0, <James.Bottomley@HansenPartnership.com>)
AM_INIT_AUTOMAKE([foreign 1.6.3])
AC_CANONICAL_HOST
AM_CONDITIONAL(NATIVE_BUILD, test "x$cross_compiling" = "xno")
PKG_PROG_PKG_CONFIG

AM_MISSING_PROG(HELP2MAN, help2man)

# Debugging support
AC_ARG_ENABLE(debug,
		AC_HELP_STRING([--enable-debug], [turn on all debugging flags [default is off]]),
		[enable_debug="yes"
		 AC_MSG_RESULT([*** Enabling debugging at user request ***])],)

# If the user has not set CFLAGS, do something appropriate
test_CFLAGS=${CFLAGS+set}
if test "$test_CFLAGS" != set; then
	if test "x$enable_debug" == "xyes"; then
		CFLAGS="-O0 -g -DDEBUG"
	else
		CFLAGS="-O2"
	fi
fi

##
# ibmtss >= 1234 now requires TPM_POSIX be set
CFLAGS="$CFLAGS -DTPM_POSIX"
CPPFLAGS="$CPPFLAGS -DTPM_POSIX"

#if test "${OPENSSL_LIB_DIR+set}" != set; then
#	OPENSSL_LIB_DIR="/usr/local/ssl/lib"
#fi
#if test "${OPENSSL_INCLUDE_DIR+set}" != set; then
#	OPENSSL_INCLUDE_DIR="/usr/local/ssl/include"
#fi

# Non-standard OpenSSL
AC_MSG_CHECKING([Non-standard OpenSSL])
AC_ARG_WITH(openssl,
	[--with-openssl=PATH      Location of openssl libs/includes],
	[OPENSSL_INCLUDE_DIR="$withval/include"
	 OPENSSL_LIB_DIR="$withval/lib"
	 if [[ ! -d $OPENSSL_INCLUDE_DIR -o ! -d $OPENSSL_LIB_DIR ]]; then
		AC_MSG_ERROR([$OPENSSL_INCLUDE_DIR or $OPENSSL_LIB_DIR doen't exist!])
	 else
		AC_MSG_RESULT([yes])
		CFLAGS="$CFLAGS -L$OPENSSL_LIB_DIR -I$OPENSSL_INCLUDE_DIR"
	 fi],
	[AC_MSG_RESULT([no])
	 AC_SUBST(OPENSSL_LIB_DIR)
	 AC_SUBST(OPENSSL_INCLUDE_DIR)])

AC_LANG(C)
AC_ARG_WITH(
	[enginesdir],
	[AC_HELP_STRING([--with-enginesdir], [OpenSSL engines directory])],
	[enginesdir="${withval}"],
	[AC_LANG_CONFTEST([AC_LANG_PROGRAM(
		[[
		  #define HEADER_CRYPTLIB_H
		  #include <openssl/crypto.h>
		  #include <stdio.h>
		]],
		[[
		  #if OPENSSL_VERSION_NUMBER < 0x10100000
		  puts(ENGINESDIR);
		  #else
		  puts(OpenSSL_version(OPENSSL_ENGINES_DIR));
		  #endif
		]]
		)])
		gcc $CFLAGS conftest.c -lcrypto
		enginesdir=`./a.out|sed 's/ENGINESDIR: //'`
	]
	)

if test -z "$enginesdir" ; then
    AC_MSG_FAILURE([Failed to find SSL engines directory])
fi

AC_SUBST(enginesdir)

PKG_CHECK_MODULES([DEPS], [libcrypto])

AC_SEARCH_LIBS([TSS_Create], [tss ibmtss], [], [
	AC_MSG_ERROR([Unable to find the TSS2 library])
])

AC_DISABLE_STATIC
AC_PROG_CC_STDC
AM_PROG_CC_C_O
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_PROG_LIBTOOL
AC_PROG_LN_S

AC_CHECK_HEADER([tss2/tss.h],[AC_DEFINE(TSS_INCLUDE,tss2)],
	AC_CHECK_HEADER([ibmtss/tss.h],[AC_DEFINE(TSS_INCLUDE,ibmtss)],
	   AC_MSG_ERROR([No TSS2 include directory found])))

CFLAGS="$CFLAGS -Wall"
SHREXT=$shrext_cmds
AC_SUBST(CFLAGS)
AC_SUBST(TSS_INCLUDE)
AC_SUBST(SHREXT)

AC_OUTPUT([Makefile tests/Makefile])

cat <<EOF

CFLAGS:				${CFLAGS}
openssl engines directory:	${enginesdir}

EOF

