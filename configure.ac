#
# configure.in for the OpenSSL TPM engine project
#

AC_INIT(openssl-tpm2-engine, 4.2.0, <openssl-tpm2-engine@groups.io>)
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

PKG_CHECK_MODULES([DEPS], [libcrypto >= 3.0.0],
                  [ac_have_openssl3=1],
		  [PKG_CHECK_MODULES([DEPS], [libcrypto])])

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

if test "$ac_have_openssl3" = "1"; then
    modulesdir=\"`$PKG_CONFIG --variable=modulesdir libcrypto`\"
    AC_SUBST(modulesdir)
fi

AC_SUBST(enginesdir)

PKG_CHECK_MODULES([DEPS], [libcrypto])

AC_SEARCH_LIBS([TSS_Create], [tss ibmtss], [
	AC_DEFINE(HAVE_IBM_TSS, 1, [Defined if we have the IBM TSS])
	tsslibs=IBM
    ], [
	AC_SEARCH_LIBS([Esys_Initialize], [tss2-esys], [
		LIBS="$LIBS -ltss2-mu -ltss2-rc -ltss2-tctildr"
		AC_DEFINE(HAVE_INTEL_TSS, 1, [Defined if we have the Intel TSS])
		tsslibs=Intel
	    ], [
		AC_MSG_ERROR([Unable to find either IBM or Intel TSS])
	    ])
])
AM_CONDITIONAL(HAVE_IBM_TSS, test "$tsslibs" = "IBM")

AM_CONDITIONAL(HAVE_OPENSSL3, test "$ac_have_openssl3" = "1")

AC_DISABLE_STATIC
AC_PROG_CC_STDC
AM_PROG_CC_C_O
AC_USE_SYSTEM_EXTENSIONS
AC_SYS_LARGEFILE
AC_PROG_LIBTOOL
AC_PROG_LN_S

if test "$tsslibs" = "IBM"; then
##
# ibmtss >= 1234 now requires TPM_POSIX be set
##
CFLAGS="$CFLAGS -DTPM_POSIX"
CPPFLAGS="$CPPFLAGS -DTPM_POSIX"
AC_CHECK_HEADER([tss2/tss.h],[AC_DEFINE(TSS_INCLUDE,tss2)],
	AC_CHECK_HEADER([ibmtss/tss.h],[AC_DEFINE(TSS_INCLUDE,ibmtss)],
	   AC_MSG_ERROR([No TSS2 include directory found])))
else
##
# Intel TSS has an API issue: Esys_TR_GetTpmHandle wasn't introduced
# until version 2.4.0.
#
# Note: the missing API is fairly serious and is also easily backportable
# so keep the check below as is intead of going by library version number.
##
AC_CHECK_LIB(tss2-esys, Esys_TR_GetTpmHandle, [], [
	AC_MSG_ERROR([Need Esys_TR_GetTpmHandle API (usually requires Intel TSS 2.4.0 or later)
	])])
fi

AC_PATH_PROG(TPMSERVER, tpm_server,,/bin:/usr/bin:/usr/lib/ibmtss:/usr/libexec/ibmtss)
AC_PATH_PROG(SWTPM, swtpm,,/bin:/usr/bin:/usr/lib/ibmtss:/usr/libexec/ibmtss)
AC_PATH_PROG(SWTPM_IOCTL, swtpm_ioctl,,/bin:/usr/bin:/usr/lib/ibmtss:/usr/libexec/ibmtss)
AC_CHECK_PROG(XML2RFC, xml2rfc, xml2rfc)
AM_CONDITIONAL(HAVE_XML2RFC, test -n "${XML2RFC}")
CFLAGS="$CFLAGS -Wall -Werror"
SHREXT=$shrext_cmds
if test -n "$ac_have_openssl3"; then
   DEPRECATION="-DOPENSSL_API_COMPAT=0x10100000L"
fi
AC_SUBST(CFLAGS)
AC_SUBST(DEPRECATION)
AC_SUBST(TSS_INCLUDE)
AC_SUBST(SHREXT)
TSSTYPE=$tsslibs
AC_SUBST(TSSTYPE)

if test -x "${TPMSERVER}"; then
   testtpm=tpm_server
elif test -x "${SWTPM}" -a -x "${SWTPM_IOCTL}"; then
   testtpm=swtpm
   unset TPMSERVER
else
    testtpm=
fi

AC_SUBST(testtpm)

AC_OUTPUT([Makefile
	   tests/engine/Makefile
	   tests/provider/Makefile
	   doc/Makefile
	   src/libcommon/Makefile
	   src/opensslmissing/Makefile
	   src/engine/Makefile
	   src/tools/Makefile
	   src/provider/Makefile])

cat <<EOF

CFLAGS:				${CFLAGS}
openssl engines directory:	${enginesdir}
openssl provider directory:	${modulesdir}
swtpm for testing:		${testtpm}
tss libraries:                  ${tsslibs}

EOF

if test -z "${testtpm}"; then
   AC_MSG_WARN([Software TPM  not found, engine will build but can't be tested])
fi
