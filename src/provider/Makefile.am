AM_CPPFLAGS=-I../include
COMMONLIB = ../libcommon/libcommon.a ../opensslmissing/libosslm.a

if HAVE_OPENSSL3
openssl_provider_LTLIBRARIES=libtpm2.la
openssl_providerdir=@modulesdir@

libtpm2_la_LDFLAGS= -no-undefined -avoid-version
libtpm2_la_LIBADD=${COMMONLIB} ${DEPS_LIBS}
libtpm2_la_SOURCES=provider.c decode_encode.c keymgmt.c signatures.c decryption.c store.c
libtpm2_la_CFLAGS=${DEPS_CFLAGS} -g -Werror

install-data-hook:
	cd $(DESTDIR)$(openssl_providerdir) && $(LN_S) -f libtpm2@SHREXT@ tpm2@SHREXT@

endif
