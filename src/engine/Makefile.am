AM_CPPFLAGS = -I ../include ${DEPRECATION}

openssl_engine_LTLIBRARIES=libtpm2.la
openssl_enginedir=@enginesdir@

COMMONLIB = ../libcommon/libcommon.a

libtpm2_la_LDFLAGS= -no-undefined -avoid-version
libtpm2_la_LIBADD=${COMMONLIB} ${DEPS_LIBS}
libtpm2_la_SOURCES=e_tpm2.c e_tpm2-rsa.c e_tpm2-ecc.c
libtpm2_la_CFLAGS=${DEPS_CFLAGS}

# openssl from 1.1.0 looks for engine.so not libengine.so
install-data-hook:
	cd $(DESTDIR)$(openssl_enginedir) && $(LN_S) -f libtpm2@SHREXT@ tpm2@SHREXT@
