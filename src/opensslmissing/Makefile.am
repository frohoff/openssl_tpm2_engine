noinst_LIBRARIES = libosslm.a

AM_CPPFLAGS = -I ../include

if HAVE_OPENSSL3
libosslm_a_SOURCES = rsa.c signature.c
libosslm_a_CFLAGS = -fPIC
endif
