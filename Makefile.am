EXTRA_DIST = README openssl.cnf.sample

if NATIVE_BUILD
EXTRA_DIST += create_tpm2_key.1 load_tpm2_key.1 seal_tpm2_data.1 \
	unseal_tpm2_data.1 signed_tpm2_policy.1
man1_MANS = create_tpm2_key.1 load_tpm2_key.1 seal_tpm2_data.1 \
	unseal_tpm2_data.1 signed_tpm2_policy.1

CLEANFILES = $(man1_MANS)
endif

if HAVE_OPENSSL3
CFLAGS+= -DOPENSSL_API_COMPAT=0x10100000L
endif

openssl_engine_LTLIBRARIES=libtpm2.la
bin_PROGRAMS=create_tpm2_key load_tpm2_key seal_tpm2_data unseal_tpm2_data \
	signed_tpm2_policy
openssl_enginedir=@enginesdir@

libtpm2_la_LDFLAGS= -no-undefined -avoid-version
libtpm2_la_LIBADD=${DEPS_LIBS}
libtpm2_la_SOURCES=e_tpm2.c e_tpm2-rsa.c e_tpm2-ecc.c tpm2-common.c
libtpm2_la_CFLAGS=${DEPS_CFLAGS} -g -Werror

create_tpm2_key_SOURCES=create_tpm2_key.c tpm2-common.c
create_tpm2_key_LDADD=${DEPS_LIBS}
create_tpm2_key_CFLAGS=${DEPS_CFLAGS} -Werror

load_tpm2_key_SOURCES=load_tpm2_key.c tpm2-common.c
load_tpm2_key_LDADD=${DEPS_LIBS}
load_tpm2_key_CFLAGS=${DEPS_CFLAGS} -Werror

seal_tpm2_data_SOURCES=seal_tpm2_data.c tpm2-common.c
seal_tpm2_data_LDADD=${DEPS_LIBS}
seal_tpm2_data_CFLAGS=${DEPS_CFLAGS} -Werror

unseal_tpm2_data_SOURCES=unseal_tpm2_data.c tpm2-common.c
unseal_tpm2_data_LDADD=${DEPS_LIBS}
unseal_tpm2_data_CFLAGS=${DEPS_CFLAGS} -Werror

signed_tpm2_policy_SOURCES=signed_tpm2_policy.c tpm2-common.c
signed_tpm2_policy_LDADD=${DEPS_LIBS}
signed_tpm2_policy_CFLAGS=${DEPS_CFLAGS} -g -Werror

$(builddir)/%.1: $(srcdir)/%.1.in $(top_builddir)/%
	$(HELP2MAN) --no-info -i $< -o $@ $(top_builddir)/$*

# openssl from 1.1.0 looks for engine.so not libengine.so
install-data-hook:
	cd $(DESTDIR)$(openssl_enginedir) && $(LN_S) -f libtpm2@SHREXT@ tpm2@SHREXT@

SUBDIRS = tests doc
