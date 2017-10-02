EXTRA_DIST = README openssl.cnf.sample create_tpm2_key.1

man1_MANS = create_tpm2_key.1

CLEANFILES = $(man1_MANS)

openssl_engine_LTLIBRARIES=libtpm2.la
bin_PROGRAMS=create_tpm2_key
openssl_enginedir=@enginesdir@

libtpm2_la_LDFLAGS= -no-undefined -avoid-version
libtpm2_la_LIBADD=-lcrypto -ltss
libtpm2_la_SOURCES=e_tpm2.c tpm2-common.c
libtpm2_la_CFLAGS=-g -Werror

create_tpm2_key_SOURCES=create_tpm2_key.c tpm2-common.c
create_tpm2_key_LDADD=-lcrypto -ltss
create_tpm2_key_CFLAGS=-Werror

$(builddir)/%.1: $(srcdir)/%.1.in $(top_builddir)/%
	$(HELP2MAN) --no-info -i $< -o $@ $(top_builddir)/$*
