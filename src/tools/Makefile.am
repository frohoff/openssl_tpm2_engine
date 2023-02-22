if NATIVE_BUILD
EXTRA_DIST = create_tpm2_key.1 load_tpm2_key.1 seal_tpm2_data.1 \
	unseal_tpm2_data.1 signed_tpm2_policy.1
man1_MANS = create_tpm2_key.1 load_tpm2_key.1 seal_tpm2_data.1 \
	unseal_tpm2_data.1 signed_tpm2_policy.1

CLEANFILES = $(man1_MANS)
endif

AM_CPPFLAGS = -I ../include ${DEPRECATION}

bin_PROGRAMS=create_tpm2_key load_tpm2_key seal_tpm2_data unseal_tpm2_data \
	signed_tpm2_policy
COMMONLIB = ../libcommon/libcommon.a

create_tpm2_key_SOURCES=create_tpm2_key.c
create_tpm2_key_LDADD=${COMMONLIB} ${DEPS_LIBS}
create_tpm2_key_CFLAGS=${DEPS_CFLAGS}

load_tpm2_key_SOURCES=load_tpm2_key.c
load_tpm2_key_LDADD=${COMMONLIB} ${DEPS_LIBS}
load_tpm2_key_CFLAGS=${DEPS_CFLAGS}

seal_tpm2_data_SOURCES=seal_tpm2_data.c
seal_tpm2_data_LDADD=${COMMONLIB} ${DEPS_LIBS}
seal_tpm2_data_CFLAGS=${DEPS_CFLAGS}

unseal_tpm2_data_SOURCES=unseal_tpm2_data.c
unseal_tpm2_data_LDADD=${COMMONLIB} ${DEPS_LIBS}
unseal_tpm2_data_CFLAGS=${DEPS_CFLAGS}

signed_tpm2_policy_SOURCES=signed_tpm2_policy.c
signed_tpm2_policy_LDADD=${COMMONLIB} ${DEPS_LIBS}
signed_tpm2_policy_CFLAGS=${DEPS_CFLAGS}

$(builddir)/%.1: $(srcdir)/%.1.in $(builddir)/%
	$(HELP2MAN) --no-info -i $< -o $@ $(builddir)/$*
