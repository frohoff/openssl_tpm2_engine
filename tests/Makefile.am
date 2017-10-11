TESTS = start_sw_tpm.sh \
	create_tpm_key.sh \
	check_auth.sh \
	wrap_tpm_key.sh \
	check_wrap_auth.sh \
	create_ecc.sh \
	stop_sw_tpm.sh

AM_TESTS_ENVIRONMENT = TPM_INTERFACE_TYPE=socsim; \
	OPENSSL_CONF=$(srcdir)/openssl.cnf \
	export TPM_INTERFACE_TYPE OPENSSL_CONF;
TEST_EXTENSIONS = .sh

CLEANFILES = key?.tpm key?.pub key?.priv tmp.* NVChip h*.bin
