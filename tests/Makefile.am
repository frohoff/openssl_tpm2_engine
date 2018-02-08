TESTS = fail_connect.sh \
	start_sw_tpm.sh \
	check_tpm_directory.sh \
	check_curves.sh \
	create_tpm_key.sh \
	check_auth.sh \
	wrap_tpm_key.sh \
	check_wrap_auth.sh \
	create_ecc.sh \
	wrap_ecc.sh \
	wrap_generic_ecc.sh \
	derive_ecc.sh \
	create_non_tpm_keys.sh \
	da_check.sh \
	test_nv_key.sh \
	stop_sw_tpm.sh

AM_TESTS_ENVIRONMENT = TPM_INTERFACE_TYPE=socsim; \
	srcdir=$(abs_srcdir); \
	OPENSSL_CONF=$(abs_srcdir)/openssl.cnf \
	export TPM_INTERFACE_TYPE OPENSSL_CONF srcdir;
TEST_EXTENSIONS = .sh

CLEANFILES = key*.tpm key*.pub key*.priv tmp.* NVChip h*.bin
clean-local:
	rm -fr testdir
