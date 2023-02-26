/*
 * Copyright (C) 2017 James.Bottomley@HansenPartnership.com
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#include "tpm2-tss.h"
#include "tpm2-common.h"
#include "e_tpm2.h"

#if OPENSSL_VERSION_NUMBER < 0x10100000
static int tpm2_ecdh_compute_key(void *out, size_t len, const EC_POINT *pub_key,
				 EC_KEY *ecdh,
				 void *(*KDF) (const void *in, size_t inlen,
					       void *out, size_t *outlen));
/* !!!FIXME!!!
 *
 * openssl 1.0.2 is crap for ecc: The ECDH_METHOD structure is opaque,
 * but provides no way of overriding entries. Hack around this here by
 * embedding a copy of the structure straight out of ech_locl.h so we
 * can provide our own methods.
 */
struct ecdh_method {
    const char *name;
    int (*compute_key) (void *key, size_t outlen, const EC_POINT *pub_key,
                        EC_KEY *ecdh, void *(*KDF) (const void *in,
                                                    size_t inlen, void *out,
                                                    size_t *outlen));
# if 0
    int (*init) (EC_KEY *eckey);
    int (*finish) (EC_KEY *eckey);
# endif
    int flags;
    char *app_data;
};
static ECDSA_METHOD *tpm2_ecdsa = NULL;
static ECDH_METHOD tpm2_ecdh = {
	.name = "tpm2 ecc",
	.compute_key = tpm2_ecdh_compute_key,
};
#else
static EC_KEY_METHOD *tpm2_eck = NULL;
#endif

/* varibles used to get/set CRYPTO_EX_DATA values */
static int ec_app_data = TPM2_ENGINE_EX_DATA_UNINIT;
static int active_keys = 0;

static struct app_data *tpm2_ad_from_key(const EC_KEY *eck)
{
	struct app_data *app_data;

#if OPENSSL_VERSION_NUMBER < 0x10100000
	/*  const mess up in openssl 1.0.2 */
	app_data = ECDSA_get_ex_data((EC_KEY *)eck, ec_app_data);
#else
	app_data = EC_KEY_get_ex_data(eck, ec_app_data);
#endif

	return app_data;
}

void tpm2_bind_key_to_engine_ecc(ENGINE *e, EVP_PKEY *pkey, struct app_data *data)
{
	EC_KEY *eck = EVP_PKEY_get1_EC_KEY(pkey);

#if OPENSSL_VERSION_NUMBER < 0x10100000
	if (!ECDSA_set_ex_data(eck, ec_app_data, data))
#else
	if (!EC_KEY_set_ex_data(eck, ec_app_data, data))
#endif
		fprintf(stderr, "Failed to bind key to engine (ecc ex_data)\n");
	else {
#if OPENSSL_VERSION_NUMBER < 0x10100000
		ECDSA_set_method(eck, tpm2_ecdsa);
		ECDH_set_method(eck, &tpm2_ecdh);
#else
		EC_KEY_set_method(eck, tpm2_eck);
#endif
	}

	data->e = e;
	ENGINE_init(e);
	active_keys++;
#if OPENSSL_VERSION_NUMBER >= 0x30000000
	EVP_PKEY_set1_EC_KEY(pkey, eck);
#else
	EC_KEY_free(eck);
#endif
}

static void tpm2_ecc_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
			  int idx, long argl, void *argp)
{
	struct app_data *data = ptr;

	if (!data)
		return;

	--active_keys;
	ENGINE_finish(data->e);
	tpm2_delete(data);
}

static ECDSA_SIG *tpm2_ecdsa_sign(const unsigned char *dgst, int dgst_len,
				  const BIGNUM *kinv, const BIGNUM *rp,
				  EC_KEY *eck)
{
	struct app_data *app_data = tpm2_ad_from_key(eck);

	return tpm2_sign_ecc(app_data, dgst, dgst_len, srk_auth);
}

static int tpm2_ecc_compute_key(unsigned char **psec, size_t *pseclen,
				const EC_POINT *pt, const EC_KEY *eck)
{
	TPM2B_ECC_POINT inPoint;
	struct app_data *app_data;

	app_data = tpm2_ad_from_key(eck);
	if (!app_data)
		return 0;

	*pseclen = tpm2_get_public_point(&inPoint, EC_KEY_get0_group(eck), pt);
	if (!*pseclen)
		return 0;

	return tpm2_ecdh_x(app_data, psec, pseclen, &inPoint, srk_auth);
}

#if OPENSSL_VERSION_NUMBER < 0x10100000
static int tpm2_ecdh_compute_key(void *out, size_t len, const EC_POINT *pt,
				 EC_KEY *ecdh,
				 void *(*KDF) (const void *in, size_t inlen,
					       void *out, size_t *outlen))
{
	unsigned char *psec;
	size_t pseclen;

	if (!tpm2_ecc_compute_key(&psec, &pseclen, pt, ecdh))
		return -1;
	if (KDF) {
		KDF(psec, pseclen, out, &len);
	} else {
		if (len > pseclen)
			len = pseclen;
		memcpy(out, psec, len);
	}
	OPENSSL_free(psec);
	return len;
}
#endif

int tpm2_setup_ecc_methods(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
	tpm2_ecdsa = ECDSA_METHOD_new(NULL);

	if (!tpm2_ecdsa)
		goto err;

	ECDSA_METHOD_set_name(tpm2_ecdsa, "tpm2 ecc");
	ECDSA_METHOD_set_sign(tpm2_ecdsa, tpm2_ecdsa_sign);

	ec_app_data = ECDSA_get_ex_new_index(0, NULL, NULL, NULL, tpm2_ecc_free);

	if (ec_app_data < 0)
		goto err;
#else
	int (*psign)(int type, const unsigned char *dgst,
		     int dlen, unsigned char *sig,
		     unsigned int *siglen,
		     const BIGNUM *kinv, const BIGNUM *r,
		     EC_KEY *eckey);

	tpm2_eck = EC_KEY_METHOD_new(EC_KEY_OpenSSL());

	if (!tpm2_eck)
		goto err;

	EC_KEY_METHOD_get_sign(tpm2_eck, &psign, NULL, NULL);
	EC_KEY_METHOD_set_sign(tpm2_eck, psign, NULL, tpm2_ecdsa_sign);
	EC_KEY_METHOD_set_compute_key(tpm2_eck, tpm2_ecc_compute_key);

	ec_app_data = EC_KEY_get_ex_new_index(0, NULL, NULL, NULL, tpm2_ecc_free);

	if (ec_app_data < 0)
		goto err;
#endif

	return 1;

err:
	tpm2_teardown_ecc_methods();

	return 0;
}

void tpm2_teardown_ecc_methods(void)
{
	if (active_keys != 0) {
		fprintf(stderr, "ERROR: engine torn down while keys active\n");
		exit(1);
	}
#if OPENSSL_VERSION_NUMBER < 0x10100000
	if (tpm2_ecdsa) {
		ECDSA_METHOD_free(tpm2_ecdsa);
		tpm2_ecdsa = NULL;
	}

	if (ec_app_data >= 0) {
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_ECDSA, ec_app_data);
		ec_app_data = TPM2_ENGINE_EX_DATA_UNINIT;
	}
#else
	if (tpm2_eck) {
		EC_KEY_METHOD_free(tpm2_eck);
		tpm2_eck = NULL;
	}

	if (ec_app_data >= 0) {
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_EC_KEY, ec_app_data);
		ec_app_data = TPM2_ENGINE_EX_DATA_UNINIT;
	}
#endif
}
