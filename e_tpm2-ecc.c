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

static TPM_HANDLE tpm2_load_key_from_ecc(const EC_KEY *eck,
					 TSS_CONTEXT **tssContext, char **auth,
					 TPM_SE *sessionType,
					 struct app_data **app_data,
					 TPM_ALG_ID *nameAlg)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
	/*  const mess up in openssl 1.0.2 */
	*app_data = ECDSA_get_ex_data((EC_KEY *)eck, ec_app_data);
#else
	*app_data = EC_KEY_get_ex_data(eck, ec_app_data);
#endif

	if (!*app_data)
		return 0;

	*auth = (*app_data)->auth;
	*sessionType = (*app_data)->req_policy_session ?
		       TPM_SE_POLICY : TPM_SE_HMAC;
	*nameAlg = (*app_data)->name_alg;

	return tpm2_load_key(tssContext, *app_data, srk_auth, NULL);
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
	TPM_RC rc;
	TPM_HANDLE keyHandle;
	DIGEST_2B digest;
	TPMT_SIG_SCHEME inScheme;
	TPMT_SIGNATURE signature;
	TSS_CONTEXT *tssContext;
	char *auth;
	TPM_HANDLE authHandle;
	TPM_SE sessionType;
	ECDSA_SIG *sig;
	BIGNUM *r, *s;
	TPM_ALG_ID nameAlg;
	struct app_data *app_data;

	/* The TPM insists on knowing the digest type, so
	 * calculate that from the size */
	switch (dgst_len) {
	case SHA_DIGEST_LENGTH:
		inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA1;
		break;
	case SHA256_DIGEST_LENGTH:
		inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
		break;
	case SHA384_DIGEST_LENGTH:
		inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA384;
		break;
#ifdef TPM_ALG_SHA512
	case SHA512_DIGEST_LENGTH:
		inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA512;
		break;
#endif
	default:
		printf("ECDSA signature: Unknown digest length, cannot deduce hash type for TPM\n");
		return NULL;
	}

	keyHandle = tpm2_load_key_from_ecc(eck, &tssContext, &auth,
					   &sessionType, &app_data, &nameAlg);
	if (keyHandle == 0) {
		fprintf(stderr, "Failed to get Key Handle in TPM EC key routines\n");
		return NULL;
	}

	inScheme.scheme = TPM_ALG_ECDSA;
	digest.size = dgst_len;
	memcpy(digest.buffer, dgst, dgst_len);

	sig = NULL;
	rc = tpm2_get_session_handle(tssContext, &authHandle, 0, sessionType,
				     nameAlg);
	if (rc)
		goto out;

	if (sessionType == TPM_SE_POLICY) {
		rc = tpm2_init_session(tssContext, authHandle,
				       app_data, nameAlg);
		if (rc)
			goto out;
	}

	rc = tpm2_Sign(tssContext, keyHandle, &digest, &inScheme, &signature,
		       authHandle, auth);
	if (rc) {
		tpm2_error(rc, "TPM2_Sign");
		tpm2_flush_handle(tssContext, authHandle);
		goto out;
	}

	sig = ECDSA_SIG_new();
	if (!sig)
		goto out;

	r = BN_bin2bn(VAL_2B(signature.signature.ecdsa.signatureR, buffer),
		      VAL_2B(signature.signature.ecdsa.signatureR, size),
		      NULL);
	s = BN_bin2bn(VAL_2B(signature.signature.ecdsa.signatureS, buffer),
		      VAL_2B(signature.signature.ecdsa.signatureS, size),
		      NULL);

#if OPENSSL_VERSION_NUMBER < 0x10100000
	sig->r = r;
	sig->s = s;
#else
	ECDSA_SIG_set0(sig, r, s);
#endif
 out:
	tpm2_unload_key(tssContext, keyHandle);
	return sig;
}

static int tpm2_ecc_compute_key(unsigned char **psec, size_t *pseclen,
				const EC_POINT *pt, const EC_KEY *eck)
{
	TPM_RC rc;
	TPM_HANDLE keyHandle;
	TPM2B_ECC_POINT inPoint;
	TPM2B_ECC_POINT outPoint;
	TSS_CONTEXT *tssContext;
	TPM_HANDLE authHandle;
	TPM_SE sessionType;
	char *auth;
	size_t len;
	TPM_ALG_ID nameAlg;
	struct app_data *app_data;
	int ret;

	keyHandle = tpm2_load_key_from_ecc(eck, &tssContext, &auth,
					   &sessionType, &app_data, &nameAlg);
	if (keyHandle == 0) {
		fprintf(stderr, "Failed to get Key Handle in TPM EC key routines\n");
		return 0;
	}
	len = tpm2_get_public_point(&inPoint, EC_KEY_get0_group(eck), pt);
	if (!len)
		return 0;

	ret = 0;
	rc = tpm2_get_session_handle(tssContext, &authHandle, 0, sessionType,
				     nameAlg);
	if (rc)
		goto out;

	if (sessionType == TPM_SE_POLICY) {
		rc = tpm2_init_session(tssContext, authHandle,
				       app_data, nameAlg);
		if (rc)
			goto out;
	}

	rc = tpm2_ECDH_ZGen(tssContext, keyHandle, &inPoint, &outPoint,
			    authHandle, auth);
	if (rc) {
		tpm2_error(rc, "TPM2_ECDH_ZGen");
		tpm2_flush_handle(tssContext, authHandle);
		goto out;
	}

	*psec = OPENSSL_malloc(len);
	if (!*psec)
		goto out;
	*pseclen = len;
	memset(*psec, 0, len);

	/* zero pad the X point */
	memcpy(*psec + len - VAL_2B(outPoint.point.x, size),
	       VAL_2B(outPoint.point.x, buffer),
	       VAL_2B(outPoint.point.x, size));
	ret = 1;
 out:
	tpm2_unload_key(tssContext, keyHandle);
	return ret;
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
