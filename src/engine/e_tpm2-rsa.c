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
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "tpm2-tss.h"
#include "tpm2-common.h"
#include "e_tpm2.h"


/* varibles used to get/set CRYPTO_EX_DATA values */
static int ex_app_data = TPM2_ENGINE_EX_DATA_UNINIT;

RSA_METHOD *tpm2_rsa = NULL;
static int active_keys = 0;

#if OPENSSL_VERSION_NUMBER < 0x10100000
/* rsa functions */
static int tpm2_rsa_init(RSA *rsa);
static int tpm2_rsa_pub_dec(int, const unsigned char *, unsigned char *, RSA *, int);
static int tpm2_rsa_pub_enc(int, const unsigned char *, unsigned char *, RSA *, int);
static int tpm2_rsa_priv_dec(int, const unsigned char *, unsigned char *, RSA *, int);
static int tpm2_rsa_priv_enc(int, const unsigned char *, unsigned char *, RSA *, int);
//static int tpm2_rsa_sign(int, const unsigned char *, unsigned int, unsigned char *, unsigned int *, const RSA *);

static RSA_METHOD tpm2_rsa_meths = {
	"TPM2 RSA method",
	tpm2_rsa_pub_enc,
	tpm2_rsa_pub_dec,
	tpm2_rsa_priv_enc,
	tpm2_rsa_priv_dec,
	NULL, /* set in tpm2_engine_init */
	BN_mod_exp_mont,
	tpm2_rsa_init,
	NULL,
	(RSA_FLAG_SIGN_VER | RSA_FLAG_NO_BLINDING),
	NULL,
	NULL, /* sign */
	NULL, /* verify */
	NULL, /* keygen */
};

static int tpm2_rsa_init(RSA *rsa)
{
	return 1;
}

static int tpm2_rsa_pub_dec(int flen,
			   const unsigned char *from,
			   unsigned char *to,
			   RSA *rsa,
			   int padding)
{
	int rv;

	rv = RSA_PKCS1_SSLeay()->rsa_pub_dec(flen, from, to, rsa,
					     padding);
	if (rv < 0) {
		fprintf(stderr, "rsa_pub_dec failed\n");
		return 0;
	}

	return rv;
}

static int tpm2_rsa_pub_enc(int flen,
			   const unsigned char *from,
			   unsigned char *to,
			   RSA *rsa,
			   int padding)
{
	int rv;

	rv = RSA_PKCS1_SSLeay()->rsa_pub_enc(flen, from, to, rsa,
					     padding);
	if (rv < 0)
		fprintf(stderr, "rsa_pub_enc failed\n");

	return rv;
}

#endif

void tpm2_bind_key_to_engine_rsa(ENGINE *e, EVP_PKEY *pkey, struct app_data *data)
{
	RSA *rsa = EVP_PKEY_get1_RSA(pkey);

#if OPENSSL_VERSION_NUMBER < 0x10100000
	rsa->meth = tpm2_rsa;
	/* call our local init function here */
	rsa->meth->init(rsa);
#else
	RSA_set_method(rsa, tpm2_rsa);
#endif
	data->e = e;
	ENGINE_init(e);

	RSA_set_ex_data(rsa, ex_app_data, data);
	active_keys++;

#if OPENSSL_VERSION_NUMBER >= 0x30000000
	EVP_PKEY_set1_RSA(pkey, rsa);
#else
	/* release the reference EVP_PKEY_get1_RSA obtained */
	RSA_free(rsa);
#endif
}

static void tpm2_rsa_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
			  int idx, long argl, void *argp)
{
	struct app_data *app_data = ptr;

	if (!app_data)
		return;

	--active_keys;
	ENGINE_finish(app_data->e);

	tpm2_delete(app_data);
}

static int tpm2_rsa_priv_dec(int flen,
			    const unsigned char *from,
			    unsigned char *to,
			    RSA *rsa,
			    int padding)
{
	const struct app_data *ad = RSA_get_ex_data(rsa, ex_app_data);
	PUBLIC_KEY_RSA_2B cipherText;

	cipherText.size = flen;
	memcpy(cipherText.buffer, from, flen);

	return tpm2_rsa_decrypt(ad, &cipherText, to, padding,
				TPMA_SESSION_ENCRYPT, srk_auth);
}

static int tpm2_rsa_priv_enc(int flen,
			    const unsigned char *from,
			    unsigned char *to,
			    RSA *rsa,
			    int padding)
{
	const struct app_data *ad = RSA_get_ex_data(rsa, ex_app_data);
	PUBLIC_KEY_RSA_2B cipherText;
	const int size = RSA_size(rsa);

	cipherText.size = size;

	/* note: currently openssl doesn't do OAEP signatures and all
	 * PSS signatures are padded and handled in the RSA layer
	 * as a no-padding private encryption */
	if (padding == RSA_PKCS1_PADDING) {
		RSA_padding_add_PKCS1_type_1(cipherText.buffer, size,
					     from, flen);
	} else if (padding == RSA_NO_PADDING) {
		/* do nothing, we're already doing a no padding encrypt */
		memcpy(cipherText.buffer, from, size);
	} else {
		fprintf(stderr, "Can't process padding type: %d\n", padding);
		return -1;
	}

	/* this is slightly paradoxical that we're doing a Decrypt
	 * operation: the only material difference between decrypt and
	 * encrypt is where the padding is applied or checked, so if
	 * you apply your own padding up to the RSA block size and use
	 * TPM_ALG_NULL (RSA_NO_PADDING), which means no padding
	 * check, a decrypt operation effectively becomes an
	 * encrypt */
	return tpm2_rsa_decrypt(ad, &cipherText, to, RSA_NO_PADDING,
				TPMA_SESSION_DECRYPT, srk_auth);
}

int tpm2_setup_rsa_methods(void)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
	tpm2_rsa = &tpm2_rsa_meths;
#else
	tpm2_rsa = RSA_meth_dup(RSA_PKCS1_OpenSSL());

	if (!tpm2_rsa)
		goto err;

	RSA_meth_set1_name(tpm2_rsa, "tpm2 rsa");
	RSA_meth_set_priv_enc(tpm2_rsa, tpm2_rsa_priv_enc);
	RSA_meth_set_priv_dec(tpm2_rsa, tpm2_rsa_priv_dec);
#endif

	ex_app_data = RSA_get_ex_new_index(0, NULL, NULL, NULL, tpm2_rsa_free);

	if (ex_app_data < 0)
		goto err;

	return 1;

err:
	tpm2_teardown_rsa_methods();

	return 0;
}

void tpm2_teardown_rsa_methods(void)
{
	if (active_keys != 0) {
		fprintf(stderr, "ERROR: engine torn down while keys active\n");
		exit(1);
	}
#if OPENSSL_VERSION_NUMBER >= 0x10100000
	if (tpm2_rsa) {
		RSA_meth_free(tpm2_rsa);
		tpm2_rsa = NULL;
	}
#endif

	if (ex_app_data >= 0) {
		CRYPTO_free_ex_index(CRYPTO_EX_INDEX_RSA, ex_app_data);
		ex_app_data = TPM2_ENGINE_EX_DATA_UNINIT;
	}
}
