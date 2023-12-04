/* Copyright (C) 2023 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/* note: we need a reference in struct app_dir which uses gcc atomics */
#include <stdatomic.h>

#include "provider.h"
#include "opensslmissing.h"

struct decryption_ctx {
	struct app_data *ad;
	struct app_data *peer_ad;
	struct osslm_dec_ctx dctx;
};

static void *tpm2_decryption_newctx(void *pctx)
{
	struct decryption_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));
	OSSL_LIB_CTX *libctx = pctx;

	if (!ctx)
		return NULL;

	ctx->dctx.libctx = libctx;

	return ctx;
}

static void tpm2_decryption_freectx(void *ctx)
{
	struct decryption_ctx *dctx = ctx;

	if (dctx->ad)
		tpm2_keymgmt_free(dctx->ad);
	if (dctx->peer_ad)
		tpm2_keymgmt_free(dctx->peer_ad);

	osslm_decryption_freectx(&dctx->dctx);
	OPENSSL_free(dctx);
}

static int tpm2_decryption_init(void *ctx, void *key, const OSSL_PARAM params[])
{
	struct decryption_ctx *dctx = ctx;

	dctx->ad = key;

	return 1;
}

static int tpm2_decryption(void *ctx, unsigned char *out, size_t *outlen,
			   size_t outsize, const unsigned char *in,
			   size_t inlen)
{
	struct decryption_ctx *dctx = ctx;
	PUBLIC_KEY_RSA_2B cipherText, outText;
	int padding = dctx->dctx.padding;
	int ret;
	unsigned char *result;

	if (out == NULL) {
		int size;

		if (!tpm2_get_sizes(dctx->ad, NULL, NULL, &size))
			return 0;

		*outlen = size;
		return 1;
	}

	cipherText.size = inlen;
	memcpy(cipherText.buffer, in, inlen);

	if (padding == 0)
		padding = RSA_PKCS1_PADDING;

	if (padding != RSA_PKCS1_PADDING) {
		padding = RSA_NO_PADDING;
		result = outText.buffer;
	} else {
		result = out;
	}

	ret = tpm2_rsa_decrypt(dctx->ad, &cipherText, result,
				   padding, TPMA_SESSION_ENCRYPT,
				   srk_auth);
	if (ret < 0)
		return 0;

	if (dctx->dctx.padding == RSA_PKCS1_OAEP_PADDING) {
		*outlen = outsize;
		osslm_rsa_unpad_oaep(&dctx->dctx, out, outlen, result, ret);
	} else {
		*outlen = ret;
	}

	return 1;
}

static int tpm2_decryption_set_params(void *ctx, const OSSL_PARAM params[])
{
	struct decryption_ctx *dctx = ctx;

	return osslm_decryption_set_params(&dctx->dctx, params);
}


static int
tpm2_keyexch_init(void *ctx, void *key, const OSSL_PARAM params[])
{
	struct decryption_ctx *dctx = ctx;

	dctx->ad = key;
	atomic_fetch_add_explicit(&dctx->ad->refs, 1,
				  memory_order_relaxed);

	return 1;
}

static int
tpm2_keyexch_set_peer(void *ctx, void *peerkey)
{
	struct decryption_ctx *dctx = ctx;

	dctx->peer_ad = peerkey;
	atomic_fetch_add_explicit(&dctx->peer_ad->refs, 1,
				  memory_order_relaxed);

	return 1;
}

static int
tpm2_keyexch_derive(void *ctx, unsigned char *secret, size_t *secretlen,
                    size_t outlen)
{
	struct decryption_ctx *dctx = ctx;
	TPM2B_ECC_POINT inPoint;

	inPoint.point = dctx->peer_ad->Public.publicArea.unique.ecc;
	*secretlen = VAL_2B(inPoint.point.x, size);
	if (!secret)
		return 1;

	return tpm2_ecdh_x(dctx->ad, &secret, secretlen, &inPoint, NULL);
}


/*
 * Two different names: RSA does asymmetric cipher (encrypts private key)
 * EC does key derivation called key exchange.
 */
static const OSSL_DISPATCH asymcipher_fns[] = {
	{ OSSL_FUNC_ASYM_CIPHER_NEWCTX, (void (*)(void))tpm2_decryption_newctx },
	{ OSSL_FUNC_ASYM_CIPHER_FREECTX, (void (*)(void))tpm2_decryption_freectx },
	{ OSSL_FUNC_ASYM_CIPHER_DECRYPT_INIT, (void (*)(void))tpm2_decryption_init },
	{ OSSL_FUNC_ASYM_CIPHER_DECRYPT, (void (*)(void))tpm2_decryption },
	{ OSSL_FUNC_ASYM_CIPHER_SET_CTX_PARAMS, (void (*)(void))tpm2_decryption_set_params, },
	{ OSSL_FUNC_ASYM_CIPHER_SETTABLE_CTX_PARAMS, (void (*)(void))osslm_decryption_settable_params },
	{ 0, NULL }
};

static const OSSL_DISPATCH keyexch_fns[] = {
	{ OSSL_FUNC_KEYEXCH_NEWCTX, (void(*)(void))tpm2_decryption_newctx },
	{ OSSL_FUNC_KEYEXCH_FREECTX, (void(*)(void))tpm2_decryption_freectx },
	{ OSSL_FUNC_KEYEXCH_INIT, (void(*)(void))tpm2_keyexch_init },
	{ OSSL_FUNC_KEYEXCH_SET_PEER, (void(*)(void))tpm2_keyexch_set_peer },
	{ OSSL_FUNC_KEYEXCH_DERIVE, (void(*)(void))tpm2_keyexch_derive },
	{ 0, NULL }
};

const OSSL_ALGORITHM asymciphers[] = {
	{ "RSA", "provider=tpm2", asymcipher_fns },
	{ NULL, NULL, NULL }
};

const OSSL_ALGORITHM keyexchs[] = {
	{ "EC", "provider=tpm2", keyexch_fns },
	{ NULL, NULL, NULL }
};
