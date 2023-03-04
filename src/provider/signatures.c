/* Copyright (C) 2023 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/* note: we need a reference in struct app_dir which uses gcc atomics */
#include <stdatomic.h>

#include "provider.h"
#include "opensslmissing.h"

struct signature_ctx {
	struct app_data *ad;
	struct osslm_sig_ctx sctx;
};

static void *tpm2_signature_newctx(void *pctx)
{
	struct signature_ctx *ctx = OPENSSL_zalloc(sizeof(*ctx));
	OSSL_LIB_CTX *libctx = pctx;

	if (!ctx)
		return NULL;

	ctx->sctx.libctx = libctx;

	return ctx;
}

static void *tpm2_signature_dupctx(void *ctx)
{
	struct signature_ctx *oldctx = ctx;
	struct signature_ctx *newctx = tpm2_signature_newctx(oldctx->sctx.libctx);

	if (!newctx)
		return NULL;

	if (!osslm_signature_dupctx(&oldctx->sctx, &newctx->sctx))
		return NULL;

	newctx->ad = oldctx->ad;
	if (newctx->ad)
		atomic_fetch_add_explicit(&newctx->ad->refs, 1,
					  memory_order_relaxed);
	return newctx;
}

static void tpm2_signature_freectx(void *ctx)
{
	struct signature_ctx *sctx = ctx;

	osslm_signature_freectx(&sctx->sctx);
	OPENSSL_free(sctx);
}

static int tpm2_signature_init(void *ctx, void *key, const OSSL_PARAM params[])
{
	struct signature_ctx *sctx = ctx;

	sctx->ad = key;

	return 1;
}

static int tpm2_signature_sign(void *ctx, unsigned char *sig, size_t *siglen,
			       size_t sigsize, const unsigned char *tbs,
			       size_t tbslen)
{
	struct signature_ctx *sctx = ctx;
	ECDSA_SIG *es;
	const TPMT_PUBLIC *pub = &sctx->ad->Public.publicArea;

	if (sig == NULL) {
		int size;

		if (!tpm2_get_sizes(sctx->ad, NULL, NULL, &size))
			return 0;
		*siglen = size;
		return 1;
	}

	if (pub->type == TPM_ALG_ECC) {
		es = tpm2_sign_ecc(sctx->ad, tbs, tbslen, srk_auth);
		if (!es)
			return 0;

		*siglen = i2d_ECDSA_SIG(es, &sig);
		ECDSA_SIG_free(es);
	} else {
		PUBLIC_KEY_RSA_2B cipherText;
		int size;

		if (!tpm2_get_sizes(sctx->ad, NULL, NULL, &size))
			return 0;

		if (!osslm_rsa_signature_pad(&sctx->sctx, cipherText.buffer,
					     size, tbs, tbslen))
			return 0;

		cipherText.size = size;

		size =  tpm2_rsa_decrypt(sctx->ad, &cipherText, sig,
					    RSA_NO_PADDING,
					    TPMA_SESSION_DECRYPT, srk_auth);
		if (size < 0)
			return 0;
		*siglen = size;
	}

	return 1;
}

/*
 * sigh, openssl should do this itself, because if the provider has no
 * digest functions, it shouldn't have to implement this as a generic
 * digest then sign
 */
static int tpm2_signature_digest_init(void *ctx, const char *mdname, void *key,
				      const OSSL_PARAM params[])
{
	struct signature_ctx *sctx = ctx;

	tpm2_signature_init(ctx, key, params);
	return osslm_signature_digest_init(&sctx->sctx, mdname, params);
}

static int tpm2_signature_digest_update(void *ctx, const unsigned char *data,
					size_t datalen)
{
	struct signature_ctx *sctx = ctx;

	return osslm_signature_digest_update(&sctx->sctx, data, datalen);
}

static int tpm2_signature_digest_final(void *ctx, unsigned char *sig,
				       size_t *siglen, size_t sigsize)
{
	struct signature_ctx *sctx = ctx;

	return osslm_signature_digest_final(&sctx->sctx, sig, siglen, sigsize,
					    sctx->ad->Public.publicArea.type
					    == TPM_ALG_RSA,
					    tpm2_signature_sign, ctx);
}

static int tpm2_signature_get_ctx_params(void *ctx, OSSL_PARAM params[])
{
	struct signature_ctx *sctx = ctx;
	int ecc = sctx->ad->Public.publicArea.type == TPM_ALG_ECC;

	return osslm_signature_get_params(&sctx->sctx, ecc, params);
}

static int tpm2_signature_set_ctx_params(void *ctx, OSSL_PARAM params[])
{
	struct signature_ctx *sctx = ctx;

	return osslm_signature_set_params(&sctx->sctx, params);
}

static const OSSL_DISPATCH signature_fns[] = {
	{ OSSL_FUNC_SIGNATURE_NEWCTX, (void (*)(void))tpm2_signature_newctx },
	{ OSSL_FUNC_SIGNATURE_FREECTX, (void (*)(void))tpm2_signature_freectx },
	{ OSSL_FUNC_SIGNATURE_DUPCTX, (void (*)(void))tpm2_signature_dupctx },
	{ OSSL_FUNC_SIGNATURE_SIGN_INIT, (void (*)(void))tpm2_signature_init },
	{ OSSL_FUNC_SIGNATURE_SIGN , (void (*)(void))tpm2_signature_sign },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_INIT, (void (*)(void))tpm2_signature_digest_init },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_UPDATE, (void (*)(void))tpm2_signature_digest_update },
	{ OSSL_FUNC_SIGNATURE_DIGEST_SIGN_FINAL, (void (*)(void))tpm2_signature_digest_final },
	{ OSSL_FUNC_SIGNATURE_GET_CTX_PARAMS,  (void (*)(void))tpm2_signature_get_ctx_params },
	{ OSSL_FUNC_SIGNATURE_GETTABLE_CTX_PARAMS,  (void (*)(void))osslm_signature_gettable_params },
	{ OSSL_FUNC_SIGNATURE_SET_CTX_PARAMS, (void (*)(void))tpm2_signature_set_ctx_params },
	{ OSSL_FUNC_SIGNATURE_SETTABLE_CTX_PARAMS,  (void (*)(void))osslm_signature_settable_params },
	{ 0, NULL }
};

const OSSL_ALGORITHM signatures[] = {
	{ "RSA", "provider=tpm2", signature_fns },
	{ "EC", "provider=tpm2", signature_fns },
	{ NULL, NULL, NULL }
};
