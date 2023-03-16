/* Copyright (C) 2023 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>

#include <openssl/store.h>

#include "provider.h"

char *nvprefix = "//nvkey";

struct tpm2_store_ctx {
	const char *uri;
	int eof;
	int expect;
};


static void *tpm2_store_open(void *provctx, const char *uri)
{
	const int nvprefix_size = strlen(nvprefix);
	struct tpm2_store_ctx *sctx;

	if (strncmp(nvprefix, uri, nvprefix_size) != 0)
		return NULL;

	sctx = OPENSSL_zalloc(sizeof(*sctx));
	if (!sctx)
		return NULL;

	sctx->uri = uri + nvprefix_size;
	if (sctx->uri[0] == ':')
		sctx->uri++;

	return sctx;
}

static int tpm2_store_load(void *ctx,
			   OSSL_CALLBACK *data_cb, void *data_cbarg,
			   OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
	struct tpm2_store_ctx *sctx = ctx;
	TPM_HANDLE key = strtoul(sctx->uri, NULL, 16);
	struct app_data *ad;
	TSS_CONTEXT *tssContext;
	TPM_RC rc;
	int ret = 0;
	int askauth = 0;
	OSSL_PARAM params[4];
	int type;
	char *keytype;

	sctx->eof = 1;
	if ((key >> 24) != TPM_HT_PERSISTENT) {
		fprintf(stderr, "nvkey doesn't have a persistent handle\n");
		return 0;
	}

	ad = tpm2_keymgmt_new(NULL);
	if (!ad)
		return 0;

	ad->dir = tpm2_set_unique_tssdir();

	rc = tpm2_create(&tssContext, ad->dir);
	if (rc)
		goto err;

	key = tpm2_handle_int(tssContext, key);
	rc = tpm2_readpublic(tssContext, key, &ad->Public.publicArea);
	if (rc)
		goto err_del;

	if ((sctx->expect == OSSL_STORE_INFO_PKEY)) {
		ad->key = tpm2_handle_ext(tssContext, key);

		if (VAL(ad->Public.publicArea.objectAttributes) & TPMA_OBJECT_NODA) {
			/* no DA implications, try an authorization
			 * and see if NULL is accepted */
			TPM_HANDLE session;

			rc = tpm2_get_bound_handle(tssContext, &session, key, NULL);
			if (rc == TPM_RC_SUCCESS) {
				rc = tpm2_ReadPublic(tssContext, key, NULL, session);
				if (rc)
					tpm2_flush_handle(tssContext, session);
		}
			if (rc != TPM_RC_SUCCESS)
				askauth = 1;
		} else {
			/* assume since we have DA implications, we have a password */
			askauth = 1;
		}

		if (askauth) {
			char pass[SHA512_DIGEST_LENGTH];
			size_t len;

			if (!pw_cb(pass, sizeof(pass), &len, NULL, pw_cbarg))
				goto err_del;
			ad->auth = OPENSSL_malloc(len + 1);
			if (!ad->auth)
				goto err_del;
			memcpy(ad->auth, pass, len);
			ad->auth[len] = '\0';
			OPENSSL_cleanse(pass, len);
		}
	} else {
		tpm2_rm_keyfile(ad->dir, tpm2_handle_ext(tssContext, key));
	}
	TSS_Delete(tssContext);

	type = OSSL_OBJECT_PKEY;
	keytype = ad->Public.publicArea.type == TPM_ALG_RSA ? "RSA" : "EC";
	params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE,
					     &type);
	params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
						     keytype, 0);
	params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
						      &ad, sizeof(ad));
	params[3] = OSSL_PARAM_construct_end();

        ret = data_cb(params, data_cbarg);
	if (!ret)
		goto err;

	return ret;

 err_del:
	TSS_Delete(tssContext);
 err:
	tpm2_delete(ad);
	return 0;
}

static int tpm2_store_eof(void *ctx)
{
	struct tpm2_store_ctx *sctx = ctx;

	return sctx->eof;
}

static int tpm2_store_close(void *ctx)
{
	OPENSSL_free(ctx);
	return 1;
}

static int tpm2_store_set_ctx_params(void *ctx, const OSSL_PARAM params[])
{
	const OSSL_PARAM *p = params;
	struct tpm2_store_ctx *sctx = ctx;

	p = OSSL_PARAM_locate_const(params, OSSL_STORE_PARAM_EXPECT);
	if (p != NULL) {
		if (p->data_type != OSSL_PARAM_INTEGER)
			return 0;
		OSSL_PARAM_get_int(p, &sctx->expect);
	}
	return 1;
}

const OSSL_DISPATCH store_fns[] = {
	{ OSSL_FUNC_STORE_OPEN, (void(*)(void))tpm2_store_open },
	{ OSSL_FUNC_STORE_LOAD, (void(*)(void))tpm2_store_load },
	{ OSSL_FUNC_STORE_EOF, (void(*)(void))tpm2_store_eof },
	{ OSSL_FUNC_STORE_CLOSE, (void(*)(void))tpm2_store_close },
	{ OSSL_FUNC_STORE_SET_CTX_PARAMS, (void(*)(void))tpm2_store_set_ctx_params },
	{ 0, NULL }
};

/*
 * OpenSSL weirdness: the algorithm_name has to be set to the scheme, but
 * the scheme can be modified by a config file parameter, so set it NULL here
 * and then set it after we collect the parameters in OSSL_provider_init()
 */
OSSL_ALGORITHM stores[] = {
	{ NULL, "provider=tpm2", store_fns },
	{ NULL, NULL, NULL }
};
