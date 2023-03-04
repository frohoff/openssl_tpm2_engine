/* Copyright (C) 2023 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/e_os2.h>
#include "opensslmissing.h"

#include "provider.h"

char *srk_auth = NULL;

static OSSL_FUNC_core_get_params_fn *core_get_params;


/* only need the provider context, so pass through */
void *tpm2_passthrough_newctx(void *ctx)
{
	return ctx;
}

void tpm2_passthrough_freectx(void *ctx)
{
	/* we don't own the passed through context, so do nothing */
}

int tpm2_get_sizes(const struct app_data *ad, int *bits, int *security,
		   int *size)
{
	const TPMT_PUBLIC *pub = &ad->Public.publicArea;
	int b, sb, sz;

	switch (pub->type) {
	case TPM_ALG_RSA:
		b = pub->parameters.rsaDetail.keyBits;
		sz = b/8;
		sb = (b == 3072) ? 128 : 112;
		break;
	case TPM_ALG_ECC:
		b = tpm2_curve_to_order(pub->parameters.eccDetail.curveID)*8;
		sb = b/2;
		/* SEQUENCE ( BIGNUM, BIGNUM ) up to 32k */
		sz = (b/8 + 3)*2 + 3;
		break;
	default:
		return 0;
	}

	if (bits)
		*bits = b;
	if (security)
		*security = sb;
	if (size)
		*size = sz;

	return 1;
}

#define QOP(op, routine) \
	[op] = { routine, #op, }
static struct {
	const OSSL_ALGORITHM *alg;
	const char *desc;
} queries[] = {
	QOP(OSSL_OP_DECODER, decoders),
	QOP(OSSL_OP_ENCODER, encoders),
	QOP(OSSL_OP_KEYMGMT, keymgmts),
	QOP(OSSL_OP_SIGNATURE, signatures),
	QOP(OSSL_OP_STORE, NULL),
};

static const OSSL_ALGORITHM *p_query(void *provctx, int operation_id,
				     int *no_store)
{
	return queries[operation_id].alg;
}

static void p_teardown(void *ctx)
{
	OSSL_LIB_CTX *libctx = ctx;
	OSSL_LIB_CTX_free(libctx);
}

static const OSSL_DISPATCH prov_fns[] = {
	{ OSSL_FUNC_PROVIDER_TEARDOWN, (void (*)(void))p_teardown },
	{ OSSL_FUNC_PROVIDER_QUERY_OPERATION, (void (*)(void))p_query },
	{ 0, NULL }
};

OSSL_provider_init_fn OSSL_provider_init;
int OSSL_provider_init(const OSSL_CORE_HANDLE *handle,
		       const OSSL_DISPATCH *in,
		       const OSSL_DISPATCH **out,
		       void **provctx)
{
	OSSL_LIB_CTX *libctx;
	const OSSL_DISPATCH *fns = in;
	OSSL_PARAM provider_params[] = {
		OSSL_PARAM_utf8_ptr("PIN", &srk_auth, 0),
		OSSL_PARAM_END
	};


	*out = prov_fns;

	for (; fns->function_id != 0; fns++) {
		switch (fns->function_id) {
		case OSSL_FUNC_CORE_GET_PARAMS:
			core_get_params = OSSL_FUNC_core_get_params(fns);
			break;
		}
	}
	if (!core_get_params) {
		fprintf(stderr, "core didn't provide get_params\n");
		goto err;
	}

	if (!core_get_params(handle, provider_params)) {
		fprintf(stderr, "core failed to load params\n");
		goto err;
	}

	libctx = OSSL_LIB_CTX_new_from_dispatch(handle, in);
	if (libctx == NULL) {
		fprintf(stderr, "tpm2-provider: Allocation failure in init\n");
		goto err;
	}

	fprintf(stderr, "tpm2-provider initialized\n");
	*provctx = libctx;

	return 1;

 err:
	p_teardown(libctx);
	return 0;
}
