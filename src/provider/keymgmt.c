/* Copyright (C) 2023 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/* note: we need a reference in struct app_dir which uses gcc atomics */
#include <stdatomic.h>

#include "provider.h"
#include "opensslmissing.h"

static void *tpm2_keymgmt_load(void *ref, size_t ref_size)
{
	struct app_data *ad;
	void **actual_ref = ref;

	ad = *actual_ref;
	*actual_ref = NULL;

	atomic_fetch_add_explicit(&ad->refs, 1, memory_order_relaxed);

	return ad;
}

static void tpm2_keymgmt_free(void *ref)
{
	struct app_data *ad = ref;
	int refcnt = atomic_fetch_sub_explicit(&ad->refs, 1,
					       memory_order_relaxed);
	if (refcnt == 1)
		tpm2_delete(ad);
	if (refcnt < 1)
		fprintf(stderr, "keymgmt free wrong reference %d\n", refcnt);
}

/* another one of openssls never used functions that has to be provided */
static const OSSL_PARAM *tpm2_keymgmt_gettable_params(void *ctx)
{
	static const OSSL_PARAM params[] = {
		OSSL_PARAM_int(OSSL_PKEY_PARAM_BITS, NULL),
		OSSL_PARAM_int(OSSL_PKEY_PARAM_SECURITY_BITS, NULL),
		OSSL_PARAM_int(OSSL_PKEY_PARAM_MAX_SIZE, NULL),
		OSSL_PARAM_END
	};

	return params;
}

static int tpm2_keymgmt_get_params(void *ref, OSSL_PARAM params[])
{
	struct app_data *ad = ref;
	int maxsize, bits, securitybits;
	OSSL_PARAM *p;

	if (!tpm2_get_sizes(ad, &bits, &securitybits, &maxsize))
		return 0;

	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_BITS);
	if (p != NULL && !OSSL_PARAM_set_int(p, bits))
		return 0;
	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_SECURITY_BITS);
	if (p != NULL && !OSSL_PARAM_set_int(p, securitybits))
		return 0;
	p = OSSL_PARAM_locate(params, OSSL_PKEY_PARAM_MAX_SIZE);
	if (p != NULL && !OSSL_PARAM_set_int(p, maxsize))
		return 0;
	return 1;
}


static int tpm2_keymgmt_has(const void *ref, int selection)
{
	const struct app_data *ad = ref;

	if (selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY)
		return 1;
	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY)
		return ad->priv != NULL;
	return 0;
}

static int tpm2_keymgmt_export(void *ref, int selection,
			       OSSL_CALLBACK *param_cb, void *cbarg)
{
	OSSL_PARAM params[3], *p = params;
	struct app_data *ad = ref;
	TPMT_PUBLIC *pub = &ad->Public.publicArea;
	unsigned long exp = 0x10001;
	int nid, ret;
	size_t len;
	unsigned char point[MAX_ECC_KEY_BYTES*2 + 1], *pt = point;
	unsigned char *n = NULL;

	if ((selection & OSSL_KEYMGMT_SELECT_PUBLIC_KEY) == 0)
		goto out;
	if ((selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY))
		return 0;

	switch (pub->type) {
	case TPM_ALG_RSA:
		if (!bn_b2h_alloc(&n, VAL_2B(pub->unique.rsa, buffer),
				  VAL_2B(pub->unique.rsa, size)))
			return 0;

		*p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_N, n,
					       VAL_2B(pub->unique.rsa, size));
		*p++ = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_RSA_E,
					       (unsigned char *)&exp,
					       sizeof(exp));
		break;
	case TPM_ALG_ECC:
		nid = tpm2_curve_name_to_nid(pub->parameters.eccDetail.curveID);
		len =  VAL_2B(pub->unique.ecc.x, size) +
			VAL_2B(pub->unique.ecc.y, size) + 1;
		*pt++ = POINT_CONVERSION_UNCOMPRESSED;
		memcpy(pt, VAL_2B(pub->unique.ecc.x, buffer),
		       VAL_2B(pub->unique.ecc.x, size));
		pt += VAL_2B(pub->unique.ecc.x, size);
		memcpy(pt, VAL_2B(pub->unique.ecc.y, buffer),
		       VAL_2B(pub->unique.ecc.y, size));
		*p++ = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
							(char *)OBJ_nid2sn(nid), 0);
		*p++ = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
							 point, len);
		break;
	}
 out:
	*p = OSSL_PARAM_construct_end();

	ret = param_cb(params, cbarg);
	bn_b2h_free(n);
	return ret;
}

/* this function must be provided but is never used */
static const OSSL_PARAM *tpm2_keymgmt_export_types(int selection)
{
	return NULL;
}

static const OSSL_DISPATCH keymgmt_fns[] = {
	{ OSSL_FUNC_KEYMGMT_LOAD, (void (*)(void))tpm2_keymgmt_load },
	{ OSSL_FUNC_KEYMGMT_FREE, (void (*)(void))tpm2_keymgmt_free },
	{ OSSL_FUNC_KEYMGMT_HAS, (void (*)(void))tpm2_keymgmt_has },
	{ OSSL_FUNC_KEYMGMT_GET_PARAMS, (void (*)(void))tpm2_keymgmt_get_params },
	{ OSSL_FUNC_KEYMGMT_GETTABLE_PARAMS, (void (*)(void))tpm2_keymgmt_gettable_params },
	/* both MUST be provided (enforced) although no-one knows why
	 * since openssl never uses export_types */
	{ OSSL_FUNC_KEYMGMT_EXPORT, (void (*)(void))tpm2_keymgmt_export },
	{ OSSL_FUNC_KEYMGMT_EXPORT_TYPES, (void (*)(void))tpm2_keymgmt_export_types },
	{ 0, NULL}
};

const OSSL_ALGORITHM keymgmts[]= {
	{ "RSA", "provider=tpm2", keymgmt_fns },
	{ "EC", "provider=tpm2", keymgmt_fns },
	{ NULL, NULL, NULL}
};
