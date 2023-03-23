/* Copyright (C) 2023 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */
#include "provider.h"

static int tpm2_pem_decode(void *ctx, OSSL_CORE_BIO *cin, int selection,
			   OSSL_CALLBACK *data_cb, void *data_cbarg,
			   OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
	int ret = 1; /* carry on decoding, even if we can't decode this */
	OSSL_LIB_CTX *libctx = ctx;
	BIO *in = BIO_new_from_core_bio(libctx, cin);
	unsigned char *der_data;
	long der_len;
	char *pem_name, *pem_header;
	OSSL_PARAM params[3];

	if (!in)
		/* stop decoding */
		return 0;

	if (PEM_read_bio(in, &pem_name, &pem_header, &der_data, &der_len) <= 0)
		goto out;

	if (strcmp(pem_name, TSSPRIVKEY_PEM_STRING) != 0 &&
	    strcmp(pem_name, TSSLOADABLE_PEM_STRING) != 0)
		goto out;

	params[0] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_DATA,
						      der_data, der_len);
	params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_STRUCTURE,
                                                     "TPM2", 0);
	params[2] = OSSL_PARAM_construct_end();
	ret = data_cb(params, data_cbarg);

 out:
	OPENSSL_free(pem_name);
	OPENSSL_free(pem_header);
	OPENSSL_free(der_data);
	BIO_free(in);

	return ret;
}

static int tpm2_pkey_decode(void *ctx, OSSL_CORE_BIO *cin, int selection,
			    OSSL_CALLBACK *data_cb, void *data_cbarg,
			    OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg,
			    TPM_ALG_ID alg)
{
	struct app_data *ad = tpm2_keymgmt_new(ctx);
	OSSL_LIB_CTX *libctx = ctx;

	BIO *in = BIO_new_from_core_bio(libctx, cin);
	int ret = 0;
	OSSL_PARAM params[4];
	int type;
	char *keytype;

	if (!ad || !in) {
		BIO_free(in);
		OPENSSL_free(ad);
		return 0;
	}

	ret = tpm2_load_bf(in, ad, NULL);
	BIO_free(in);
	if (!ret)
		goto out_free;

	ret = 1;
	if (ad->Public.publicArea.type != alg)
		goto out_free;

	if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
		if (!ad->empty_auth) {
			char pass[SHA512_DIGEST_LENGTH];
			size_t len;

			if (!pw_cb(pass, sizeof(pass), &len, NULL, pw_cbarg))
				goto out_free;
			ad->auth = OPENSSL_malloc(len + 1);
			if (!ad->auth)
				goto out_free;
			memcpy(ad->auth, pass, len);
			ad->auth[len] = '\0';
			OPENSSL_cleanse(pass, len);
		}
	} else {
		OPENSSL_free(ad->priv);
		ad->priv = NULL;
	}

	type = OSSL_OBJECT_PKEY;
	keytype = alg == TPM_ALG_RSA ? "RSA" : "EC";
	params[0] = OSSL_PARAM_construct_int(OSSL_OBJECT_PARAM_TYPE,
					     &type);
	params[1] = OSSL_PARAM_construct_utf8_string(OSSL_OBJECT_PARAM_DATA_TYPE,
						     keytype, 0);
	params[2] = OSSL_PARAM_construct_octet_string(OSSL_OBJECT_PARAM_REFERENCE,
						      &ad, sizeof(ad));
	params[3] = OSSL_PARAM_construct_end();
	if (alg == TPM_ALG_ECC) {
		/*
		 * NASTY HACK for provider recursion problem.  If the
		 * provider depends on openssl, like this one does
		 * (tss uses it) then you always get a problem with
		 * the key management methods for this provider being
		 * found first in the cache because the order of
		 * searching is cache first then providers by order.
		 * The specific problem is that the lower tss routines
		 * need to use EC derivation to create the
		 * encryption/HMAC salt, but they can't use this
		 * provider to do it (otherwise they'd recurse
		 * forvever), so you need to populate the cache with
		 * the default implementation of EC keys so they are
		 * found before this provider's ones.
		 */
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
		EVP_PKEY_CTX_free(ctx);
	}

        ret = data_cb(params, data_cbarg);
	if (ret)
		/* here the key must not be freed.  It is freed
		 * instead by keymgmt_free once all references are
		 * dropped */
		return ret;

 out_free:
	tpm2_delete(ad);
	return ret;
}

static int tpm2_rsa_decode(void *ctx, OSSL_CORE_BIO *cin, int selection,
			   OSSL_CALLBACK *data_cb, void *data_cbarg,
			   OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
	return tpm2_pkey_decode(ctx, cin, selection, data_cb, data_cbarg,
				pw_cb, pw_cbarg, TPM_ALG_RSA);
}

static int tpm2_ec_decode(void *ctx, OSSL_CORE_BIO *cin, int selection,
			  OSSL_CALLBACK *data_cb, void *data_cbarg,
			  OSSL_PASSPHRASE_CALLBACK *pw_cb, void *pw_cbarg)
{
	return tpm2_pkey_decode(ctx, cin, selection, data_cb, data_cbarg,
				pw_cb, pw_cbarg, TPM_ALG_ECC);
}

static int
tpm2_encode_text(void *ctx, OSSL_CORE_BIO *cout, const void *key,
		 const OSSL_PARAM key_abstract[], int selection,
		 OSSL_PASSPHRASE_CALLBACK *cb, void *cbarg)
{
	OSSL_LIB_CTX *libctx = ctx;
	BIO *out = BIO_new_from_core_bio(libctx, cout);
	const struct app_data *ad = key;

	if (!out)
		return 0;

	BIO_printf(out, "TPM %s key, parent=%08x\n",
		   ad->Public.publicArea.type == TPM_ALG_RSA ? "RSA" : "EC",
		   ad->parent);

	BIO_free(out);

	return 1;
}

static const OSSL_DISPATCH encode_text_fns[] = {
	{ OSSL_FUNC_ENCODER_NEWCTX, (void (*)(void))tpm2_passthrough_newctx },
	{ OSSL_FUNC_ENCODER_FREECTX, (void (*)(void))tpm2_passthrough_freectx },
	{ OSSL_FUNC_ENCODER_ENCODE, (void (*)(void))tpm2_encode_text },
	{ 0, NULL }
};

static const OSSL_DISPATCH decode_pem_fns[] = {
	{ OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))tpm2_passthrough_newctx },
	{ OSSL_FUNC_DECODER_FREECTX, (void (*)(void))tpm2_passthrough_freectx },
	{ OSSL_FUNC_DECODER_DECODE, (void (*)(void))tpm2_pem_decode },
	{ 0, NULL }
};

static const OSSL_DISPATCH decode_rsa_fns[] = {
	{ OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))tpm2_passthrough_newctx },
	{ OSSL_FUNC_DECODER_FREECTX, (void (*)(void))tpm2_passthrough_freectx },
	{ OSSL_FUNC_DECODER_DECODE, (void (*)(void))tpm2_rsa_decode },
	{ 0, NULL }
};

static const OSSL_DISPATCH decode_ec_fns[] = {
	{ OSSL_FUNC_DECODER_NEWCTX, (void (*)(void))tpm2_passthrough_newctx },
	{ OSSL_FUNC_DECODER_FREECTX, (void (*)(void))tpm2_passthrough_freectx },
	{ OSSL_FUNC_DECODER_DECODE, (void (*)(void))tpm2_ec_decode },
	{ 0, NULL }
};

/* only provide pretty print encoders.  All other key saves
 * are done by keymgmt export (which means only public keys) */
const OSSL_ALGORITHM encoders[] = {
	{ "RSA", "provider=tpm2,output=text", encode_text_fns },
	{ "EC", "provider=tpm2,output=text", encode_text_fns },
	{ NULL, NULL, NULL }
};

const OSSL_ALGORITHM decoders[] = {
	{ "DER", "provider=tpm2,input=pem", decode_pem_fns },
	{ "RSA", "provider=tpm2,input=der,structure=TPM2", decode_rsa_fns },
	{ "EC", "provider=tpm2,input=der,structure=TPM2", decode_ec_fns },
	{ NULL, NULL, NULL }
};
