/*
 * Copyright (C) 2017 James.Bottomley@HansenPartnership.com
 *
 * GPLv2
 *
 */

#include <stdio.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bn.h>

#include <tss2/tss.h>
#include <tss2/tssutils.h>
#include <tss2/tssmarshal.h>
#include <tss2/tssresponsecode.h>
#include <tss2/Unmarshal_fp.h>

#include "tpm2-common.h"
#include "e_tpm2.h"

static const char *ecc_method_names = "tpm2 ecc";
static ECDSA_METHOD *tpm2_ecdsa;

/* varibles used to get/set CRYPTO_EX_DATA values */
static int ec_app_data = TPM2_ENGINE_EX_DATA_UNINIT;

static TPM_HANDLE tpm2_load_key_from_ecc(EC_KEY *eck, TSS_CONTEXT **tssContext, char **auth)
{
	struct app_data *app_data = ECDSA_get_ex_data(eck, ec_app_data);

	if (!app_data)
		return 0;

	*auth = app_data->auth;
	*tssContext = app_data->tssContext;

	return app_data->key;
}

void tpm2_bind_key_to_engine_ecc(EVP_PKEY *pkey, void *data)
{
	EC_KEY *eck = EVP_PKEY_get1_EC_KEY(pkey);

	if (!ECDSA_set_ex_data(eck, ec_app_data, data))
		fprintf(stderr, "Failed to bind key to engine (ecc ex_data)\n");
	else
		ECDSA_set_method(eck, tpm2_ecdsa);

	EC_KEY_free(eck);
}

static void tpm2_ecdsa_free(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
			   int idx, long argl, void *argp)
{
	struct app_data *data = ptr;

	if (!data)
		return;

	tpm2_flush_handle(data->tssContext, data->key);
	if (data->parent == 0)
		tpm2_flush_srk(data->tssContext);

	TSS_Delete(data->tssContext);

	OPENSSL_free(data);
}

static ECDSA_SIG *tpm2_ecdsa_sign(const unsigned char *dgst, int dgst_len,
				  const BIGNUM *kinv, const BIGNUM *rp,
				  EC_KEY *eck)
{
	TPM_RC rc;
	Sign_In in;
	Sign_Out out;
	TSS_CONTEXT *tssContext;
	char *auth;
	TPM_HANDLE authHandle;
	ECDSA_SIG *sig;

	/* The TPM insists on knowing the digest type, so
	 * calculate that from the size */
	switch (dgst_len) {
	case SHA_DIGEST_LENGTH:
		in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA1;
		break;
	case SHA256_DIGEST_LENGTH:
		in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA256;
		break;
	case SHA384_DIGEST_LENGTH:
		in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA384;
		break;
#ifdef TPM_ALG_SHA512
	case SHA512_DIGEST_LENGTH:
		in.inScheme.details.ecdsa.hashAlg = TPM_ALG_SHA512;
		break;
#endif
	default:
		printf("ECDSA signature: Unknown digest length, cannot deduce hash type for TPM\n");
		return NULL;
	}

	in.keyHandle = tpm2_load_key_from_ecc(eck, &tssContext, &auth);
	if (in.keyHandle == 0) {
		fprintf(stderr, "Failed to get Key Handle in TPM EC key routines\n");
		return NULL;
	}

	in.inScheme.scheme = TPM_ALG_ECDSA;
	in.digest.t.size = dgst_len;
	memcpy(in.digest.t.buffer, dgst, dgst_len);
	in.validation.tag = TPM_ST_HASHCHECK;
	in.validation.hierarchy = TPM_RH_NULL;
	in.validation.digest.t.size = 0;
	rc = tpm2_get_hmac_handle(tssContext, &authHandle, 0);
	if (rc)
		return NULL;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Sign,
			 authHandle, auth, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tpm2_error(rc, "TPM2_Sign");
		tpm2_flush_handle(tssContext, authHandle);
		return NULL;
	}

	sig = ECDSA_SIG_new();
	if (!sig)
		return NULL;

	sig->r = BN_bin2bn(out.signature.signature.ecdsa.signatureR.t.buffer,
			   out.signature.signature.ecdsa.signatureR.t.size,
			   NULL);
	sig->s = BN_bin2bn(out.signature.signature.ecdsa.signatureS.t.buffer,
			   out.signature.signature.ecdsa.signatureS.t.size,
			   NULL);

	return sig;
}

int tpm2_setup_ecc_methods(void)
{
	tpm2_ecdsa = ECDSA_METHOD_new(NULL);

	if (!tpm2_ecdsa)
		return 0;

	ECDSA_METHOD_set_name(tpm2_ecdsa, (char *)ecc_method_names);
	ECDSA_METHOD_set_sign(tpm2_ecdsa, tpm2_ecdsa_sign);

	ec_app_data =  ECDSA_get_ex_new_index(0, NULL, NULL, NULL, tpm2_ecdsa_free);

	return 1;
}
