/*
 * Copyright (C) 2016 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * GPLv2
 */

#include <stdio.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <tss2/tss.h>
#include <tss2/tssresponsecode.h>

#include "tpm2-common.h"

void tpm2_error(TPM_RC rc, const char *reason)
{
	const char *msg, *submsg, *num;

	fprintf(stderr, "%s failed with %d\n", reason, rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	fprintf(stderr, "%s%s%s\n", msg, submsg, num);
}


static TPM_HANDLE hSRK = 0;

TPM_RC tpm2_load_srk(TSS_CONTEXT *tssContext, TPM_HANDLE *h, const char *auth,TPM2B_PUBLIC *pub)
{
	static TPM2B_PUBLIC srk_pub;
	TPM_RC rc;
	CreatePrimary_In in;
	CreatePrimary_Out out;

	if (hSRK)
		goto out;

	/* SPS owner */
	in.primaryHandle = TPM_RH_OWNER;
	/* assume no owner password */
	in.inSensitive.sensitive.userAuth.t.size = 0;
	/* no sensitive date for storage keys */
	in.inSensitive.sensitive.data.t.size = 0;
	/* no outside info */
	in.outsideInfo.t.size = 0;
	/* no PCR state */
	in.creationPCR.count = 0;

	/* public parameters for an RSA2048 key  */
	in.inPublic.publicArea.type = TPM_ALG_RSA;
	in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
	in.inPublic.publicArea.objectAttributes.val =
		TPMA_OBJECT_NODA |
		TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_USERWITHAUTH |
		TPMA_OBJECT_DECRYPT |
		TPMA_OBJECT_RESTRICTED;
	in.inPublic.publicArea.parameters.rsaDetail.symmetric.algorithm = TPM_ALG_AES;
	in.inPublic.publicArea.parameters.rsaDetail.symmetric.keyBits.aes = 128;
	in.inPublic.publicArea.parameters.rsaDetail.symmetric.mode.aes = TPM_ALG_CFB;
	in.inPublic.publicArea.parameters.rsaDetail.scheme.scheme = TPM_ALG_NULL;
	in.inPublic.publicArea.parameters.rsaDetail.keyBits = 2048;
	/* means conventional 2^16+1 */
	in.inPublic.publicArea.parameters.rsaDetail.exponent = 0;
	in.inPublic.publicArea.unique.rsa.t.size = 0;
	in.inPublic.publicArea.authPolicy.t.size = 0;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_CreatePrimary,
			 TPM_RS_PW, NULL, 0,
			 TPM_RH_NULL, NULL, 0);

	if (rc) {
		tpm2_error(rc, "TSS_CreatePrimary");
		return rc;
	}

	hSRK = out.objectHandle;
	srk_pub = out.outPublic;
 out:
	*h = hSRK;
	if (pub)
		*pub = srk_pub;

	return 0;
}

void tpm2_flush_srk(TSS_CONTEXT *tssContext)
{
	if (hSRK)
		tpm2_flush_handle(tssContext, hSRK);
	hSRK = 0;
}

void tpm2_flush_handle(TSS_CONTEXT *tssContext, TPM_HANDLE h)
{
	FlushContext_In in;

	if (!h)
		return;

	in.flushHandle = h;
	TSS_Execute(tssContext, NULL, 
		    (COMMAND_PARAMETERS *)&in,
		    NULL,
		    TPM_CC_FlushContext,
		    TPM_RH_NULL, NULL, 0);
}

static EVP_PKEY *tpm2_to_openssl_public_rsa(TPMT_PUBLIC *pub)
{
	RSA *rsa = RSA_new();
	EVP_PKEY *pkey;
	unsigned long exp;
	BIGNUM *n, *e;

	if (!rsa)
		return NULL;
	pkey = EVP_PKEY_new();
	if (!pkey)
		goto err_free_rsa;
	e = BN_new();
	if (!e)
		goto err_free_pkey;
	n = BN_new();
	if (!n)
		goto err_free_e;
	if (pub->parameters.rsaDetail.exponent == 0)
		exp = 0x10001;
	else
		exp = pub->parameters.rsaDetail.exponent;
	if (!BN_set_word(e, exp))
		goto err_free;
	if (!BN_bin2bn(pub->unique.rsa.t.buffer, pub->unique.rsa.t.size, n))
		goto err_free;
#if OPENSSL_VERSION_NUMBER < 0x10100000
	rsa->n = n;
	rsa->e = e;
#else
	RSA_set0_key(rsa, n, e, NULL);
#endif
	if (!EVP_PKEY_assign_RSA(pkey, rsa))
		goto err_free;

	return pkey;

 err_free:
	BN_free(n);
 err_free_e:
	BN_free(e);
 err_free_pkey:
	EVP_PKEY_free(pkey);
 err_free_rsa:
	RSA_free(rsa);

	return NULL;
}

EVP_PKEY *tpm2_to_openssl_public(TPMT_PUBLIC *pub)
{
	switch (pub->type) {
	case TPM_ALG_RSA:
		return tpm2_to_openssl_public_rsa(pub);
	default:
		break;
	}
	return NULL;
}

TPM_RC tpm2_get_hmac_handle(TSS_CONTEXT *tssContext, TPM_HANDLE *handle,
			    TPM_HANDLE salt_key)
{
	TPM_RC rc;
	StartAuthSession_In in;
	StartAuthSession_Out out;
	StartAuthSession_Extra extra;

	memset(&in, 0, sizeof(in));
	memset(&extra, 0 , sizeof(extra));
	in.bind = TPM_RH_NULL;
	in.sessionType = TPM_SE_HMAC;
	in.authHash = TPM_ALG_SHA256;
	in.tpmKey = TPM_RH_NULL;
	in.symmetric.algorithm = TPM_ALG_AES;
	in.symmetric.keyBits.aes = 128;
	in.symmetric.mode.aes = TPM_ALG_CFB;
	if (salt_key)
		in.tpmKey = salt_key;
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 (EXTRA_PARAMETERS *)&extra,
			 TPM_CC_StartAuthSession,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tpm2_error(rc, "TPM2_StartAuthSession");
		return rc;
	}

	*handle = out.sessionHandle;

	return TPM_RC_SUCCESS;
}
