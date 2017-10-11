/*
 * Copyright (C) 2016 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * GPLv2
 */

#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <tss2/tss.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>
#include <tss2/tsscrypto.h>
#include <tss2/tsscryptoh.h>

#include "tpm2-common.h"

/*
 * Mutually supported curves: curves both the TPM2 and
 * openssl support (this excludes BN P256)
 */
struct tpm2_ECC_Curves tpm2_supported_curves[] = {
	{ "prime256v1", NID_X9_62_prime256v1, TPM_ECC_NIST_P256 },
	{ "secp384r1", NID_secp384r1, TPM_ECC_NIST_P384 },
	/* openssl unknown algorithms */
	{ "bnp256", 0, TPM_ECC_BN_P256 },
	{ NULL, 0, 0 }
};

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

int tpm2_get_ecc_group(EC_KEY *eck, TPMI_ECC_CURVE curveID)
{
	const int nid = tpm2_curve_name_to_nid(curveID);
	BN_CTX *ctx = NULL;
	BIGNUM *p, *a, *b, *gX, *gY, *n, *h;
	ECC_Parameters_In in;
	ECC_Parameters_Out out;
	TSS_CONTEXT *tssContext = NULL;
	TPM_RC rc;
	EC_GROUP *g = NULL;
	EC_POINT *P = NULL;
	int ret = 0;

	if (nid) {
		g = EC_GROUP_new_by_curve_name(nid);
		goto out;
	}

	/* openssl doesn't have a nid for the curve, so need
	 * to set the exact parameters in the key */
	rc = TSS_Create(&tssContext);
	if (rc) {
		tpm2_error(rc, "TSS_Create");
		goto err;
	}
	in.curveID = curveID;
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_ECC_Parameters,
			 TPM_RH_NULL, NULL, 0);
	TSS_Delete(tssContext);

	if (rc) {
		tpm2_error(rc, "TPM2_ECC_Parameters");
		goto err;
	}

	ctx = BN_CTX_new();
	if (!ctx)
		goto err;

	BN_CTX_start(ctx);
	p = BN_CTX_get(ctx);
	a = BN_CTX_get(ctx);
	b = BN_CTX_get(ctx);
	gX = BN_CTX_get(ctx);
	gY = BN_CTX_get(ctx);
	n = BN_CTX_get(ctx);
	h = BN_CTX_get(ctx);

	if (!p || !a || !b || !gX || !gY || !n || !h)
		goto err;

	BN_bin2bn(out.parameters.p.t.buffer, out.parameters.p.t.size, p);
	BN_bin2bn(out.parameters.a.t.buffer, out.parameters.a.t.size, a);
	BN_bin2bn(out.parameters.b.t.buffer, out.parameters.b.t.size, b);
	BN_bin2bn(out.parameters.gX.t.buffer, out.parameters.gX.t.size, gX);
	BN_bin2bn(out.parameters.gY.t.buffer, out.parameters.gY.t.size, gY);
	BN_bin2bn(out.parameters.n.t.buffer, out.parameters.n.t.size, n);
	BN_bin2bn(out.parameters.h.t.buffer, out.parameters.h.t.size, h);

	g = EC_GROUP_new_curve_GFp(p, a, b, ctx);
	if (!g)
		goto err;

	P = EC_POINT_new(g);
	if (!P)
		goto err;
	if (!EC_POINT_set_affine_coordinates_GFp(g, P, gX, gY, ctx))
		goto err;
	if (!EC_GROUP_set_generator(g, P, n, h))
		goto err;
 out:
	ret = 1;
	EC_KEY_set_group(eck, g);

 err:
	if (P)
		EC_POINT_free(P);
	if (g)
		EC_GROUP_free(g);
	if (ctx) {
		BN_CTX_end(ctx);
		BN_CTX_free(ctx);
	}
	return ret;
}

static EVP_PKEY *tpm2_to_openssl_public_ecc(TPMT_PUBLIC *pub)
{
	EC_KEY *eck = EC_KEY_new();
	EVP_PKEY *pkey;
	BIGNUM *x, *y;

	if (!eck)
		return NULL;
	pkey = EVP_PKEY_new();
	if (!pkey)
		goto err_free_eck;
	if (!tpm2_get_ecc_group(eck, pub->parameters.eccDetail.curveID))
		goto err_free_pkey;
	x = BN_bin2bn(pub->unique.ecc.x.t.buffer, pub->unique.ecc.x.t.size, NULL);
	y = BN_bin2bn(pub->unique.ecc.y.t.buffer, pub->unique.ecc.y.t.size, NULL);
	EC_KEY_set_public_key_affine_coordinates(eck, x, y);
	BN_free(y);
	BN_free(x);
	if (!EVP_PKEY_assign_EC_KEY(pkey, eck))
		goto err_free_pkey;

	return pkey;

 err_free_pkey:
	EVP_PKEY_free(pkey);
 err_free_eck:
	EC_KEY_free(eck);

	return NULL;
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
	case TPM_ALG_ECC:
		return tpm2_to_openssl_public_ecc(pub);
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

/*
 * Cut down version of Part 4 Supporting Routines 7.6.3.10
 *
 * Hard coded to symmetrically encrypt with aes128 as the inner
 * wrapper and no outer wrapper but with a prototype that allows
 * drop in replacement with a tss equivalent
 */
TPM_RC tpm2_SensitiveToDuplicate(TPMT_SENSITIVE *s,
				 TPM2B_NAME *name,
				 TPM_ALG_ID nalg,
				 TPM2B_SEED *seed,
				 TPMT_SYM_DEF_OBJECT *symdef,
				 TPM2B_DATA *innerkey,
				 TPM2B_PRIVATE *p)
{
	BYTE *buf = p->t.buffer;

	p->t.size = 0;
	memset(p, 0, sizeof(*p));

	/* hard code AES CFB */
	if (symdef->algorithm == TPM_ALG_AES
	    && symdef->mode.aes == TPM_ALG_CFB) {
		TPMT_HA hash;
		const int hlen = TSS_GetDigestSize(nalg);
		TPM2B *digest = (TPM2B *)buf;
		TPM2B *s2b;
		int32_t size;
		unsigned char null_iv[AES_128_BLOCK_SIZE_BYTES];
		UINT16 bsize, written = 0;

		/* WARNING: don't use the static null_iv trick here:
		 * the AES routines alter the passed in iv */
		memset(null_iv, 0, sizeof(null_iv));

		/* reserve space for hash before the encrypted sensitive */
		bsize = sizeof(digest->size) + hlen;
		buf += bsize;
		p->t.size += bsize;
		s2b = (TPM2B *)buf;

		/* marshal the digest size */
		buf = (BYTE *)&digest->size;
		bsize = hlen;
		size = 2;
		TSS_UINT16_Marshal(&bsize, &written, &buf, &size);

		/* marshal the unencrypted sensitive in place */
		size = sizeof(*s);
		bsize = 0;
		buf = s2b->buffer;
		TSS_TPMT_SENSITIVE_Marshal(s, &bsize, &buf, &size);
		buf = (BYTE *)&s2b->size;
		size = 2;
		TSS_UINT16_Marshal(&bsize, &written, &buf, &size);

		bsize = bsize + sizeof(s2b->size);
		p->t.size += bsize;

		/* compute hash of unencrypted marshalled sensitive and
		 * write to the digest buffer */
		hash.hashAlg = nalg;
		TSS_Hash_Generate(&hash, bsize, s2b,
				  name->t.size, name->t.name,
				  0, NULL);
		memcpy(digest->buffer, &hash.digest, hlen);

		/* encrypt hash and sensitive in place */
		TSS_AES_EncryptCFB(p->t.buffer,
				   symdef->keyBits.aes,
				   innerkey->b.buffer,
				   null_iv,
				   p->t.size,
				   p->t.buffer);
	} else if (symdef->algorithm == TPM_ALG_NULL) {
		TPM2B *s2b = (TPM2B *)buf;
		int32_t size = sizeof(*s);
		UINT16 bsize = 0, written = 0;

		buf = s2b->buffer;

		/* marshal the unencrypted sensitive in place */
		TSS_TPMT_SENSITIVE_Marshal(s, &bsize, &buf, &size);
		buf = (BYTE *)&s2b->size;
		size = 2;
		TSS_UINT16_Marshal(&bsize, &written, &buf, &size);

		p->b.size += bsize + sizeof(s2b->size);
	} else {
		printf("Unknown symmetric algorithm\n");
		return TPM_RC_SYMMETRIC;
	}

	return TPM_RC_SUCCESS;
}

TPM_RC tpm2_ObjectPublic_GetName(TPM2B_NAME *name,
				 TPMT_PUBLIC *tpmtPublic)
{
	TPM_RC rc = 0;
	uint16_t written = 0;
	TPMT_HA digest;
	uint32_t sizeInBytes;
	uint8_t buffer[MAX_RESPONSE_SIZE];

	/* marshal the TPMT_PUBLIC */
	if (rc == 0) {
		INT32 size = MAX_RESPONSE_SIZE;
		uint8_t *buffer1 = buffer;
		rc = TSS_TPMT_PUBLIC_Marshal(tpmtPublic, &written, &buffer1, &size);
	}
	/* hash the public area */
	if (rc == 0) {
		sizeInBytes = TSS_GetDigestSize(tpmtPublic->nameAlg);
		digest.hashAlg = tpmtPublic->nameAlg;	/* Name digest algorithm */
		/* generate the TPMT_HA */
		rc = TSS_Hash_Generate(&digest,	
				       written, buffer,
				       0, NULL);
	}
	if (rc == 0) {
		/* copy the digest */
		memcpy(name->t.name + sizeof(TPMI_ALG_HASH), (uint8_t *)&digest.digest, sizeInBytes);
		/* copy the hash algorithm */
		TPMI_ALG_HASH nameAlgNbo = htons(tpmtPublic->nameAlg);
		memcpy(name->t.name, (uint8_t *)&nameAlgNbo, sizeof(TPMI_ALG_HASH));
		/* set the size */
		name->t.size = sizeInBytes + sizeof(TPMI_ALG_HASH);
	}
	return rc;
}

TPMI_ECC_CURVE tpm2_curve_name_to_TPMI(const char *name)
{
	int i;

	for (i = 0; tpm2_supported_curves[i].name != NULL; i++)
		if (strcmp(name, tpm2_supported_curves[i].name) == 0)
			return tpm2_supported_curves[i].curve;

	return TPM_ECC_NONE;
}

int tpm2_curve_name_to_nid(TPMI_ECC_CURVE curve)
{
	int i;

	for (i = 0; tpm2_supported_curves[i].name != NULL; i++)
		if (tpm2_supported_curves[i].curve == curve)
			return tpm2_supported_curves[i].nid;

	return 0;
}
