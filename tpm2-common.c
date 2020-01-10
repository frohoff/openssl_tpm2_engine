/*
 * Copyright (C) 2016 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/ui.h>

#define TSSINCLUDE(x) < TSS_INCLUDE/x >
#include TSSINCLUDE(tss.h)
#include TSSINCLUDE(tssresponsecode.h)
#include TSSINCLUDE(tssmarshal.h)
#include TSSINCLUDE(tsscryptoh.h)
#include TSSINCLUDE(Unmarshal_fp.h)

#include "tpm2-common.h"
#include "tpm2-asn.h"

struct myTPM2B {
	UINT16 s;
	BYTE *const b;
};
struct tpm2_ECC_Curves {
	const char *name;
	int nid;
	TPMI_ECC_CURVE curve;
	/* 7 parameters are p, a, b, gX, gY, n, h */
	struct myTPM2B C[7];
};
/*
 * Mutually supported curves: curves both the TPM2 and
 * openssl support (this excludes BN P256)
 */
struct tpm2_ECC_Curves tpm2_supported_curves[] = {
	{ .name = "prime256v1",
	  .nid = NID_X9_62_prime256v1,
	  .curve = TPM_ECC_NIST_P256,
	  /* p */
	  .C[0].s = 32,
	  .C[0].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

		},
	  /* a */
	  .C[1].s = 32,
	  .C[1].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC,
		},
	  /* b */
	  .C[2].s = 32,
	  .C[2].b = (BYTE [])
		{
			0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7,
			0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
			0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6,
			0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B,
		},
	  /* gX */
	  .C[3].s = 32,
	  .C[3].b = (BYTE [])
		{
			0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47,
			0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
			0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0,
			0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96,
		},
	  /* gY */
	  .C[4].s = 32,
	  .C[4].b = (BYTE [])
		{
			0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b,
			0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
			0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
			0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
		},
	  /* order */
	  .C[5].s = 32,
	  .C[5].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
			0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
		},
	},
	{ .name = "secp384r1",
	  .nid = NID_secp384r1,
	  .curve = TPM_ECC_NIST_P384,
	  /* p */
	  .C[0].s = 48,
	  .C[0].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
			0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF,
		},
	  /* a */
	  .C[1].s = 48,
	  .C[1].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
			0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFC,

		},
	  /* b */
	  .C[2].s = 48,
	  .C[2].b = (BYTE [])
		{
			0xB3, 0x31, 0x2F, 0xA7, 0xE2, 0x3E, 0xE7, 0xE4,
			0x98, 0x8E, 0x05, 0x6B, 0xE3, 0xF8, 0x2D, 0x19,
			0x18, 0x1D, 0x9C, 0x6E, 0xFE, 0x81, 0x41, 0x12,
			0x03, 0x14, 0x08, 0x8F, 0x50, 0x13, 0x87, 0x5A,
			0xC6, 0x56, 0x39, 0x8D, 0x8A, 0x2E, 0xD1, 0x9D,
			0x2A, 0x85, 0xC8, 0xED, 0xD3, 0xEC, 0x2A, 0xEF,
		},
	  /* gX */
	  .C[3].s = 48,
	  .C[3].b = (BYTE [])
		{
			0xAA, 0x87, 0xCA, 0x22, 0xBE, 0x8B, 0x05, 0x37,
			0x8E, 0xB1, 0xC7, 0x1E, 0xF3, 0x20, 0xAD, 0x74,
			0x6E, 0x1D, 0x3B, 0x62, 0x8B, 0xA7, 0x9B, 0x98,
			0x59, 0xF7, 0x41, 0xE0, 0x82, 0x54, 0x2A, 0x38,
			0x55, 0x02, 0xF2, 0x5D, 0xBF, 0x55, 0x29, 0x6C,
			0x3A, 0x54, 0x5E, 0x38, 0x72, 0x76, 0x0A, 0xB7,
		},
	  /* gY */
	  .C[4].s = 48,
	  .C[4].b = (BYTE [])
		{
			0x36, 0x17, 0xde, 0x4a, 0x96, 0x26, 0x2c, 0x6f,
			0x5d, 0x9e, 0x98, 0xbf, 0x92, 0x92, 0xdc, 0x29,
			0xf8, 0xf4, 0x1d, 0xbd, 0x28, 0x9a, 0x14, 0x7c,
			0xe9, 0xda, 0x31, 0x13, 0xb5, 0xf0, 0xb8, 0xc0,
			0x0a, 0x60, 0xb1, 0xce, 0x1d, 0x7e, 0x81, 0x9d,
			0x7a, 0x43, 0x1d, 0x7c, 0x90, 0xea, 0x0e, 0x5f,
		},
	  /* order */
	  .C[5].s = 48,
	  .C[5].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
			0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A,
			0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73,
		},
	},
	/* openssl unknown algorithms below */
	{ .name = "bnp256",
	  .nid = 0,
	  .curve = TPM_ECC_BN_P256,
	  /* p */
	  .C[0].s = 32,
	  .C[0].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
			0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9F,
			0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x98, 0x0A, 0x82,
			0xD3, 0x29, 0x2D, 0xDB, 0xAE, 0xD3, 0x30, 0x13,

		},
	  /* a */
	  .C[1].s = 1 ,
	  .C[1].b = (BYTE [])
		{
			0x00,
		},
	  /* b */
	  .C[2].s = 1,
	  .C[2].b = (BYTE [])
		{
			0x03,
		},
	  /* gX */
	  .C[3].s = 1 ,
	  .C[3].b = (BYTE [])
		{
			0x01,
		},
	  /* gY */
	  .C[4].s = 1 ,
	  .C[4].b = (BYTE [])
		{
			0x02,
		},
	  /* order */
	  .C[5].s = 32,
	  .C[5].b = (BYTE [])
		{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC, 0xF0, 0xCD,
			0x46, 0xE5, 0xF2, 0x5E, 0xEE, 0x71, 0xA4, 0x9E,
			0x0C, 0xDC, 0x65, 0xFB, 0x12, 0x99, 0x92, 0x1A,
			0xF6, 0x2D, 0x53, 0x6C, 0xD1, 0x0B, 0x50, 0x0D,
		},
	},
	{ .name = NULL, }
};

void tpm2_error(TPM_RC rc, const char *reason)
{
	const char *msg, *submsg, *num;

	fprintf(stderr, "%s failed with %d\n", reason, rc);
	TSS_ResponseCode_toString(&msg, &submsg, &num, rc);
	fprintf(stderr, "%s%s%s\n", msg, submsg, num);
}


TPM_RC tpm2_load_srk(TSS_CONTEXT *tssContext, TPM_HANDLE *h, const char *auth,TPM2B_PUBLIC *pub, TPM_HANDLE hierarchy, int version)
{
	TPM_RC rc;
	CreatePrimary_In in;
	CreatePrimary_Out out;
	TPM_HANDLE session;

	/* SPS owner */
	in.primaryHandle = hierarchy;
	if (auth) {
		in.inSensitive.sensitive.userAuth.t.size = strlen(auth);
		memcpy(in.inSensitive.sensitive.userAuth.t.buffer, auth, strlen(auth));
	} else {
		in.inSensitive.sensitive.userAuth.t.size = 0;
	}

	/* no sensitive date for storage keys */
	in.inSensitive.sensitive.data.t.size = 0;
	/* no outside info */
	in.outsideInfo.t.size = 0;
	/* no PCR state */
	in.creationPCR.count = 0;

	/* public parameters for an RSA2048 key  */
	in.inPublic.publicArea.type = TPM_ALG_ECC;
	in.inPublic.publicArea.nameAlg = TPM_ALG_SHA256;
	in.inPublic.publicArea.objectAttributes.val =
		TPMA_OBJECT_NODA |
		TPMA_OBJECT_SENSITIVEDATAORIGIN |
		TPMA_OBJECT_USERWITHAUTH |
		TPMA_OBJECT_DECRYPT |
		TPMA_OBJECT_RESTRICTED;
	if (version)
		in.inPublic.publicArea.objectAttributes.val |=
			TPMA_OBJECT_FIXEDPARENT |
			TPMA_OBJECT_FIXEDTPM;

	in.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
	in.inPublic.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
	in.inPublic.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
	in.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
	in.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
	in.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;

	in.inPublic.publicArea.unique.ecc.x.t.size = 0;
	in.inPublic.publicArea.unique.ecc.y.t.size = 0;
	in.inPublic.publicArea.authPolicy.t.size = 0;

	/* use a bound session here because we have no known key objects
	 * to encrypt a salt to */
	rc = tpm2_get_bound_handle(tssContext, &session, hierarchy, auth);
	if (rc)
		return rc;

	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_CreatePrimary,
			 session, auth, TPMA_SESSION_DECRYPT,
			 TPM_RH_NULL, NULL, 0);

	if (rc) {
		tpm2_error(rc, "TSS_CreatePrimary");
		tpm2_flush_handle(tssContext, session);
		return rc;
	}

	*h = out.objectHandle;
	if (pub)
		*pub = out.outPublic;

	return 0;
}

void tpm2_flush_srk(TSS_CONTEXT *tssContext, TPM_HANDLE hSRK)
{
	/* only flush if it's a volatile key which we must have created */
	if ((hSRK & 0xFF000000) == 0x80000000)
		tpm2_flush_handle(tssContext, hSRK);
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
		EC_GROUP_set_asn1_flag(g, OPENSSL_EC_NAMED_CURVE);
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

TPM_RC tpm2_readpublic(TSS_CONTEXT *tssContext, TPM_HANDLE handle,
		       TPMT_PUBLIC *pub)
{
	ReadPublic_In rin;
	ReadPublic_Out rout;
	TPM_RC rc;

	rin.objectHandle = handle;
	rc = TSS_Execute (tssContext,
			  (RESPONSE_PARAMETERS *)&rout,
			  (COMMAND_PARAMETERS *)&rin,
			  NULL,
			  TPM_CC_ReadPublic,
			  TPM_RH_NULL, NULL, 0);
	if (rc) {
		tpm2_error(rc, "TPM2_ReadPublic");
		return rc;
	}
	if (pub)
		*pub = rout.outPublic.publicArea;

	return rc;
}

TPM_RC tpm2_get_bound_handle(TSS_CONTEXT *tssContext, TPM_HANDLE *handle,
			     TPM_HANDLE bind, const char *auth)
{
	TPM_RC rc;
	StartAuthSession_In in;
	StartAuthSession_Out out;
	StartAuthSession_Extra extra;

	memset(&in, 0, sizeof(in));
	memset(&extra, 0 , sizeof(extra));
	in.bind = bind;
	extra.bindPassword = auth;
	in.sessionType = TPM_SE_HMAC;
	in.authHash = TPM_ALG_SHA256;
	in.tpmKey = TPM_RH_NULL;
	in.symmetric.algorithm = TPM_ALG_AES;
	in.symmetric.keyBits.aes = 128;
	in.symmetric.mode.aes = TPM_ALG_CFB;
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

TPM_RC tpm2_get_session_handle(TSS_CONTEXT *tssContext, TPM_HANDLE *handle,
			       TPM_HANDLE salt_key, TPM_SE sessionType,
			       TPM_ALG_ID name_alg)
{
	TPM_RC rc;
	StartAuthSession_In in;
	StartAuthSession_Out out;
	StartAuthSession_Extra extra;

	memset(&in, 0, sizeof(in));
	memset(&extra, 0 , sizeof(extra));
	in.bind = TPM_RH_NULL;
	in.sessionType = sessionType;
	in.authHash = name_alg;
	in.tpmKey = TPM_RH_NULL;
	in.symmetric.algorithm = TPM_ALG_AES;
	in.symmetric.keyBits.aes = 128;
	in.symmetric.mode.aes = TPM_ALG_CFB;
	if (salt_key) {
		/* For the TSS to use a key as salt, it must have
		 * access to the public part.  It does this by keeping
		 * key files, but request the public part just to make
		 * sure*/
		tpm2_readpublic(tssContext, salt_key,  NULL);
		/* don't care what rout returns, the purpose of the
		 * operation was to get the public key parameters into
		 * the tss so it can construct the salt */
		in.tpmKey = salt_key;
	}
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

TPM_RC tpm2_init_session(TSS_CONTEXT *tssContext, TPM_HANDLE handle,
			 int num_commands, struct policy_command *commands,
			 TPM_ALG_ID name_alg)
{
	INT32 size;
	BYTE *policy;
	TPM_RC rc = 0, reason_rc = 0;
	COMMAND_PARAMETERS in;
	int i;
	char reason[256];
	int name_alg_size = TSS_GetDigestSize(name_alg);

	reason[0] = '\0';
	/* pick a random policy type: they all have the handle first */
	in.PolicyPCR.policySession = handle;

	for (i = 0; i < num_commands; i++) {
		size = commands[i].size;
		policy = commands[i].policy;

		switch (commands[i].code) {
		case TPM_CC_PolicyPCR: {
			PolicyPCR_In *ppcrin = &in.PolicyPCR;

			rc = TPML_PCR_SELECTION_Unmarshal(
				&ppcrin->pcrs, &policy, &size);
			ppcrin->pcrDigest.b.size = name_alg_size;
			memcpy(ppcrin->pcrDigest.b.buffer,
			       policy, name_alg_size);
			sprintf(reason, "PCR Mismatch");
			reason_rc = TPM_RC_VALUE;

			break;
		}
		case TPM_CC_PolicyAuthValue:
			break;
		case TPM_CC_PolicyCounterTimer: {
			PolicyCounterTimer_In *pctin = &in.PolicyCounterTimer;
			BYTE *p_buffer;
			INT32 p_size;
			int i, c;
			const char *const operand[] = {
				[TPM_EO_EQ] = "==",
				[TPM_EO_NEQ] = "!=",
				[TPM_EO_SIGNED_GT] = ">(s)",
				[TPM_EO_UNSIGNED_GT] = ">",
				[TPM_EO_SIGNED_LT] = "<(s)",
				[TPM_EO_UNSIGNED_LT] = "<",
				[TPM_EO_SIGNED_GE] = ">=(s)",
				[TPM_EO_UNSIGNED_GE] = ">=",
				[TPM_EO_SIGNED_LE] = "<=(s)",
				[TPM_EO_UNSIGNED_LE] = "<=",
				[TPM_EO_BITSET] = "bitset",
				[TPM_EO_BITCLEAR] = "bitclear",
			};

			/* last UINT16 is the operand */
			p_buffer = policy + size - 2;
			p_size = 2;
			TPM_EO_Unmarshal(&pctin->operation, &p_buffer,
					 &p_size);
			/* second to last UINT16 is the offset */
			p_buffer = policy + size - 4;
			p_size = 2;
			UINT16_Unmarshal(&pctin->offset, &p_buffer, &p_size);

			/* and the rest is the OperandB */
			pctin->operandB.b.size = size - 4;
			memcpy(pctin->operandB.b.buffer, policy, size - 4);

			c = sprintf(reason,
				    "Counter Timer at offset %d is not %s ",
				    pctin->offset, operand[pctin->operation]);
			for (i = 0; i < size - 4; i++)
				c += sprintf(&reason[c], "%02x", policy[i]);

			reason[c] = '\0';
			reason_rc = TPM_RC_POLICY;

			break;
		}
		default:
			fprintf(stderr, "Unsupported policy command %d\n",
				commands[i].code);
			rc = TPM_RC_FAILURE;
			goto out_flush;
		}

		if (rc) {
			tpm2_error(rc, "unmarshal");
			goto out_flush;
		}

		rc = TSS_Execute(tssContext,
				NULL,
				&in,
				NULL,
				commands[i].code,
				TPM_RH_NULL, NULL, 0);
		if (rc) {
			TPM_RC check_rc;

			/* strip additional parameter or session information */
			if ((rc & 0x180) == RC_VER1)
				check_rc = rc & 0x1ff;
			else if (rc & RC_FMT1)
				check_rc = rc & 0xbf;
			else
				check_rc = rc;

			if (check_rc == reason_rc && reason[0])
				fprintf(stderr, "Policy Failure: %s\n", reason);
			else
				tpm2_error(rc, "policy command");
			goto out_flush;
		}
	}

	return TPM_RC_SUCCESS;

 out_flush:
	tpm2_flush_handle(tssContext, handle);
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

TPMI_ECC_CURVE tpm2_nid_to_curve_name(int nid)
{
	int i;

	if (!nid)
		return TPM_ECC_NONE;

	for (i = 0; tpm2_supported_curves[i].name != NULL; i++)
		if (tpm2_supported_curves[i].nid == nid)
			return tpm2_supported_curves[i].curve;

	return TPM_ECC_NONE;
}

TPMI_ECC_CURVE tpm2_get_curve_name(const EC_GROUP *g)
{
	int nid = EC_GROUP_get_curve_name(g);
	const EC_POINT *P;
	BIGNUM *C[6], *N, *R;
	BN_CTX *ctx;
	int i;
	TPMI_ECC_CURVE curve = TPM_ECC_NONE;

	if (nid)
		return tpm2_nid_to_curve_name(nid);

	ctx = BN_CTX_new();
	BN_CTX_start(ctx);
	for (i = 0; i < 6; i++)
		C[i] = BN_CTX_get(ctx);
	N = BN_CTX_get(ctx);
	R = BN_CTX_get(ctx);

	EC_GROUP_get_curve_GFp(g, C[0], C[1], C[2], ctx);
	P = EC_GROUP_get0_generator(g);
	EC_POINT_get_affine_coordinates_GFp(g, P, C[3], C[4], ctx);
	EC_GROUP_get_order(g, C[5], ctx);

	for (i = 0; tpm2_supported_curves[i].name != NULL; i++) {
		int j;
		for (j = 0; j < 6; j++) {
			BN_bin2bn(tpm2_supported_curves[i].C[j].b,
				  tpm2_supported_curves[i].C[j].s, N);
			BN_sub(R, N, C[j]);
			if (!BN_is_zero(R))
				break;
		}
		if (j == 6) {
			curve = tpm2_supported_curves[i].curve;
			break;
		}
	}

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	return curve;
}

const char *tpm2_curve_name_to_text(TPMI_ECC_CURVE curve)
{
	int i;

	for (i = 0; tpm2_supported_curves[i].name != NULL; i++)
		if (tpm2_supported_curves[i].curve == curve)
			return tpm2_supported_curves[i].name;

	return NULL;
}

const char *tpm2_set_unique_tssdir(void)
{
	char *prefix = getenv("XDG_RUNTIME_DIR"), *template,
		*dir;
	int len = 0;

	if (!prefix)
		prefix = "/tmp";

	len = snprintf(NULL, 0, "%s/tss2.XXXXXX", prefix);
	if (len <= 0)
		return NULL;
	template = OPENSSL_malloc(len + 1);
	if (!template)
		return NULL;

	len++;
	len = snprintf(template, len, "%s/tss2.XXXXXX", prefix);

	dir = mkdtemp(template);
	return dir;
}

void tpm2_rm_keyfile(const char *dir, TPM_HANDLE key)
{
	char keyfile[1024];

	snprintf(keyfile, sizeof(keyfile), "%s/h%08x.bin", dir, key);
	unlink(keyfile);
	snprintf(keyfile, sizeof(keyfile), "%s/hp%08x.bin", dir, key);
	unlink(keyfile);
}

void tpm2_rm_tssdir(const char *dir)
{
	if (rmdir(dir) < 0) {
		fprintf(stderr, "Unlinking %s", dir);
		perror(":");
	}
}

TPM_RC tpm2_create(TSS_CONTEXT **tsscp, const char *dir)
{
	TPM_RC rc;

	rc = TSS_Create(tsscp);
	if (rc) {
		tpm2_error(rc, "TSS_Create");
		return rc;
	}
	rc = TSS_SetProperty(*tsscp, TPM_DATA_DIR, dir);
	if (rc) {
		tpm2_error(rc, "TSS_SetProperty");
		return rc;
	}

	return TPM_RC_SUCCESS;
}

int tpm2_get_public_point(TPM2B_ECC_POINT *tpmpt, const EC_GROUP *group,
			  const EC_POINT *pt)
{
	BN_CTX *ctx;
	size_t len;
	unsigned char point[MAX_ECC_KEY_BYTES*2 + 1];

	ctx = BN_CTX_new();
	if (!ctx)
		return 0;
	BN_CTX_start(ctx);
	len = EC_POINT_point2oct(group, pt, POINT_CONVERSION_UNCOMPRESSED,
				 point, sizeof(point), ctx);
	BN_CTX_free(ctx);

	len--;
	len >>= 1;

	memcpy(tpmpt->point.x.t.buffer, point + 1, len);
	tpmpt->point.x.t.size = len;
	memcpy(tpmpt->point.y.t.buffer, point + 1 + len, len);
	tpmpt->point.y.t.size = len;

	return len;
}

static char *tpm2_get_auth_ui(UI_METHOD *ui_method, char *prompt, void *cb_data)
{
	UI *ui = UI_new();
	/* Max auth size is name algorithm hash length, so this
	 * is way bigger than necessary */
	char auth[256], *ret = NULL;
	int len;

	if (ui_method)
		UI_set_method(ui, ui_method);

	UI_add_user_data(ui, cb_data);

	if (UI_add_input_string(ui, prompt, UI_INPUT_FLAG_DEFAULT_PWD,
				auth, 0, sizeof(auth)) == 0) {
		fprintf(stderr, "UI_add_input_string failed\n");
		goto out;
	}

	if (UI_process(ui)) {
		fprintf(stderr, "UI_process failed\n");
		goto out;
	}

	len = strlen(auth);
	ret = OPENSSL_malloc(len + 1);
	if (!ret)
		goto out;

	strcpy(ret, auth);

 out:
	UI_free(ui);

	return ret;
}

static char *tpm2_get_auth_pem(char *input_string, void *cb_data)
{
	char auth[256], *ret;
	int len;

	EVP_set_pw_prompt(input_string);

	PEM_def_callback(auth, sizeof(auth), 0, cb_data);
	EVP_set_pw_prompt(NULL);

	len = strlen(auth);
	ret = OPENSSL_malloc(len + 1);
	if (!ret)
		goto out;

	strcpy(ret, auth);

 out:
	return ret;
}

char *tpm2_get_auth(UI_METHOD *ui, char *input_string, void *cb_data)
{
	if (ui)
		return tpm2_get_auth_ui(ui, input_string, cb_data);
	else
		return tpm2_get_auth_pem(input_string, cb_data);
}

static int tpm2_engine_load_key_policy(struct app_data *app_data,
				       STACK_OF(TSSOPTPOLICY) *st_policy)
{
	struct policy_command *command;
	TSSOPTPOLICY *policy;
	int i, commands_len;

	app_data->num_commands = sk_TSSOPTPOLICY_num(st_policy);
	if (app_data->num_commands <= 0)
		return 1;

	commands_len = sizeof(struct policy_command) * app_data->num_commands;
	app_data->commands = OPENSSL_malloc(commands_len);
	if (!app_data->commands)
		return 0;

	for (i = 0; i < app_data->num_commands; i++) {
		policy = sk_TSSOPTPOLICY_value(st_policy, i);
		if (!policy)
			return 0;

		command = app_data->commands + i;
		command->code = ASN1_INTEGER_get(policy->CommandCode);
		command->size = policy->CommandPolicy->length;
		command->policy = NULL;

		if (!command->size)
			continue;

		command->policy = OPENSSL_malloc(command->size);
		if (!command->policy)
			return 0;

		memcpy(command->policy, policy->CommandPolicy->data,
		       command->size);
	}

	return 1;
}

int tpm2_load_engine_file(const char *filename, struct app_data **app_data,
			  EVP_PKEY **ppkey, UI_METHOD *ui, void *cb_data,
			  const char *srk_auth, int get_key_auth)
{
	BIO *bf;
	TSSLOADABLE *tssl = NULL;
	TSSPRIVKEY *tpk = NULL;
	BYTE *buffer;
	INT32 size;
	struct app_data *ad;
	char oid[128];
	int empty_auth, version = 0;
	ASN1_OBJECT *type;
	ASN1_INTEGER *parent;
	ASN1_OCTET_STRING *pubkey;
	STACK_OF(TSSOPTPOLICY) *policy;
	ASN1_OCTET_STRING *privkey;
	ASN1_OCTET_STRING *secret = NULL;
	Import_In iin;

	bf = BIO_new_file(filename, "r");
	if (!bf) {
		fprintf(stderr, "File %s does not exist or cannot be read\n",
			filename); 
		return 0;
	}

	tpk = PEM_read_bio_TSSPRIVKEY(bf, NULL, NULL, NULL);
	if (!tpk) {
		BIO_seek(bf, 0);
		ERR_clear_error();
		tpk = ASN1_item_d2i_bio(ASN1_ITEM_rptr(TSSPRIVKEY), bf, NULL);
	}
	if (tpk) {
		version = 1;
		type = tpk->type;
		empty_auth = tpk->emptyAuth;
		parent = tpk->parent;
		pubkey = tpk->pubkey;
		privkey = tpk->privkey;
		policy = tpk->policy;
		secret = tpk->secret;
	} else {
		BIO_seek(bf, 0);
		tssl = PEM_read_bio_TSSLOADABLE(bf, NULL, NULL, NULL);
		if (!tssl) {
			BIO_free(bf);
			fprintf(stderr, "Failed to parse file %s\n", filename);
			return 0;
		}

		/* have error from failed TSSPRIVKEY load */
		ERR_clear_error();
		type = tssl->type;
		empty_auth = tssl->emptyAuth;
		parent = tssl->parent;
		pubkey = tssl->pubkey;
		privkey = tssl->privkey;
		policy = tssl->policy;
	}

	BIO_free(bf);

	if (OBJ_obj2txt(oid, sizeof(oid), type, 1) == 0) {
		fprintf(stderr, "Failed to parse object type\n");
		goto err;
	}

	if (strcmp(OID_loadableKey, oid) == 0) {
		if (version != 1) {
			fprintf(stderr, "New type found in old format key\n");
			goto err;
		}
	} else if (strcmp(OID_OldloadableKey, oid) == 0) {
		if (version != 0) {
			fprintf(stderr, "Old type found in new format key\n");
			goto err;
		}
	} else if (strcmp(OID_importableKey, oid) == 0) {
		if (!secret) {
			fprintf(stderr, "Importable keys require an encrypted secret\n");
			goto err;
		}
	} else {
		fprintf(stderr, "Unrecognised object type\n");
		goto err;
	}

	if (empty_auth == -1)
		/* not present means auth is not empty */
		empty_auth = 0;

	ad = OPENSSL_malloc(sizeof(*ad));

	if (!ad) {
		fprintf(stderr, "Failed to allocate app_data\n");
		goto err;
	}
	memset(ad, 0, sizeof(*ad));

	*app_data = ad;

	ad->version = version;
	ad->dir = tpm2_set_unique_tssdir();

	if (parent)
		ad->parent = ASN1_INTEGER_get(parent);
	else
		/* older keys have absent parent */
		ad->parent = TPM_RH_OWNER;

	ad->pub = OPENSSL_malloc(pubkey->length);
	if (!ad->pub)
		goto err_free;
	ad->pub_len = pubkey->length;
	memcpy(ad->pub, pubkey->data, ad->pub_len);

	buffer = ad->pub;
	size = ad->pub_len;
	TPM2B_PUBLIC_Unmarshal(&iin.objectPublic, &buffer, &size, FALSE);
	ad->name_alg = iin.objectPublic.publicArea.nameAlg;

	if (strcmp(OID_importableKey, oid) == 0) {
		TPM_HANDLE session;
		TSS_CONTEXT *tssContext;
		TPM_RC rc;
		const char *reason;
		TPM2B_PRIVATE priv_2b;
		BYTE *buf;
		UINT16 written;
		INT32 size;
		Import_Out iout;

		rc = tpm2_create(&tssContext, ad->dir);
		if (rc) {
			reason="tpm2_create";
			goto import_err;
		}

		if ((ad->parent & 0xff000000) == 0x40000000) {
			tpm2_load_srk(tssContext, &iin.parentHandle,
				      srk_auth, NULL, ad->parent, 1);
		} else {
			iin.parentHandle = ad->parent;
		}
		rc = tpm2_get_session_handle(tssContext, &session,
					     iin.parentHandle,
					     TPM_SE_HMAC,
					     iin.objectPublic.publicArea.nameAlg);
		if (rc) {
			reason="tpm2_get_session_handle";
			goto import_err;
		}

		/* no inner encryption */
		iin.encryptionKey.t.size = 0;
		iin.symmetricAlg.algorithm = TPM_ALG_NULL;

		/* for importable keys the private key is actually the
		 * outer wrapped duplicate structure */
		buffer = privkey->data;
		size = privkey->length;
		TPM2B_PRIVATE_Unmarshal(&iin.duplicate, &buffer, &size);

		buffer = secret->data;
		size = secret->length;
		TPM2B_ENCRYPTED_SECRET_Unmarshal(&iin.inSymSeed, &buffer, &size);
		rc = TSS_Execute(tssContext,
				 (RESPONSE_PARAMETERS *)&iout,
				 (COMMAND_PARAMETERS *)&iin,
				 NULL,
				 TPM_CC_Import,
				 session, srk_auth, 0,
				 TPM_RH_NULL, NULL, 0);
		if (rc)
			tpm2_flush_handle(tssContext, session);
		reason = "TPM2_Import";

	import_err:
		tpm2_flush_srk(tssContext, iin.parentHandle);
		TSS_Delete(tssContext);
		if (rc) {
			tpm2_error(rc, reason);
			goto err_free;
		}
		buf = priv_2b.t.buffer;
		size = sizeof(priv_2b.t.buffer);
		written = 0;
		TSS_TPM2B_PRIVATE_Marshal(&iout.outPrivate, &written,
					  &buf, &size);
		ad->priv = OPENSSL_malloc(written);
		if (!ad->priv)
			goto err_free;
		ad->priv_len = written;
		memcpy(ad->priv, priv_2b.t.buffer, written);
	} else {
		ad->priv = OPENSSL_malloc(privkey->length);
		if (!ad->priv)
			goto err_free;

		ad->priv_len = privkey->length;
		memcpy(ad->priv, privkey->data, ad->priv_len);
	}

	/* create the new objects to return */
	if (ppkey) {
		*ppkey = tpm2_to_openssl_public(&iin.objectPublic.publicArea);
		if (!*ppkey) {
			fprintf(stderr, "Failed to allocate a new EVP_KEY\n");
			goto err_free;
		}
	}

	if (empty_auth == 0 && get_key_auth) {
		ad->auth = tpm2_get_auth(ui, "TPM Key Password: ", cb_data);
		if (!ad->auth)
			goto err_free_key;
	}

	if (!(iin.objectPublic.publicArea.objectAttributes.val &
	      TPMA_OBJECT_USERWITHAUTH))
		ad->req_policy_session = 1;

	if (!tpm2_engine_load_key_policy(ad, policy))
		goto err_free_key;

	TSSLOADABLE_free(tssl);
	TSSPRIVKEY_free(tpk);

	return 1;
 err_free_key:
	if (ppkey)
		EVP_PKEY_free(*ppkey);
 err_free:
	*ppkey = NULL;

	tpm2_delete(ad);
 err:
	TSSLOADABLE_free(tssl);
	TSSPRIVKEY_free(tpk);

	return 0;
}

void tpm2_delete(struct app_data *app_data)
{
	int i;

	for (i = 0; i < app_data->num_commands; i++)
		OPENSSL_free(app_data->commands[i].policy);

	OPENSSL_free(app_data->commands);
	OPENSSL_free(app_data->priv);
	OPENSSL_free(app_data->pub);

	tpm2_rm_keyfile(app_data->dir, app_data->parent);
	/* if key was nv key, flush may not have removed file */
	tpm2_rm_keyfile(app_data->dir, app_data->key);
	tpm2_rm_tssdir(app_data->dir);

	OPENSSL_free((void *)app_data->dir);

	OPENSSL_free(app_data);
}

TPM_HANDLE tpm2_load_key(TSS_CONTEXT **tsscp, struct app_data *app_data,
			 const char *srk_auth)
{
	TSS_CONTEXT *tssContext;
	Load_In in;
	Load_Out out;
	TPM_HANDLE key = 0;
	TPM_RC rc;
	BYTE *buffer;
	INT32 size;
	TPM_HANDLE session;

	rc = tpm2_create(&tssContext, app_data->dir);
	if (rc)
		return 0;

	if (app_data->key) {
		key = app_data->key;
		goto out;
	}

	buffer = app_data->priv;
	size = app_data->priv_len;
	TPM2B_PRIVATE_Unmarshal(&in.inPrivate, &buffer, &size);

	buffer = app_data->pub;
	size = app_data->pub_len;
	TPM2B_PUBLIC_Unmarshal(&in.inPublic, &buffer, &size, FALSE);

	if ((app_data->parent & 0xff000000) == 0x81000000) {
		in.parentHandle = app_data->parent;
	} else {
		rc = tpm2_load_srk(tssContext, &in.parentHandle, srk_auth, NULL, app_data->parent, app_data->version);
		if (rc)
			goto out;
	}
	rc = tpm2_get_session_handle(tssContext, &session, in.parentHandle,
				     TPM_SE_HMAC, app_data->name_alg);
	if (rc)
		goto out_flush_srk;
	rc = TSS_Execute(tssContext,
			 (RESPONSE_PARAMETERS *)&out,
			 (COMMAND_PARAMETERS *)&in,
			 NULL,
			 TPM_CC_Load,
			 session, srk_auth, 0,
			 TPM_RH_NULL, NULL, 0);
	if (rc) {
		tpm2_error(rc, "TPM2_Load");
		tpm2_flush_handle(tssContext, session);
	}
	else
		key = out.objectHandle;

 out_flush_srk:
	tpm2_flush_srk(tssContext, in.parentHandle);
 out:
	if (!key)
		TSS_Delete(tssContext);
	else
		*tsscp = tssContext;
	return key;
}

void tpm2_unload_key(TSS_CONTEXT *tssContext, TPM_HANDLE key)
{
	tpm2_flush_handle(tssContext, key);

	TSS_Delete(tssContext);
}

IMPLEMENT_ASN1_FUNCTIONS(TSSOPTPOLICY)
IMPLEMENT_ASN1_FUNCTIONS(TSSLOADABLE)
IMPLEMENT_ASN1_FUNCTIONS(TSSPRIVKEY)
IMPLEMENT_PEM_write_bio(TSSLOADABLE, TSSLOADABLE, TSSLOADABLE_PEM_STRING, TSSLOADABLE)
IMPLEMENT_PEM_read_bio(TSSLOADABLE, TSSLOADABLE, TSSLOADABLE_PEM_STRING, TSSLOADABLE)
IMPLEMENT_PEM_write_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY)
IMPLEMENT_PEM_read_bio(TSSPRIVKEY, TSSPRIVKEY, TSSPRIVKEY_PEM_STRING, TSSPRIVKEY)

ASN1_SEQUENCE(TSSOPTPOLICY) = {
	ASN1_EXP(TSSOPTPOLICY, CommandCode, ASN1_INTEGER, 0),
	ASN1_EXP(TSSOPTPOLICY, CommandPolicy, ASN1_OCTET_STRING, 1)
} ASN1_SEQUENCE_END(TSSOPTPOLICY)

ASN1_SEQUENCE(TSSLOADABLE) = {
	ASN1_SIMPLE(TSSLOADABLE, type, ASN1_OBJECT),
	ASN1_EXP_OPT(TSSLOADABLE, emptyAuth, ASN1_BOOLEAN, 0),
	ASN1_EXP_OPT(TSSLOADABLE, parent, ASN1_INTEGER, 1),
	ASN1_EXP_OPT(TSSLOADABLE, pubkey, ASN1_OCTET_STRING, 2),
	ASN1_EXP_SEQUENCE_OF_OPT(TSSLOADABLE, policy, TSSOPTPOLICY, 3),
	ASN1_SIMPLE(TSSLOADABLE, privkey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TSSLOADABLE)

ASN1_SEQUENCE(TSSPRIVKEY) = {
	ASN1_SIMPLE(TSSPRIVKEY, type, ASN1_OBJECT),
	ASN1_EXP_OPT(TSSPRIVKEY, emptyAuth, ASN1_BOOLEAN, 0),
	ASN1_EXP_SEQUENCE_OF_OPT(TSSPRIVKEY, policy, TSSOPTPOLICY, 1),
	ASN1_EXP_OPT(TSSPRIVKEY, secret, ASN1_OCTET_STRING, 2),
	ASN1_SIMPLE(TSSPRIVKEY, parent, ASN1_INTEGER),
	ASN1_SIMPLE(TSSPRIVKEY, pubkey, ASN1_OCTET_STRING),
	ASN1_SIMPLE(TSSPRIVKEY, privkey, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(TSSPRIVKEY)

