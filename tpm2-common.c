/*
 * Copyright (C) 2016 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * GPLv2
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>

#include <tss2/tss.h>
#include <tss2/tssresponsecode.h>
#include <tss2/tssmarshal.h>
#include <tss2/tsscrypto.h>
#include <tss2/tsscryptoh.h>

#include "tpm2-common.h"

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


TPM_RC tpm2_load_srk(TSS_CONTEXT *tssContext, TPM_HANDLE *h, const char *auth,TPM2B_PUBLIC *pub, TPM_HANDLE hierarchy)
{
	static TPM2B_PUBLIC srk_pub;
	TPM_RC rc;
	CreatePrimary_In in;
	CreatePrimary_Out out;

	/* SPS owner */
	in.primaryHandle = hierarchy;
	/* assume no owner password */
	in.inSensitive.sensitive.userAuth.t.size = 0;
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
	in.inPublic.publicArea.parameters.eccDetail.symmetric.algorithm = TPM_ALG_AES;
	in.inPublic.publicArea.parameters.eccDetail.symmetric.keyBits.aes = 128;
	in.inPublic.publicArea.parameters.eccDetail.symmetric.mode.aes = TPM_ALG_CFB;
	in.inPublic.publicArea.parameters.eccDetail.scheme.scheme = TPM_ALG_NULL;
	in.inPublic.publicArea.parameters.eccDetail.curveID = TPM_ECC_NIST_P256;
	in.inPublic.publicArea.parameters.eccDetail.kdf.scheme = TPM_ALG_NULL;

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

	srk_pub = out.outPublic;
	*h = out.objectHandle;
	if (pub)
		*pub = srk_pub;

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

static void tpm2_rm_keyfile(const char *dir, TPM_HANDLE key)
{
	char keyfile[1024];

	snprintf(keyfile, sizeof(keyfile), "%s/h%08x.bin", dir, key);
	unlink(keyfile);
	snprintf(keyfile, sizeof(keyfile), "%s/hp%08x.bin", dir, key);
	unlink(keyfile);
}

void tpm2_rm_tssdir(const char *dir, TPM_HANDLE extrakey)
{
	if (extrakey)
		tpm2_rm_keyfile(dir, extrakey);
	tpm2_rm_keyfile(dir, 0x81000001);
	if (rmdir(dir) < 0)
		perror("Unlinking TPM_DATA_DIR");
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
