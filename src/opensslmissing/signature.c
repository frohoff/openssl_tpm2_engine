/* Copyright (C) 2023 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/x509.h>

#include "opensslmissing.h"

/* give me strength: openssl case problems, now! */
#define NID_ecdsa_with_sha1	NID_ecdsa_with_SHA1
#define NID_ecdsa_with_sha224	NID_ecdsa_with_SHA224
#define NID_ecdsa_with_sha256	NID_ecdsa_with_SHA256
#define NID_ecdsa_with_sha384	NID_ecdsa_with_SHA384
#define NID_ecdsa_with_sha512	NID_ecdsa_with_SHA512
#define MD_NID(hash)						\
	case NID_##hash:					\
		if (ecc)					\
			signid = NID_ecdsa_with_##hash;		\
		else						\
			signid = NID_##hash##WithRSAEncryption;	\
		break

/*
 * When using provider digested signature routines, implementations need to
 * know the OID to be attached to the signed certificate.  Ideally openssl would
 * supply this and we'd only have to modify it if something about the signature
 * and hash actually required it, but actually we have to construct it with no
 * help from openssl.
 */
static int osslm_get_alg(struct osslm_sig_ctx *ctx, int ecc,
			 unsigned char **alg, int *alg_len)
{
	/* need the canonical hash name */
	int mdnid = EVP_MD_nid(ctx->md);
	int signid;
	X509_ALGOR *a;
	RSA_PSS_PARAMS *pssp;

	if (ctx->padding == RSA_PKCS1_PSS_PADDING) {
		signid = NID_rsassaPss;
	} else {
		switch (mdnid) {
			MD_NID(sha1);
			MD_NID(sha224);
			MD_NID(sha256);
			MD_NID(sha384);
			MD_NID(sha512);
		default:
			return 0;
		}
	}
	a = X509_ALGOR_new();
	if (!a)
		return 0;
	if (ctx->padding == RSA_PKCS1_PSS_PADDING) {
		ASN1_STRING *str = NULL;
		int mgf1nid = ctx->mgf1 ? EVP_MD_nid(ctx->mgf1) : mdnid;
		X509_ALGOR *mgf1;

		pssp = RSA_PSS_PARAMS_new();
		if (!pssp)
			goto err;
		pssp->hashAlgorithm = X509_ALGOR_new();
		pssp->maskGenAlgorithm = X509_ALGOR_new();
		pssp->saltLength = ASN1_INTEGER_new();
		if (!pssp->hashAlgorithm || !pssp->maskGenAlgorithm ||
		    !pssp->saltLength)
			goto err1;
		mgf1 = X509_ALGOR_new();
		if (!mgf1)
			goto err1;
		X509_ALGOR_set0(mgf1, OBJ_nid2obj(mgf1nid),
				V_ASN1_UNDEF, NULL);
		if (!ASN1_item_pack(mgf1, ASN1_ITEM_rptr(X509_ALGOR), &str)) {
			X509_ALGOR_free(mgf1);
			goto err1;
		}
		X509_ALGOR_free(mgf1);
		X509_ALGOR_set0(pssp->hashAlgorithm, OBJ_nid2obj(mdnid),
				V_ASN1_UNDEF, NULL);
		X509_ALGOR_set0(pssp->maskGenAlgorithm, OBJ_nid2obj(NID_mgf1),
				V_ASN1_SEQUENCE, str);
		ASN1_INTEGER_set(pssp->saltLength, ctx->salt_len);
		str = NULL;
		if (!ASN1_item_pack(pssp, ASN1_ITEM_rptr(RSA_PSS_PARAMS), &str))
			goto err1;
		RSA_PSS_PARAMS_free(pssp);
		X509_ALGOR_set0(a, OBJ_nid2obj(signid),
				V_ASN1_SEQUENCE, str);
	} else {
		X509_ALGOR_set0(a, OBJ_nid2obj(signid),
				V_ASN1_UNDEF, NULL);
	}
	*alg = NULL;
	*alg_len = i2d_X509_ALGOR(a, alg);
	X509_ALGOR_free(a);

	return 1;

 err1:
	RSA_PSS_PARAMS_free(pssp);
 err:
	X509_ALGOR_free(a);

	return 0;
}

int osslm_signature_digest_init(struct osslm_sig_ctx *ctx, const char *mdname,
				const OSSL_PARAM params[])
{
	if (!mdname)
		mdname = "SHA256";

	ctx->md = EVP_MD_fetch(ctx->libctx, mdname, NULL);
	if (!ctx->md)
		return 0;
	ctx->mctx = EVP_MD_CTX_new();
	if (!ctx->mctx)
		goto err;
	if (!EVP_DigestInit_ex(ctx->mctx, ctx->md, NULL))
		goto err;

	return 1;
 err:
	EVP_MD_free(ctx->md);
	ctx->md = NULL;
	EVP_MD_CTX_free(ctx->mctx);
	ctx->mctx = NULL;
	return 0;
}

int osslm_signature_digest_update(struct osslm_sig_ctx *ctx,
				  const unsigned char *data, size_t datalen)
{
	return EVP_DigestUpdate(ctx->mctx, data, datalen);
}

int osslm_signature_digest_final(struct osslm_sig_ctx *ctx, unsigned char *sig,
				 size_t *siglen, size_t sigsize, int rsa,
				 OSSL_FUNC_signature_sign_fn *ssf, void *sctx)
{
	unsigned int dsize = EVP_MD_get_size(ctx->md);
	unsigned char digest[dsize];

	if (sig == NULL)
		return ssf(sctx, NULL, siglen, sigsize, NULL, 0);

	if (!EVP_DigestFinal_ex(ctx->mctx, digest, &dsize))
		return 0;

	if (rsa) {
		unsigned char *to_sign = NULL;
		size_t to_sign_len;
		int ret;

		if (ctx->md && ctx->padding != RSA_PKCS1_PSS_PADDING) {
			if (!osslm_rsa_digest_to_sign(ctx->md, digest, dsize,
						      &to_sign, &to_sign_len))
				return 0;
		} else {
			to_sign = (unsigned char *)digest;
			to_sign_len = dsize;
		}

		ret = ssf(sctx, sig, siglen, sigsize, to_sign, to_sign_len);

		if (to_sign != digest)
			OPENSSL_free(to_sign);

		return ret;
	} else {
		return ssf(sctx, sig, siglen, sigsize, digest, dsize);
	}
}

int osslm_signature_get_params(struct osslm_sig_ctx *ctx, int ecc,
			       OSSL_PARAM params[])
{
	OSSL_PARAM *p;
	unsigned char *alg;
	int alg_len;
	int ret;

	p = OSSL_PARAM_locate(params, OSSL_SIGNATURE_PARAM_ALGORITHM_ID);
	if (!p)
		return 1;

	if (!osslm_get_alg(ctx, ecc, &alg, &alg_len))
		return 0;

	ret = OSSL_PARAM_set_octet_string(p, alg, alg_len);
	OPENSSL_free(alg);

	return ret;
}

const OSSL_PARAM *osslm_signature_gettable_params(void *ctx, void *pctx)
{
	static OSSL_PARAM params[] = {
		OSSL_PARAM_octet_string(OSSL_SIGNATURE_PARAM_ALGORITHM_ID, NULL, 0),
		OSSL_PARAM_END
	};

	return params;
}

int osslm_signature_set_params(struct osslm_sig_ctx *ctx, const OSSL_PARAM params[])
{
	const OSSL_PARAM *p = params;
	ctx->salt_len = 20;

	p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PAD_MODE);
	if (p) {
		if (p->data_type == OSSL_PARAM_INTEGER) {
			OSSL_PARAM_get_int(p, &ctx->padding);
		} else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
			if (strcasecmp(p->data, "pss") == 0) {
				ctx->padding = RSA_PKCS1_PSS_PADDING;
			} else if (strcasecmp(p->data, "pkcs1") == 0) {
				ctx->padding = RSA_PKCS1_PADDING;
			} else {
				fprintf(stderr, "unknown padding '%s'\n",
					(char *)p->data);
				return 0;
			}
		} else {
			return 0;
		}
	}

	p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_MGF1_DIGEST);
	if (p) {
		ctx->mgf1 = EVP_MD_fetch(ctx->libctx, p->data, NULL);
		if (!ctx->mgf1)
			return 0;
	}

	p = OSSL_PARAM_locate_const(params, OSSL_ALG_PARAM_DIGEST);
	if (p) {
		EVP_MD_free(ctx->md);
		ctx->md = EVP_MD_fetch(ctx->libctx, p->data, NULL);
		if (!ctx->md)
			return 0;
	}

	p = OSSL_PARAM_locate_const(params, OSSL_SIGNATURE_PARAM_PSS_SALTLEN);
	if (p) {
		if (p->data_type != OSSL_PARAM_INTEGER)
			return 0;
		if (!OSSL_PARAM_get_int(p, &ctx->salt_len))
			return 0;
	}

	return 1;
}

const OSSL_PARAM *osslm_signature_settable_params(void *ctx, void *pctx)
{
	static OSSL_PARAM params[] = {
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_PAD_MODE, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_SIGNATURE_PARAM_MGF1_DIGEST, NULL, 0),
		OSSL_PARAM_int(OSSL_SIGNATURE_PARAM_PSS_SALTLEN, NULL),
		/* necessary for -pkeyopt digest:<md> */
		OSSL_PARAM_utf8_string(OSSL_ALG_PARAM_DIGEST, NULL, 0),
		OSSL_PARAM_END
	};

	return params;
}
