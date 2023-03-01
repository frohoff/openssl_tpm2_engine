/* Copyright (C) 2023 James Bottomley <James.Bottomley@HansenPartnership.com>
 *
 * SPDX-License-Identifier: MIT
 */

#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/core.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <endian.h>
#include <arpa/inet.h>
#include "opensslmissing.h"

/*
 * have to have this because openssl doesn't export a to be signed
 * form of a digest for RSA, which is a DigestInfo.
 *
 * DigestInfo ::= SEQUENCE {
 *         digestAlgorithm AlgorithmIdentifier,
 *         digest OCTET STRING
 *     }
 */
typedef struct {
	X509_ALGOR *digestAlgorithm;
	ASN1_OCTET_STRING *digest;
} DIGEST_INFO;
DECLARE_ASN1_FUNCTIONS(DIGEST_INFO);
IMPLEMENT_ASN1_FUNCTIONS(DIGEST_INFO);
ASN1_SEQUENCE(DIGEST_INFO) = {
	ASN1_SIMPLE(DIGEST_INFO, digestAlgorithm, X509_ALGOR),
	ASN1_SIMPLE(DIGEST_INFO, digest, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(DIGEST_INFO)

/*
 * RSA toBeSigned aren't simply digests like EC, they're actually
 * ASN1 DigestInfo structures which have a hash OID prefix (meaning
 * the entity signing must know the hash.
 *
 * Given a digest type and output, this routine will populate to_sign
 * with the correct RSA form of the signature which must then be
 * padded and encrypted.
 */
int osslm_rsa_digest_to_sign(EVP_MD *md,
			     const unsigned char *digest, int digest_len,
			     unsigned char **to_sign, size_t *to_sign_len)
{
	DIGEST_INFO *di = DIGEST_INFO_new();

	*to_sign = NULL;
	if (!di)
		return 0;

	di->digestAlgorithm = X509_ALGOR_new();
	di->digest = ASN1_OCTET_STRING_new();
	if (!di->digestAlgorithm || !di->digest) {
		DIGEST_INFO_free(di);
		return 0;
	}
	X509_ALGOR_set0(di->digestAlgorithm,
			OBJ_nid2obj(EVP_MD_nid(md)),
			V_ASN1_NULL, NULL);
	ASN1_STRING_set(di->digest, digest, digest_len);
	*to_sign_len = i2d_DIGEST_INFO(di, to_sign);
	DIGEST_INFO_free(di);
	return 1;
}

/*
 * For reasons best known to openssl, the form of the bignums exported
 * as rsa values are host endian (This doesn't apply to EC because the
 * prescribed form of the public key is bit endian points).  Since most
 * users of the provider (x86, arm) are little endian hosts, this means
 * that native binary bignum formats must be byte reversed.
 *
 * This pair of routines is designed to make the byte reversal code as
 * painless as possible.
 */
int bn_b2h_alloc(unsigned char **dst, unsigned char *src, const int len)
{
#if __BYTE_ORDER == __BIG_ENDIAN
	*dst = src;
#else
	int i;

	*dst = OPENSSL_malloc(len);
	if (!*dst)
		return 0;
	for (i = 0; i < len; i++)
		(*dst)[i] = src[len - i - 1];
#endif
	return 1;
}

void bn_b2h_free(unsigned char *src)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
	OPENSSL_free(src);
#endif
}


int osslm_signature_dupctx(struct osslm_sig_ctx *oldctx,
			   struct osslm_sig_ctx *newctx)
{
	newctx->md = oldctx->md;
	if (newctx->md)
		EVP_MD_up_ref(newctx->md);

	if (oldctx->mctx) {
		newctx->mctx = EVP_MD_CTX_new();
		if (!newctx->mctx)
			return 0;
		if (!EVP_MD_CTX_copy_ex(newctx->mctx, oldctx->mctx))
			return 0;
	}

	newctx->mgf1 = oldctx->mgf1;
	if (oldctx->mgf1)
		EVP_MD_up_ref(newctx->mgf1);

	newctx->libctx = oldctx->libctx;
	newctx->padding = oldctx->padding;
	newctx->salt_len = oldctx->salt_len;

	return 1;
}

void osslm_signature_freectx(struct osslm_sig_ctx *sctx)
{
	EVP_MD_free(sctx->md);
	sctx->md = NULL;
	EVP_MD_free(sctx->mgf1);
	sctx->mgf1 = NULL;
	EVP_MD_CTX_free(sctx->mctx);
	sctx->mctx = NULL;
}

/* see RFC3447 Appendix B.2.1 */
static int osslm_mgf1(const unsigned char *seed, int seedlen,
		      unsigned char *mask, int masklen, const EVP_MD *md)
{
	int i;
	const int mdlen = EVP_MD_get_size(md);
	unsigned char buffer[mdlen];
	EVP_MD_CTX *ctx = EVP_MD_CTX_new();
	int outlen = 0;

	if (!ctx)
		return 0;

	for (i = 0; outlen < masklen; i++) {
		const uint32_t becount = htonl(i);

		EVP_DigestInit_ex(ctx, md, NULL);
		EVP_DigestUpdate(ctx, seed, seedlen);
		EVP_DigestUpdate(ctx, &becount, sizeof(becount));
		if (outlen + mdlen <= masklen) {
			EVP_DigestFinal_ex(ctx, &mask[outlen], NULL);
		} else {
			EVP_DigestFinal_ex(ctx, buffer, NULL);
			memcpy(&mask[outlen], buffer, masklen - outlen);
		}
		outlen += mdlen;
	}
	return 1;
}

/* see RFC3447 section 9.1 */
static int osslm_rsa_padding_add_PKCS1_PSS_mgf1(struct osslm_sig_ctx *sctx,
						unsigned char *padded,
						int padsize,
						const unsigned char *mHash,
						int mHashsize)
{
	unsigned char salt[padsize];
	int DBsize = padsize - mHashsize - 1;
	EVP_MD_CTX *ctx;
	/* hash goes in last bytes leaving room for final 0xbc */
	unsigned char *Hash = &padded[padsize - mHashsize - 1];
	unsigned char *ptr;
	unsigned char zeros[] = {0, 0, 0, 0, 0, 0, 0, 0 };
	int i;

	padded[padsize - 1] = 0xbc;

	/* openssl magic negative values */
	switch (sctx->salt_len) {
	case 0:
	case RSA_PSS_SALTLEN_DIGEST:
		sctx->salt_len = mHashsize;
		break;
	case RSA_PSS_SALTLEN_AUTO:
	case RSA_PSS_SALTLEN_MAX:
		sctx->salt_len = padsize - mHashsize - 2;
		break;
	}
	if (sctx->salt_len < 0 || sctx->salt_len > padsize - mHashsize - 2) {
		fprintf(stderr, "salt too big %d > %d\n", sctx->salt_len,
			padsize - mHashsize -2);
		return 0;
	}

	RAND_bytes_ex(sctx->libctx, salt, sctx->salt_len, 0);

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return 0;

	EVP_DigestInit_ex(ctx, sctx->md, NULL);
	EVP_DigestUpdate(ctx, zeros, sizeof(zeros));
	EVP_DigestUpdate(ctx, mHash, mHashsize);
	EVP_DigestUpdate(ctx, salt, sctx->salt_len);
	EVP_DigestFinal_ex(ctx, Hash, NULL);
	EVP_MD_CTX_free(ctx);

	/* place the mask into the message header */
	osslm_mgf1(Hash, mHashsize, padded, DBsize,
		   sctx->mgf1 ? sctx->mgf1 : sctx->md);
	/*
	 * clear most significant bit.  Optimization because we know
	 * the key size in bits is a multiple of 8
	 */
	padded[0] &= 0x7f;
	/* now xor in padding and salt remembering that zero xor X is X */
	ptr = padded;
	ptr += padsize - sctx->salt_len - mHashsize - 2;
	*ptr++ ^= 0x01;
	for (i = 0; i < sctx->salt_len; i++)
		*ptr++ ^= salt[i];
	return 1;
}

/* RFC3447 section 9.2 */
static int osslm_rsa_pkcs1_pad(unsigned char *padded, int padsize,
			       const unsigned char *from, int fsize)
{
	if (padsize < fsize + 3)
		return 0;

	padded[0] = 0x00;
	padded[1] = 0x01;
	memset(&padded[2], 0xff, padsize - fsize - 3);
	padded[padsize - fsize - 1] = 0x00;
	memcpy(&padded[padsize - fsize], from, fsize);

	return 1;
}

int osslm_rsa_signature_pad(struct osslm_sig_ctx *sctx, unsigned char *padded,
			    int padsize, const unsigned char *from, int fsize)
{
	switch (sctx->padding) {
	case 0:
	case RSA_PKCS1_PADDING:
		/*
		 * May or may not need to find an alternative, see
		 * https://github.com/openssl/openssl/issues/17187
		 */
		osslm_rsa_pkcs1_pad(padded, padsize, from, fsize);
		break;
	case RSA_PKCS1_PSS_PADDING:
		if (!osslm_rsa_padding_add_PKCS1_PSS_mgf1(sctx, padded, padsize,
							  from, fsize))
			return 0;
		break;
	default:
		if (fsize != padsize) {
			fprintf(stderr, "unpadded RSA encrypt wrong size %d!=%d\n",
				padsize, fsize);
			return 0;
		}
		memcpy(padded, from, fsize);
		break;
	}
	return 1;
}

/* RFC3447 Section 7.1
 *
 * Note: this should be constant time, which is why we don't do any
 * checking until the end
 */
int osslm_rsa_unpad_oaep(struct osslm_dec_ctx *ctx,
			 unsigned char *to, size_t *tosize,
			 const unsigned char *from, int fromsize)
{
	const int mdsize = EVP_MD_get_size(ctx->md);
	const int DBsize = fromsize - mdsize - 1;
	unsigned char seed[mdsize], mask[mdsize], DBmask[DBsize],
		label_hash[mdsize];
	int good = 1, i;

	memcpy(seed, from + 1, sizeof(seed));

	osslm_mgf1(from + 1 + mdsize, DBsize, mask, sizeof(mask), ctx->mgfmd);
	for (i = 0; i < sizeof(mask); i++)
		seed[i] ^= mask[i];

	osslm_mgf1(seed, sizeof(seed), DBmask, sizeof(DBmask), ctx->mgfmd);
	for (i = 0; i < sizeof(DBmask); i++)
		DBmask[i] ^= from[i + 1 + mdsize];

	/* DBmask is now actually DB */

	/* now check; byte 0 should be 0,  */
	good &= (from[0] == 0);
	for (i = mdsize; i < sizeof(DBmask); i++)
		if (DBmask[i] != 0)
			break;
	good &= (i != sizeof(DBmask) && DBmask[i] == 1);


	EVP_Digest(ctx->label, ctx->label_size, label_hash, NULL,
		   ctx->md, NULL);
	good &= (CRYPTO_memcmp(label_hash, DBmask, mdsize) == 0);

	if (good) {
		if (*tosize >= sizeof(DBmask) - i - 1) {
			*tosize = sizeof(DBmask) - i - 1;
			memcpy(to, &DBmask[i + 1], *tosize);
		}
	}
	return good;

}

int osslm_decryption_set_params(struct osslm_dec_ctx *ctx,
				const OSSL_PARAM params[])
{
	const OSSL_PARAM *p = params;

	p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_PAD_MODE);
	if (p) {
		if (p->data_type == OSSL_PARAM_INTEGER) {
			OSSL_PARAM_get_int(p, &ctx->padding);
		} else if (p->data_type == OSSL_PARAM_UTF8_STRING) {
			if (strcasecmp(p->data, "oaep") == 0) {
				ctx->padding = RSA_PKCS1_OAEP_PADDING;
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
		if (ctx->padding == RSA_PKCS1_OAEP_PADDING) {
			/* must follow OpenSSL default */
			ctx->md = EVP_MD_fetch(ctx->libctx, "sha1", NULL);
			ctx->mgfmd = ctx->md;
			EVP_MD_up_ref(ctx->mgfmd);
		}
	}

	p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST);
	if (p) {
		if (p->data_type != OSSL_PARAM_UTF8_STRING)
			return 0;
		EVP_MD_free(ctx->md);
		ctx->md = EVP_MD_fetch(ctx->libctx, p->data, NULL);
		if (!ctx->md)
			return 0;
	}

	p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST);
	if (p) {
		if (p->data_type != OSSL_PARAM_UTF8_STRING)
			return 0;
		EVP_MD_free(ctx->mgfmd);
		ctx->mgfmd = EVP_MD_fetch(ctx->libctx, p->data, NULL);
		if (!ctx->mgfmd)
			return 0;
	}

	p = OSSL_PARAM_locate_const(params, OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL);
	if (p) {
		if (p->data_type != OSSL_PARAM_OCTET_STRING)
			return 0;
		OSSL_PARAM_get_octet_string(p, (void **)&ctx->label, 0, &ctx->label_size);
	}
	return 1;
}

const OSSL_PARAM *osslm_decryption_settable_params(void *ctx, void *provctx)
{
	static const OSSL_PARAM params[] = {
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_PAD_MODE, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_OAEP_DIGEST, NULL, 0),
		OSSL_PARAM_utf8_string(OSSL_ASYM_CIPHER_PARAM_MGF1_DIGEST, NULL, 0),
		OSSL_PARAM_octet_string(OSSL_ASYM_CIPHER_PARAM_OAEP_LABEL, NULL, 0),
		OSSL_PARAM_END
	};
	return params;
}

void osslm_decryption_freectx(struct osslm_dec_ctx *ctx)
{
	EVP_MD_free(ctx->md);
	ctx->md = NULL;
	EVP_MD_free(ctx->mgfmd);
	ctx->mgfmd = NULL;
	OPENSSL_free(ctx->label);
	ctx->label = NULL;
	ctx->label_size = 0;
}
